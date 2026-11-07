"""Post-update guard: notice when a container starts running a new image, check
it a few minutes later, and if it is broken offer a one-tap rollback.

Rollback recreates the container from its current settings with the previous
image (still on disk: Watchtower runs with cleanup off), labels it so Watchtower
leaves it alone, and for Compose projects also pins the previous image in the
Compose file (backed up first) so a later rebuild keeps it.
Nothing is deleted: the broken container is renamed to_delete_<name>_broken.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .diagnose import diagnose
from .docker import DockerClient, DockerError
from . import writes as w

log = logging.getLogger("nasmcp.updates")

CHECK_AFTER = 300            # seconds after the update
SKIP = ("nas-mcp", "nas-mcp-docker-proxy")
WT_LABEL = "com.centurylinklabs.watchtower.enable"


@dataclass
class Update:
    id: str
    name: str
    old_image: str           # image id (sha256:...)
    new_image: str
    image_ref: str
    at: float
    checked: bool = False
    healthy: bool | None = None
    problems: list[str] = field(default_factory=list)
    secret: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    rolled_back: bool = False


class UpdateWatcher(threading.Thread):
    daemon = True

    def __init__(self, docker: DockerClient, data_dir: Path,
                 notify: Callable[[Update, dict[str, str]], None] | None = None,
                 audit: w.Audit | None = None, docker_root: Path | None = None,
                 interval: float = 60, check_after: float = CHECK_AFTER):
        super().__init__(name="update-watcher")
        self.docker = docker
        self.file = data_dir / "updates.json"
        self.notify = notify
        self.audit = audit
        self.docker_root = docker_root
        self.interval = interval
        self.check_after = check_after
        self.lock = threading.Lock()
        self.seen: dict[str, dict] = {}
        self.updates: dict[str, Update] = {}
        self._load()

    # -- persistence -----------------------------------------------------------------
    def _load(self) -> None:
        if not self.file.exists():
            return
        try:
            data = json.loads(self.file.read_text(encoding="utf-8"))
        except ValueError:
            return
        self.seen = data.get("seen", {})
        for u in data.get("updates", []):
            self.updates[u["id"]] = Update(**u)

    def _save(self) -> None:
        keep = sorted(self.updates.values(), key=lambda u: u.at)[-50:]
        self.updates = {u.id: u for u in keep}
        self.file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seen": self.seen, "updates": [asdict(u) for u in keep]},
                                  indent=1), encoding="utf-8")
        tmp.replace(self.file)

    # -- the loop ------------------------------------------------------------------
    def run(self) -> None:  # pragma: no cover - timing loop
        while True:
            try:
                self.scan()
                self.check_due()
            except Exception as e:
                log.warning("update watcher: %s", e)
            time.sleep(self.interval)

    def scan(self, now: float | None = None) -> list[Update]:
        """Compare every container's image with what was seen last time."""
        now = now or time.time()
        found = []
        with self.lock:
            first_run = not self.seen
            for c in self.docker.containers():
                name = (c.get("Names") or ["?"])[0].lstrip("/")
                image_id = c.get("ImageID") or ""
                prev = self.seen.get(name)
                self.seen[name] = {"image_id": image_id, "image": c.get("Image"), "t": now}
                if first_run or not prev or name in SKIP or re.match(r"^_?to_?delete", name):
                    continue
                if prev["image_id"] and image_id and prev["image_id"] != image_id \
                        and prev.get("image") == c.get("Image"):
                    u = Update(id=secrets.token_urlsafe(9), name=name, old_image=prev["image_id"],
                               new_image=image_id, image_ref=c.get("Image") or "", at=now)
                    self.updates[u.id] = u
                    found.append(u)
                    if self.audit:
                        self.audit.add("update_seen", name, "checking in 5 minutes",
                                       image=u.image_ref)
            self._save()
        return found

    def check_due(self, now: float | None = None) -> list[Update]:
        now = now or time.time()
        done = []
        for u in list(self.updates.values()):
            if u.checked or now - u.at < self.check_after:
                continue
            self.check(u)
            done.append(u)
        return done

    def check(self, u: Update) -> Update:
        try:
            c = self.docker.find(u.name)
            if not c:
                u.problems = ["the container is gone"]
            else:
                insp = self.docker.inspect(c["Id"])
                logs = self.docker.logs(c["Id"], tail=300)
                fs = diagnose(c, insp, logs, None)
                bad = [f for f in fs if f.severity == "high"]
                u.problems = [f"{f.title}: {f.detail}"[:200] for f in bad]
        except DockerError as e:
            u.problems = [f"could not check: {e}"]
        u.checked = True
        u.healthy = not u.problems
        with self.lock:
            self._save()
        if self.audit:
            self.audit.add("update_check", u.name, "ok" if u.healthy else "broken",
                           problems=u.problems)
        if not u.healthy and self.notify:
            try:
                self.notify(u, {"rollback": f"/update/{u.id}/{u.secret}/rollback",
                                "ignore": f"/update/{u.id}/{u.secret}/ignore"})
            except Exception as e:
                log.warning("update alert failed: %s", e)
        return u

    def recent(self) -> list[dict]:
        out = []
        for u in sorted(self.updates.values(), key=lambda x: x.at)[-30:]:
            d = asdict(u)
            d.pop("secret", None)
            d["time"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(u.at))
            d["status"] = ("rolled back" if u.rolled_back else "waiting for check" if not u.checked
                           else "ok" if u.healthy else "broken")
            out.append(d)
        return out

    def find(self, name: str) -> Update | None:
        hits = [u for u in self.updates.values() if u.name == name]
        return max(hits, key=lambda u: u.at) if hits else None

    # -- rollback ----------------------------------------------------------------
    def decide(self, uid: str, secret: str, action: str) -> str:
        u = self.updates.get(uid)
        if not u or not secrets.compare_digest(u.secret, secret):
            return "expired"
        if u.rolled_back:
            return "rolled back"
        if action == "ignore":
            u.healthy = True
            with self.lock:
                self._save()
            return "ignored"
        if action == "rollback":
            return self.rollback(u)
        return "expired"

    def rollback(self, u: Update) -> str:
        res = rollback_container(self.docker, u.name, u.old_image, self.docker_root)
        u.rolled_back = True
        with self.lock:
            self._save()
        if self.audit:
            self.audit.add("rollback", u.name, "ok", **res)
        return "rolled back"


# -- recreate with the previous image ---------------------------------------------------------

def _create_body(insp: dict, image: str) -> dict:
    cfg = dict(insp.get("Config") or {})
    cfg["Image"] = image
    labels = dict(cfg.get("Labels") or {})
    labels[WT_LABEL] = "false"
    cfg["Labels"] = labels
    nets = (insp.get("NetworkSettings") or {}).get("Networks") or {}
    endpoints = {}
    for net, v in nets.items():
        ep: dict[str, Any] = {}
        if v.get("Aliases"):
            ep["Aliases"] = [a for a in v["Aliases"] if not re.fullmatch(r"[0-9a-f]{12}", a)]
        if v.get("IPAMConfig"):
            ep["IPAMConfig"] = v["IPAMConfig"]
        endpoints[net] = ep
    body = {**cfg, "HostConfig": insp.get("HostConfig") or {}}
    if endpoints and (insp.get("HostConfig") or {}).get("NetworkMode") not in ("host", "none"):
        body["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return body


def rollback_container(docker: DockerClient, name: str, old_image: str,
                       docker_root: Path | None = None) -> dict:
    w._check_not_protected(name)
    c = docker.find(name)
    if not c:
        raise DockerError(f"container {name} not found")
    insp = docker.inspect(c["Id"])
    body = _create_body(insp, old_image)
    broken = f"to_delete_{name}_broken_{time.strftime('%Y%m%d%H%M')}"
    w._post(docker, f"/containers/{c['Id']}/stop", {"t": "20"}, timeout=90)
    w._post(docker, f"/containers/{c['Id']}/update", body={"RestartPolicy": {"Name": "no"}})
    w._post(docker, f"/containers/{c['Id']}/rename", {"name": broken})
    try:
        new_id = _create(docker, name, body)
        w._post(docker, f"/containers/{new_id}/start", timeout=90)
    except DockerError:
        # Put the original back so nothing is lost.
        w._post(docker, f"/containers/{c['Id']}/rename", {"name": name})
        w._post(docker, f"/containers/{c['Id']}/start", timeout=90)
        raise
    result = {"renamed_broken_to": broken, "image": old_image[:19]}
    pinned = _pin_compose(docker, insp, old_image, docker_root)
    if pinned:
        result["compose_pinned"] = pinned
    return result


def _create(docker: DockerClient, name: str, body: dict) -> str:
    import httpx
    try:
        with httpx.Client(timeout=60, transport=docker.transport) as cl:
            r = cl.post(f"{docker.base}/containers/create", params={"name": name}, json=body)
    except httpx.HTTPError as e:
        raise DockerError(f"create failed: {e}") from e
    if r.status_code >= 400:
        raise DockerError(f"create failed {r.status_code}: {r.text[:200]}")
    return r.json()["Id"]


def _pin_compose(docker: DockerClient, insp: dict, old_image: str,
                 docker_root: Path | None) -> dict | None:
    labels = (insp.get("Config") or {}).get("Labels") or {}
    workdir = labels.get("com.docker.compose.project.working_dir")
    service = labels.get("com.docker.compose.service")
    if not (workdir and service and docker_root):
        return None
    m = re.match(r"^/volume\d+/docker/(.+)$", workdir)
    if not m:
        return None
    pdir = docker_root / m.group(1)
    f = w.find_compose(pdir)
    if not f:
        return None
    try:
        ref = _digest_ref(docker, old_image)
    except DockerError:
        return None
    if not ref:
        return None
    data = yaml.safe_load(f.read_text(encoding="utf-8"))
    svc = (data.get("services") or {}).get(service)
    if not isinstance(svc, dict):
        return None
    svc["image"] = ref
    lab = svc.get("labels")
    if isinstance(lab, list):
        lab = [x for x in lab if not str(x).startswith(WT_LABEL)] + [f"{WT_LABEL}=false"]
    else:
        lab = dict(lab or {})
        lab[WT_LABEL] = "false"
    svc["labels"] = lab
    res = w.write_compose(pdir, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return {"project_dir": m.group(1), "image": ref, **res}


def _digest_ref(docker: DockerClient, image_id: str) -> str | None:
    im = docker.image(image_id)
    digests = im.get("RepoDigests") or []
    return digests[0] if digests else None
