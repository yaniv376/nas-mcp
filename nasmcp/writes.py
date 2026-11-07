"""Changes to the NAS (stage 1c).

Every change:
  * needs the NAS gate's "agent" window to be open (asked live, fails closed),
  * is written to an audit log (/data/actions.jsonl),
  * never deletes anything: retiring renames to to_delete_<name>, and a Compose
    file is backed up before it is overwritten.
Disruptive steps (retiring a container) also wait for a tap on the phone.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

from .config import Settings
from .docker import DockerClient, DockerError
from .dsm import DSMClient, DSMError
from .gate import GateClient, GateError

# Containers this server never stops, restarts or retires: itself, its Docker
# proxy and the gate that guards it.
PROTECTED = ("nas-mcp", "nas-mcp-docker-proxy", "nas-gate")
HISTORY_DIR = ".nas-mcp-history"


class WriteDenied(Exception):
    pass


# -- gate check ---------------------------------------------------------------------

def require_window(gate: GateClient) -> dict:
    """Raise unless the gate's agent window is open right now."""
    if not gate.configured:
        raise WriteDenied("Changes need the NAS gate (gate_url and gate token are not set).")
    try:
        st = gate.status()
    except GateError as e:
        raise WriteDenied(f"Cannot ask the NAS gate, so no change is allowed: {e}") from e
    p = (st.get("protections") or {}).get("agent")
    if p is None:
        raise WriteDenied("The NAS gate has no 'Agent (MCP)' window yet: update the gate.")
    if not p.get("managed"):
        raise WriteDenied("The gate's 'Agent (MCP)' window is turned off in the gate settings.")
    if not p.get("is_open"):
        raise WriteDenied("The agent window in the NAS gate is closed. Open it from the "
                          "Home Assistant dashboard or the gate page, then ask again.")
    return {"remaining_minutes": round((p.get("remaining_seconds") or 0) / 60)}


# -- audit log ----------------------------------------------------------------------

class Audit:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def add(self, action: str, target: str, result: str, **extra) -> None:
        item = {"t": time.time(), "action": action, "target": target, "result": result, **extra}
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    def recent(self, limit: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        out = []
        for ln in lines:
            try:
                d = json.loads(ln)
                d["time"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.pop("t", 0)))
                out.append(d)
            except ValueError:
                continue
        return out


# -- phone approval for disruptive steps ------------------------------------------------

@dataclass
class Approval:
    id: str
    secret: str
    what: str
    created: float = field(default_factory=time.time)
    decision: str = ""


class Approvals:
    TTL = 300

    def __init__(self, public_url: str, send: Callable[[Approval, str, str], None] | None):
        self.public = public_url.rstrip("/")
        self.send = send
        self.items: dict[str, Approval] = {}

    def ask(self, what: str, wait_seconds: int = 120, poll: float = 2.0) -> bool:
        if not self.send or not self.public:
            raise WriteDenied("This step needs approval on the phone, but notifications or "
                              "the public address are not configured.")
        a = Approval(id=secrets.token_urlsafe(12), secret=secrets.token_urlsafe(24), what=what)
        self.items[a.id] = a
        base = f"{self.public}/approve/{a.id}/{a.secret}"
        try:
            self.send(a, f"{base}/approve", f"{base}/deny")
        except Exception as e:
            self.items.pop(a.id, None)
            raise WriteDenied(f"Could not send the approval request: {e}") from e
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if a.decision:
                break
            time.sleep(poll)
        self.items.pop(a.id, None)
        if a.decision == "approved":
            return True
        if a.decision == "denied":
            raise WriteDenied("Denied on the phone.")
        raise WriteDenied("No answer on the phone within 2 minutes; nothing was changed.")

    def decide(self, aid: str, secret: str, action: str) -> str:
        a = self.items.get(aid)
        if not a or not secrets.compare_digest(a.secret, secret) or time.time() - a.created > self.TTL:
            return "expired"
        if not a.decision:
            a.decision = "approved" if action == "approve" else "denied"
        return a.decision


# -- Compose files ------------------------------------------------------------------------

COMPOSE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")


def validate_compose(text: str) -> dict:
    """Parse and sanity-check a Compose file. Raises ValueError with a readable reason."""
    if "\t" in text:
        line = text[: text.index("\t")].count("\n") + 1
        raise ValueError(f"line {line}: tabs are not allowed in YAML, use spaces")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}: " if mark else ""
        raise ValueError(f"{where}{getattr(e, 'problem', None) or e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict) or not data["services"]:
        raise ValueError("the file needs a 'services:' section with at least one service")
    for name, svc in data["services"].items():
        if not isinstance(svc, dict):
            raise ValueError(f"service '{name}' is not a mapping (check its indentation)")
        if not svc.get("image") and not svc.get("build"):
            raise ValueError(f"service '{name}' has neither 'image' nor 'build'")
        for key in ("ports", "volumes", "environment"):
            if key in svc and svc[key] is not None and not isinstance(svc[key], (list, dict)):
                raise ValueError(f"service '{name}': '{key}' must be a list (check its indentation)")
    return data


def find_compose(project_dir: Path) -> Path | None:
    for n in COMPOSE_NAMES:
        if (project_dir / n).is_file():
            return project_dir / n
    return None


def write_compose(project_dir: Path, content: str) -> dict:
    validate_compose(content)
    project_dir.mkdir(parents=True, exist_ok=True)
    target = find_compose(project_dir) or (project_dir / "compose.yaml")
    backup = None
    if target.exists():
        hist = project_dir / HISTORY_DIR
        hist.mkdir(exist_ok=True)
        backup = hist / f"{target.stem}-{time.strftime('%Y%m%d-%H%M%S')}{target.suffix}"
        shutil.copy2(target, backup)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
    tmp.replace(target)
    return {"file": target.name, "backup": f"{HISTORY_DIR}/{backup.name}" if backup else None}


def list_backups(project_dir: Path) -> list[str]:
    hist = project_dir / HISTORY_DIR
    return sorted((p.name for p in hist.glob("*")), reverse=True) if hist.is_dir() else []


def restore_compose(project_dir: Path, backup_name: str) -> dict:
    if "/" in backup_name or backup_name.startswith("."):
        raise ValueError("give the backup file name only")
    src = project_dir / HISTORY_DIR / backup_name
    if not src.is_file():
        raise ValueError(f"no backup named {backup_name}")
    return write_compose(project_dir, src.read_text(encoding="utf-8"))


# -- Docker container actions (through the socket proxy) --------------------------------------

def _post(docker: DockerClient, path: str, params: dict | None = None,
          body: dict | None = None, timeout: float = 60) -> None:
    try:
        with httpx.Client(timeout=timeout, transport=docker.transport) as c:
            r = c.post(f"{docker.base}{path}", params=params, json=body)
    except httpx.HTTPError as e:
        raise DockerError(f"Docker request failed: {e}") from e
    if r.status_code == 403:
        raise DockerError("The Docker proxy refused the change: set POST: 1 on nas-mcp-docker-proxy.")
    if r.status_code >= 400 and r.status_code != 304:
        raise DockerError(f"Docker API {r.status_code}: {r.text[:200]}")


def _check_not_protected(name: str) -> None:
    if name.lstrip("/") in PROTECTED:
        raise WriteDenied(f"'{name}' runs this server or its gate, so it is never changed from here.")


def container_action(docker: DockerClient, cid: str, name: str, action: str) -> None:
    _check_not_protected(name)
    if action not in ("start", "stop", "restart"):
        raise ValueError("action must be start, stop or restart")
    _post(docker, f"/containers/{cid}/{action}", {"t": "20"} if action != "start" else None, timeout=90)


def set_restart_policy(docker: DockerClient, cid: str, name: str, policy: str) -> None:
    if policy not in ("no", "always", "unless-stopped", "on-failure"):
        raise ValueError("policy must be no, always, unless-stopped or on-failure")
    _post(docker, f"/containers/{cid}/update", body={"RestartPolicy": {"Name": policy}})


def retire_container(docker: DockerClient, cid: str, name: str) -> str:
    _check_not_protected(name)
    new = "to_delete_" + re.sub(r"^[^a-zA-Z0-9]+", "", name)
    _post(docker, f"/containers/{cid}/stop", {"t": "20"}, timeout=90)
    _post(docker, f"/containers/{cid}/update", body={"RestartPolicy": {"Name": "no"}})
    _post(docker, f"/containers/{cid}/rename", {"name": new})
    return new


# -- Container Manager projects (DSM API) ---------------------------------------------------

PROJECT_ACTIONS = {"stop": "stop_stream", "build": "build_stream", "start": "start_stream",
                   "restart": "restart_stream"}


def list_projects(dsm: DSMClient) -> list[dict]:
    data = dsm.request("SYNO.Docker.Project", "list", version=1)
    items = data if isinstance(data, list) else (data.get("projects") or data)
    if isinstance(items, dict):
        items = [dict(v, id=k) if isinstance(v, dict) and "id" not in v else v for k, v in items.items()]
    out = []
    for p in items or []:
        if isinstance(p, dict):
            out.append({"id": p.get("id"), "name": p.get("name"), "path": p.get("path"),
                        "status": p.get("status"), "containers": p.get("containerIds") or p.get("containers")})
    return out


def find_project(dsm: DSMClient, name: str) -> dict:
    projects = list_projects(dsm)
    for p in projects:
        if p["name"] == name:
            return p
    names = ", ".join(str(p["name"]) for p in projects)
    raise ValueError(f"No Container Manager project named '{name}'. Projects: {names}")


def project_action(dsm: DSMClient, project_id: str, action: str) -> str:
    """Runs a Container Manager project action and returns its console output."""
    method = PROJECT_ACTIONS.get(action)
    if not method:
        raise ValueError("action must be stop, build, start or restart")
    info = dsm.api_info("SYNO.Docker.Project")
    assert dsm._client is not None
    try:
        r = dsm._client.get(f"{dsm.base}/webapi/{info['path']}", timeout=900, params={
            "api": "SYNO.Docker.Project", "version": 1, "method": method,
            "id": json.dumps(project_id), "_sid": dsm._sid})
    except httpx.HTTPError as e:
        raise DSMError(f"Container Manager did not answer: {e}") from e
    text = r.text
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
            if not data.get("success", True):
                raise DSMError(f"Container Manager error {data.get('error')}")
        except ValueError:
            pass
    return text[-4000:]
