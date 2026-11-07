"""The NAS facts and diagnoses that the MCP tools and the status page share."""

from __future__ import annotations

import time
from typing import Any, Callable

from . import files as filesmod
from . import system as sysmod
from . import watchtower as wtmod
from .config import Settings
from .diagnose import SEVERITY_ORDER, Finding, diagnose, summarize
from .docker import DockerClient, DockerError
from .dsm import DSMClient, DSMError
from .events import EventLog
from .gate import GateClient, GateError
from . import writes as w
from pathlib import Path


class NAS:
    def __init__(self, settings: Settings, events: EventLog,
                 dsm_factory: Callable[[], DSMClient] | None = None,
                 docker: DockerClient | None = None, gate: GateClient | None = None):
        self.s = settings
        self.events = events
        self.docker = docker or DockerClient(settings.docker_url)
        self.gate = gate or GateClient(settings.gate_url, settings.gate_token)
        self._dsm_factory = dsm_factory or (lambda: DSMClient(
            settings.dsm_url, settings.dsm_user, settings.dsm_password, settings.dsm_verify_tls))
        self._wt_cache: tuple[float, wtmod.WatchtowerReport] | None = None
        self.audit = w.Audit(events.path.parent / "actions.jsonl")
        self.approvals = w.Approvals(settings.public_url, None)

    # -- DSM ---------------------------------------------------------------------
    def system(self) -> dict:
        try:
            with self._dsm_factory() as dsm:
                return sysmod.system(dsm)
        except DSMError as e:
            return {"errors": [str(e)]}

    def storage(self) -> dict:
        try:
            with self._dsm_factory() as dsm:
                st = sysmod.storage(dsm)
        except DSMError as e:
            return {"errors": [str(e)]}
        st["findings"] = sysmod.storage_findings(st)
        return st

    # -- containers ------------------------------------------------------------------
    def containers(self) -> list[dict]:
        out = []
        for c in self.docker.containers():
            labels = c.get("Labels") or {}
            out.append({
                "name": (c.get("Names") or ["?"])[0].lstrip("/"),
                "image": c.get("Image"),
                "state": c.get("State"),
                "status": c.get("Status"),
                "project": labels.get("com.docker.compose.project"),
                "ports": sorted({f"{p.get('PublicPort')}->{p.get('PrivatePort')}/{p.get('Type')}"
                                 for p in c.get("Ports") or [] if p.get("PublicPort")}),
            })
        return sorted(out, key=lambda x: (x["state"] == "running", x["name"]))

    def _find(self, name: str) -> dict:
        c = self.docker.find(name)
        if not c:
            names = ", ".join(x["name"] for x in self.containers())
            raise DockerError(f"No single container matches '{name}'. Containers: {names}")
        return c

    def container(self, name: str) -> dict:
        c = self._find(name)
        insp = self.docker.inspect(c["Id"])
        s = summarize(c, insp)
        img = s["image"]
        try:
            im = self.docker.image(insp.get("Image", ""))
            s["image_created"] = im.get("Created")
            s["image_version_label"] = (im.get("Config") or {}).get("Labels", {}).get(
                "org.opencontainers.image.version")
        except DockerError:
            pass
        wt = self.watchtower_report()
        upd = wt.last_update(s["name"]) if wt else None
        s["last_watchtower_update"] = (
            {"time": _fmt(upd.t), "image": upd.image, "new_image_id": upd.new_image_id}
            if upd else None)
        s["image_ref"] = img
        return s

    def logs(self, name: str, tail: int = 200, errors_only: bool = False) -> str:
        c = self._find(name)
        tail = max(1, min(int(tail), self.s.max_log_lines))
        text = self.docker.logs(c["Id"], tail=tail)
        if errors_only:
            import re
            rx = re.compile(r"error|critical|fatal|panic|denied|failed|exception|traceback", re.I)
            text = "\n".join(ln for ln in text.splitlines() if rx.search(ln))
        return filesmod.redact(text)

    def watchtower_report(self, max_age: float = 120) -> wtmod.WatchtowerReport | None:
        if self._wt_cache and time.time() - self._wt_cache[0] < max_age:
            return self._wt_cache[1]
        try:
            c = self.docker.find(self.s.watchtower_container)
            if not c:
                return None
            rep = wtmod.parse(self.docker.logs(c["Id"], tail=self.s.max_log_lines * 5))
        except DockerError:
            return None
        self._wt_cache = (time.time(), rep)
        return rep

    def watchtower(self) -> dict:
        rep = self.watchtower_report(max_age=0)
        if rep is None:
            return {"error": f"No Watchtower container matching '{self.s.watchtower_container}'"}
        d = rep.as_dict()
        for key in ("updates", "stops", "errors", "sessions"):
            for item in d[key]:
                item["time"] = _fmt(item.pop("t", None))
        d["updates"] = d["updates"][-40:]
        d["stops"] = d["stops"][-40:]
        d["sessions_with_updates"] = [s for s in d.pop("sessions") if s.get("updated") not in ("0", None)]
        return d

    def diagnose(self, name: str | None = None, log_lines: int = 300) -> dict:
        wt = self.watchtower_report()
        targets = [self._find(name)] if name else self.docker.containers()
        findings: list[Finding] = []
        healthy: list[str] = []
        for c in targets:
            try:
                insp = self.docker.inspect(c["Id"])
                logs = self.docker.logs(c["Id"], tail=log_lines)
            except DockerError as e:
                findings.append(Finding((c.get("Names") or ["?"])[0].lstrip("/"), "medium",
                                        "unreadable", "Could not read the container", str(e)))
                continue
            fs = diagnose(c, insp, logs, wt)
            if any(f.severity in ("high", "medium") for f in fs) or name:
                findings.extend(fs)
            else:
                healthy.append(summarize(c, insp)["name"])
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        return {
            "checked": len(targets),
            "problems": [f.as_dict() for f in findings if f.severity in ("high", "medium")],
            "notes": [f.as_dict() for f in findings if f.severity in ("low", "info")][:40],
            "healthy": sorted(healthy),
            "watchtower_log_read": wt is not None,
        }

    def timeline(self, hours: int = 72, name: str | None = None) -> dict:
        since = time.time() - hours * 3600
        items = [dict(e, time=_fmt(e["t"])) for e in self.events.query(since, name)]
        wt = self.watchtower_report()
        if wt:
            for u in wt.updates:
                if u.t and u.t >= since and (not name or name.lower() in u.container.lower()):
                    items.append({"t": u.t, "time": _fmt(u.t), "type": "watchtower",
                                  "action": "update", "name": u.container, "image": u.image})
        items.sort(key=lambda x: x.get("t") or 0)
        for i in items:
            i.pop("t", None)
        first = self.events.first_time()
        return {"since": _fmt(since), "events": items[-300:],
                "recording_since": _fmt(first) if first else "not yet recording"}

    # -- backups / gate / files ------------------------------------------------------------
    def backups(self) -> list[dict]:
        out = []
        now = time.time()
        for b in self.s.backups:
            nf = filesmod.newest_file(b.path, b.pattern)
            item: dict[str, Any] = {"name": b.name}
            if not nf:
                item.update(status="missing", detail="no backup file found")
            else:
                age_h = (now - nf["modified"]) / 3600
                item.update(newest=nf["file"], size_mb=nf["size_mb"], time=_fmt(nf["modified"]),
                            age_hours=round(age_h, 1),
                            status="ok" if age_h <= b.max_age_hours else "late")
            out.append(item)
        return out

    def security_scan(self) -> dict:
        try:
            return self.gate.scan()
        except GateError as e:
            return {"error": str(e)}

    def gate_status(self) -> dict:
        try:
            st = self.gate.status()
        except GateError as e:
            return {"error": str(e)}
        return {k: st.get(k) for k in ("is_open", "remaining_seconds", "protections", "scan", "version")}

    def overview(self) -> dict:
        """One call that answers 'how is the NAS?'"""
        sysinfo = self.system()
        st = self.storage()
        try:
            diag = self.diagnose()
            containers = {"checked": diag["checked"], "problems": diag["problems"][:15],
                           "healthy_count": len(diag["healthy"])}
        except DockerError as e:
            containers = {"error": str(e)}
        scan = self.security_scan()
        return {
            "system": sysinfo,
            "storage_findings": st.get("findings", []),
            "volumes": st.get("volumes", []),
            "containers": containers,
            "backups": self.backups(),
            "security_score": scan.get("score") if isinstance(scan, dict) else None,
        }


class Changes:
    """Write operations. Each checks the gate window first and is audited."""

    def __init__(self, nas: "NAS"):
        self.nas = nas

    def _guard(self) -> dict:
        return w.require_window(self.nas.gate)

    def _docker_dir(self) -> Path:
        f = self.nas.s.folder("docker")
        if not f or f.access != "write":
            raise w.WriteDenied("The docker folder is mounted read-only: change ':ro' to ':rw' "
                                "on the /volume1/docker line of nas-mcp's compose file.")
        return Path(f.path)

    def _project_dir(self, project: str) -> Path:
        root = self._docker_dir().resolve()
        d = (root / project.strip("/")).resolve()
        if root not in d.parents:
            raise w.WriteDenied("the project folder must be inside the docker folder")
        return d

    def _do(self, action: str, target: str, fn, **extra):
        win = self._guard()
        try:
            result = fn()
        except Exception as e:
            self.nas.audit.add(action, target, f"failed: {e}", **extra)
            raise
        self.nas.audit.add(action, target, "ok", **extra)
        return {"done": True, "window_minutes_left": win["remaining_minutes"], **(
            result if isinstance(result, dict) else {"result": result})}

    def container(self, name: str, action: str) -> dict:
        c = self.nas._find(name)
        cname = (c.get("Names") or [name])[0].lstrip("/")
        return self._do(f"container_{action}", cname,
                        lambda: w.container_action(self.nas.docker, c["Id"], cname, action))

    def restart_policy(self, name: str, policy: str) -> dict:
        c = self.nas._find(name)
        cname = (c.get("Names") or [name])[0].lstrip("/")
        return self._do("restart_policy", cname,
                        lambda: w.set_restart_policy(self.nas.docker, c["Id"], cname, policy),
                        policy=policy)

    def retire(self, name: str) -> dict:
        c = self.nas._find(name)
        cname = (c.get("Names") or [name])[0].lstrip("/")
        w._check_not_protected(cname)
        self._guard()
        self.nas.approvals.ask(f"Retire container {cname} (stop it and rename to to_delete_)")
        return self._do("retire", cname,
                        lambda: {"renamed_to": w.retire_container(self.nas.docker, c["Id"], cname)})

    def compose_write(self, project: str, content: str) -> dict:
        d = self._project_dir(project)
        return self._do("compose_write", project, lambda: w.write_compose(d, content))

    def compose_restore(self, project: str, backup: str) -> dict:
        d = self._project_dir(project)
        return self._do("compose_restore", project, lambda: w.restore_compose(d, backup),
                        backup=backup)

    def compose_backups(self, project: str) -> list[str]:
        return w.list_backups(self._project_dir(project))

    def projects(self) -> list[dict]:
        with self.nas._dsm_factory() as dsm:
            return w.list_projects(dsm)

    def project(self, name: str, action: str) -> dict:
        def run():
            with self.nas._dsm_factory() as dsm:
                p = w.find_project(dsm, name)
                if action == "build":
                    # Build applies compose changes only on a stopped project.
                    w.project_action(dsm, p["id"], "stop")
                out = w.project_action(dsm, p["id"], action)
            return {"project": name, "output_tail": out}
        return self._do(f"project_{action}", name, run)


def _fmt(t: float | None) -> str:
    if not t:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
