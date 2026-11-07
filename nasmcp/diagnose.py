"""Container diagnosis: turn state, logs and Watchtower history into findings.

Pure functions over plain dicts, so they are easy to test without Docker.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .watchtower import WatchtowerReport

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}


@dataclass
class Finding:
    container: str
    severity: str            # high | medium | low | info
    code: str
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    suggestion: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


# Images whose upstream ended maintenance -> replacement (repository part only).
DEPRECATED_IMAGES: dict[str, str] = {
    "fallenbagel/jellyseerr": "ghcr.io/seerr-team/seerr",
    "containrrr/watchtower": "nickfedor/watchtower",
    "linuxserver/letsencrypt": "linuxserver/swag",
    "filebrowser/filebrowser": "(archived upstream; Synology File Station covers it)",
}

# Command-line flags or settings that leave a service without a password.
NO_AUTH_MARKERS = ("--rc-no-auth", "--no-auth", "--noauth", "auth=none", "AUTH=false",
                   "DISABLE_AUTH=true", "--allow-anonymous")

EXIT_CODES = {
    0: "exited cleanly (the program finished on its own)",
    1: "the program failed with an error (see the log)",
    2: "wrong command line arguments",
    125: "Docker could not start the container",
    126: "the command is not executable (permissions)",
    127: "the command was not found in the image",
    137: "killed with SIGKILL (out of memory, or a stop that timed out)",
    139: "crashed (segmentation fault)",
    143: "stopped with SIGTERM (a normal stop: user, Watchtower or system)",
}

LOG_PATTERNS: list[tuple[str, re.Pattern, str, str, str]] = [
    # code, regex, severity, title, suggestion
    ("permission", re.compile(r"permission denied|EACCES|operation not permitted", re.I), "high",
     "Permission error on a mounted folder",
     "Run the container as the folder owner: add user: \"1026:100\" (your DSM user:group) to the "
     "compose file, or fix the folder owner. Some images need user: \"0:0\"."),
    ("port_in_use", re.compile(r"port is already allocated|address already in use", re.I), "high",
     "Port already in use",
     "Another container or DSM service uses the same port. Change the host side of ports: "
     "in the compose file."),
    ("bind_missing", re.compile(r"bind (?:mount )?(?:source path )?.*does not exist|"
                                r"no such file or directory.*mount", re.I), "high",
     "A mounted folder does not exist",
     "Create the folder in File Station, or correct the path under volumes:."),
    ("flag_changed", re.compile(r"superseded|unknown flag|flag provided but not defined|"
                                r"unrecognized (?:argument|option)|no such option|deprecated and removed",
                                re.I), "high",
     "The command uses an option the new version no longer accepts",
     "A newer image changed its options. Pin the previous version in the compose file "
     "(image: name:<old version>) or update the command."),
    ("exec_format", re.compile(r"exec format error", re.I), "high",
     "Image built for a different processor",
     "Pick an image tag for amd64 (the DS920+ is Intel)."),
    ("disk_full", re.compile(r"no space left on device", re.I), "high",
     "Disk full", "Free space on the volume."),
    ("oom", re.compile(r"out of memory|cannot allocate memory|OOMKilled", re.I), "high",
     "Out of memory", "Raise or remove the memory limit, or check for a leak."),
    ("db_locked", re.compile(r"database is locked|database disk image is malformed", re.I), "medium",
     "Database problem", "Stop the container, back up its config folder, and check the database file."),
    ("dns", re.compile(r"temporary failure in name resolution|no such host|ENOTFOUND", re.I), "medium",
     "Cannot resolve host names", "Check the container network and the NAS DNS settings."),
]

ERROR_LINE = re.compile(r"\b(CRITICAL|FATAL|ERROR|Error:|panic:|Traceback)\b")
_TS_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s+")
_NOISE = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}[T ][\d:.,]+Z?|\b\d+(\.\d+)?(ms|s)?\b|0x[0-9a-f]+", re.I)


def parse_time(value: str | None) -> float | None:
    if not value or value.startswith("0001-01-01"):
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?", value)
    if not m:
        return None
    tz = m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    try:
        return datetime.fromisoformat(m.group(1) + (m.group(2) or "")[:7] + tz).timestamp()
    except ValueError:
        return None


def image_repo(image: str) -> str:
    img = str(image or "").strip().split("@", 1)[0]
    for p in ("docker.io/", "registry-1.docker.io/", "index.docker.io/", "lscr.io/", "ghcr.io/"):
        if img.startswith(p):
            img = img[len(p):]
            break
    last = img.rsplit("/", 1)[-1]
    if ":" in last:
        img = img[: len(img) - len(last)] + last.split(":", 1)[0]
    if "/" not in img:
        img = "library/" + img
    return img.lower()


def image_tag(image: str) -> str:
    last = str(image or "").split("@", 1)[0].rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else "latest"


def repeated_errors(logs: str, min_count: int = 3) -> list[tuple[str, int]]:
    """Error lines that repeat (normalised for times and numbers)."""
    counts: Counter[str] = Counter()
    sample: dict[str, str] = {}
    for line in logs.splitlines():
        body = _TS_PREFIX.sub("", line).strip()
        if not body or not ERROR_LINE.search(body):
            continue
        key = _NOISE.sub("#", body)[:200]
        counts[key] += 1
        sample.setdefault(key, body[:300])
    return [(sample[k], n) for k, n in counts.most_common(5) if n >= min_count]


def summarize(container: dict, inspect: dict) -> dict[str, Any]:
    st = inspect.get("State") or {}
    hc = inspect.get("HostConfig") or {}
    cfg = inspect.get("Config") or {}
    labels = cfg.get("Labels") or {}
    name = (inspect.get("Name") or (container.get("Names") or ["?"])[0]).lstrip("/")
    return {
        "name": name,
        "image": cfg.get("Image") or container.get("Image", ""),
        "image_id": (inspect.get("Image") or "")[:19],
        "state": st.get("Status"),
        "health": (st.get("Health") or {}).get("Status"),
        "exit_code": st.get("ExitCode"),
        "exit_meaning": EXIT_CODES.get(st.get("ExitCode")) if st.get("Status") != "running" else None,
        "oom_killed": st.get("OOMKilled"),
        "error": st.get("Error") or None,
        "started_at": st.get("StartedAt"),
        "finished_at": st.get("FinishedAt"),
        "restart_count": inspect.get("RestartCount", 0),
        "restart_policy": (hc.get("RestartPolicy") or {}).get("Name") or "no",
        "created": inspect.get("Created"),
        "compose_project": labels.get("com.docker.compose.project"),
        "watchtower_enabled": labels.get("com.centurylinklabs.watchtower.enable", "default"),
        "ports": container.get("Ports") or [],
        "mounts": [f"{m.get('Source')} -> {m.get('Destination')} ({'rw' if m.get('RW') else 'ro'})"
                   for m in inspect.get("Mounts") or []],
        "command": " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or [])),
    }


def diagnose(container: dict, inspect: dict, logs: str = "",
             wt: WatchtowerReport | None = None, now: float | None = None) -> list[Finding]:
    s = summarize(container, inspect)
    name = s["name"]
    out: list[Finding] = []
    state = s["state"]
    now = now or datetime.now().timestamp()
    started = parse_time(s["started_at"])
    finished = parse_time(s["finished_at"])
    cfg = inspect.get("Config") or {}
    hc = inspect.get("HostConfig") or {}

    # -- state ----------------------------------------------------------------
    if state == "restarting" or (s["restart_count"] >= 5 and started and now - started < 600):
        out.append(Finding(name, "high", "restart_loop", "Crash loop: the container keeps restarting",
                           f"restart count {s['restart_count']}, last start {_fmt(started)}",
                           suggestion="Read the repeated error below; the fix is usually in the "
                                      "command, the image version or folder permissions."))
    if state == "exited":
        code = s["exit_code"]
        sev = "low" if code in (0, 143) else "high"
        detail = f"exit code {code}: {EXIT_CODES.get(code, 'unknown')}"
        if s["oom_killed"]:
            sev, detail = "high", "killed for using too much memory (OOM)"
        stopper = wt.stop_near(name, finished) if (wt and finished) else None
        ev = []
        if stopper:
            ev.append(f"Watchtower stopped it at {_fmt(stopper['t'])} for an update")
            sev = "high"
            detail += "; it was stopped by Watchtower and did not come back up"
        out.append(Finding(name, sev, "stopped", f"Container is stopped since {_fmt(finished)}",
                           detail, ev))
        if s["restart_policy"] in ("no", ""):
            out.append(Finding(name, "medium", "no_restart_policy",
                               "No automatic restart",
                               "If it stops (update, crash, NAS reboot) it stays down.",
                               suggestion="Add restart: unless-stopped to the compose file "
                                          "(or Enable auto-restart in Container Manager)."))
    if state == "created":
        out.append(Finding(name, "medium", "never_started", "Container was created but never started",
                           s["error"] or ""))
    if s["error"]:
        out.append(Finding(name, "high", "docker_error", "Docker reported an error starting it",
                           str(s["error"])[:300],
                           suggestion=_suggest_for_text(str(s["error"]))))
    if s["health"] == "unhealthy":
        out.append(Finding(name, "medium", "unhealthy", "Health check is failing"))

    # -- logs -----------------------------------------------------------------
    seen_codes: set[str] = set()
    for code, rx, sev, title, sugg in LOG_PATTERNS:
        lines = [ln for ln in logs.splitlines() if rx.search(ln)]
        if lines and code not in seen_codes:
            seen_codes.add(code)
            out.append(Finding(name, sev, f"log_{code}", title,
                               f"{len(lines)} matching log line(s)",
                               [_TS_PREFIX.sub('', ln)[:300] for ln in lines[-3:]], sugg))
    for line, n in repeated_errors(logs):
        out.append(Finding(name, "high" if n >= 10 else "medium", "repeated_error",
                           f"The same error repeats {n} times in the recent log", "",
                           [line]))

    # -- after an update? --------------------------------------------------------
    if wt:
        upd = wt.last_update(name)
        bad = state in ("restarting", "exited") or any(f.severity == "high" for f in out)
        if upd and bad and upd.t and (not finished or finished >= upd.t - 60):
            out.append(Finding(name, "high", "broke_after_update",
                               "The problems started after a Watchtower update",
                               f"updated at {_fmt(upd.t)} to {upd.image} ({upd.new_image_id[:19]})",
                               suggestion="Roll back: pin the previous version in the compose file "
                                          "(image: name:<previous tag>) and add the label "
                                          "com.centurylinklabs.watchtower.enable=false until fixed."))

    # -- configuration ------------------------------------------------------------
    if not s["compose_project"]:
        out.append(Finding(name, "low", "standalone",
                           "Standalone container (not a Compose project)",
                           "Settings live only inside Container Manager, so a rebuild means "
                           "re-entering them by hand.",
                           suggestion="Recreate it as a Compose project with the same volumes, "
                                      "ports and command (one YAML file, easy to rebuild)."))
    if image_tag(s["image"]) == "latest" and s["watchtower_enabled"] != "false":
        out.append(Finding(name, "info", "latest_tag",
                           "Uses the :latest tag, so Watchtower installs every new version",
                           suggestion="Fine for most apps; pin a version for fragile ones."))

    # -- security -----------------------------------------------------------------
    cmd = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or []) + (cfg.get("Env") or []))
    for marker in NO_AUTH_MARKERS:
        if marker.lower() in cmd.lower():
            out.append(Finding(name, "medium", "no_auth", "Service runs without a password",
                               f"found '{marker}' in the command or environment",
                               suggestion="Anyone on the home network can use it. Add a password, "
                                          "or remove the container if it is not needed."))
            break
    repo = image_repo(s["image"])
    if repo in DEPRECATED_IMAGES:
        out.append(Finding(name, "medium", "deprecated_image",
                           "The image is no longer maintained (no security fixes)",
                           f"{repo} -> {DEPRECATED_IMAGES[repo]}"))
    if hc.get("Privileged"):
        out.append(Finding(name, "medium", "privileged", "Runs in privileged mode",
                           "It has full control of the NAS kernel.",
                           suggestion="Remove privileged: true unless the app really needs it."))
    for m in inspect.get("Mounts") or []:
        if str(m.get("Source", "")).endswith("docker.sock") and m.get("RW"):
            out.append(Finding(name, "low", "docker_socket",
                               "Has write access to the Docker socket",
                               "It can control every container (expected for Watchtower and Portainer)."))
            break

    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return out


def _suggest_for_text(text: str) -> str:
    for _code, rx, _sev, _title, sugg in LOG_PATTERNS:
        if rx.search(text):
            return sugg
    return ""


def _fmt(t: float | None) -> str:
    if not t:
        return "?"
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
