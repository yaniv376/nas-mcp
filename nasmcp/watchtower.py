"""Read Watchtower's own log to learn what it updated, stopped and when.

Works with containrrr/watchtower and its maintained fork nickfedor/watchtower
(both log in logfmt: time="..." level=info msg="...").
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_FOUND = re.compile(r"Found new (?P<image>\S+) image \((?P<id>[^)]+)\)")
_STOP = re.compile(r"Stopping /?(?P<name>[^\s(]+) \((?P<id>[^)]+)\)")
_CREATE = re.compile(r"Creating /?(?P<name>\S+)")
_RMIMG = re.compile(r"Removing image (?P<id>\S+)")


def parse_line(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in _KV.findall(line):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def _ts(value: str) -> float | None:
    if not value:
        return None
    v = value.strip()
    # trim nanoseconds that fromisoformat cannot read
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?", v)
    if not m:
        return None
    base, frac, tz = m.group(1), (m.group(2) or "")[:7], m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    try:
        return datetime.fromisoformat(base + frac + tz).timestamp()
    except ValueError:
        return None


@dataclass
class Update:
    t: float | None
    container: str
    image: str = ""
    new_image_id: str = ""
    recreated: bool = False


@dataclass
class WatchtowerReport:
    updates: list[Update] = field(default_factory=list)
    stops: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "updates": [asdict(u) for u in self.updates],
            "stops": [dict(x) for x in self.stops],
            "errors": [dict(x) for x in self.errors[-30:]],
            "sessions": [dict(x) for x in self.sessions[-20:]],
        }

    def last_update(self, container: str) -> Update | None:
        name = container.lstrip("/")
        hits = [u for u in self.updates if u.container == name]
        return hits[-1] if hits else None

    def stop_near(self, container: str, t: float, window: float = 900) -> dict | None:
        """A Watchtower stop of `container` within `window` seconds before `t`."""
        name = container.lstrip("/")
        best = None
        for s in self.stops:
            if s["container"] == name and s["t"] and 0 <= t - s["t"] <= window:
                best = s
        return best


def parse(log_text: str) -> WatchtowerReport:
    rep = WatchtowerReport()
    pending: dict[str, dict[str, Any]] = {}   # image -> found info, waiting for stop/create
    last_found: list[dict[str, Any]] = []
    for raw in log_text.splitlines():
        if not raw.strip():
            continue
        # docker adds "<rfc3339nano> " when logs are read with timestamps
        docker_ts = None
        first, _, rest = raw.partition(" ")
        if re.match(r"\d{4}-\d{2}-\d{2}T", first):
            docker_ts = _ts(first)
            line = rest
        else:
            line = raw
        kv = parse_line(line)
        msg = kv.get("msg", "")
        level = kv.get("level", "")
        t = _ts(kv.get("time", "")) or docker_ts
        if not msg:
            continue
        m = _FOUND.search(msg)
        if m:
            info = {"t": t, "image": m["image"], "id": m["id"]}
            pending[m["image"]] = info
            last_found.append(info)
            continue
        m = _STOP.search(msg)
        if m:
            rep.stops.append({"t": t, "container": m["name"], "id": m["id"]})
            continue
        m = _CREATE.search(msg)
        if m:
            name = m["name"]
            # pair with the most recent "found new image" of this session
            info = last_found[-1] if last_found else {}
            rep.updates.append(Update(t=t, container=name, image=info.get("image", ""),
                                      new_image_id=info.get("id", ""), recreated=True))
            if info:
                last_found.pop()
            continue
        if msg.startswith("Session done"):
            rep.sessions.append({"t": t, "failed": kv.get("Failed"), "scanned": kv.get("Scanned"),
                                 "updated": kv.get("Updated")})
            last_found.clear()
            continue
        if level in ("error", "fatal", "warning"):
            rep.errors.append({"t": t, "level": level, "msg": msg[:300]})
    return rep
