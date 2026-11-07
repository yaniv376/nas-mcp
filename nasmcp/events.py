"""Persistent Docker event log.

Docker keeps past events only in memory and loses them when it restarts, and
Container Manager's own log does not show what Watchtower does. This recorder
follows the live event stream and appends the interesting ones to
`/data/events.jsonl`, so "when did this container stop, and who stopped it"
has an answer later.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from .docker import DockerClient

log = logging.getLogger("nasmcp.events")

INTERESTING = {
    "container": {"create", "start", "die", "stop", "kill", "oom", "restart", "destroy",
                  "rename", "health_status", "pause", "unpause"},
    "image": {"pull", "delete", "untag", "tag"},
}
MAX_BYTES = 5_000_000


def compact(ev: dict[str, Any]) -> dict[str, Any] | None:
    etype = ev.get("Type") or ev.get("type")
    action = str(ev.get("Action") or ev.get("status") or "")
    base_action = action.split(":", 1)[0]
    if base_action not in INTERESTING.get(etype or "", set()):
        return None
    attrs = (ev.get("Actor") or {}).get("Attributes") or {}
    out = {
        "t": ev.get("time") or int(time.time()),
        "type": etype,
        "action": action,
        "name": attrs.get("name") or (ev.get("Actor") or {}).get("ID", "")[:12],
    }
    if attrs.get("image"):
        out["image"] = attrs["image"]
    if attrs.get("exitCode") is not None:
        out["exit"] = attrs["exitCode"]
    proj = attrs.get("com.docker.compose.project")
    if proj:
        out["project"] = proj
    return out


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def append(self, item: dict[str, Any]) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
            if self.path.stat().st_size > MAX_BYTES:
                lines = self.path.read_text(encoding="utf-8").splitlines()
                self.path.write_text("\n".join(lines[len(lines) // 2:]) + "\n", encoding="utf-8")

    def query(self, since: float = 0, name: str | None = None, limit: int = 300) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        needle = (name or "").lower()
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("t", 0) < since:
                continue
            if needle and needle not in str(item.get("name", "")).lower() \
                    and needle not in str(item.get("image", "")).lower():
                continue
            out.append(item)
        return out[-limit:]

    def first_time(self) -> float | None:
        if not self.path.exists():
            return None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    return json.loads(line).get("t")
                except ValueError:
                    continue
        return None


class Recorder(threading.Thread):
    daemon = True

    def __init__(self, docker: DockerClient, store: EventLog):
        super().__init__(name="event-recorder")
        self.docker = docker
        self.store = store
        self.connected = False
        self.last_error = ""
        self.listeners: list = []   # callables(item), e.g. the update watcher

    def run(self) -> None:  # pragma: no cover - needs a live daemon
        backoff = 5
        while True:
            try:
                self.connected = True
                self.last_error = ""
                for ev in self.docker.stream_events():
                    item = compact(ev)
                    if item:
                        self.store.append(item)
                        for fn in self.listeners:
                            try:
                                fn(item)
                            except Exception as e:  # a listener never stops recording
                                log.warning("event listener: %s", e)
                    backoff = 5
            except Exception as e:
                self.last_error = str(e)
                log.warning("event stream lost: %s", e)
            self.connected = False
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
