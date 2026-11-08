"""Which folders the server may touch, and how.

Two sources, merged:
  * folders this server always mounts (config.yaml or the defaults: docker and
    the read-only DSM files), and
  * the owner's choice per shared folder in the NAS gate ("folders" in the
    gate's /api/status): closed, read, or read and write.

The gate wins for every folder it lists, including docker. Shared folders the
gate allows are found under /host/<volume>/<name> (mount /volume1 to
/host/volume1 and so on). If the gate cannot be reached, only the folders this
server mounts itself are available, so a gate outage never opens anything.
Writes still need the agent window (writes.require_window).
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .config import Folder, Settings
from .gate import GateClient, GateError

HOST_ROOT = "/host"


class FolderPolicy:
    def __init__(self, settings: Settings, gate: GateClient, ttl: float = 30.0,
                 host_root: str = HOST_ROOT):
        self.s = settings
        self.gate = gate
        self.ttl = ttl
        self.host_root = host_root
        self._lock = threading.Lock()
        self._t = 0.0
        self._items: list[dict] | None = None
        self.error = ""

    def _gate_items(self) -> list[dict] | None:
        now = time.time()
        with self._lock:
            if now - self._t < self.ttl:
                return self._items
            self._t = now
            try:
                st = self.gate.status() if self.gate.configured else {}
                f = st.get("folders")
                if isinstance(f, dict):
                    self._items, self.error = f.get("items"), f.get("error") or ""
                else:
                    self._items = None
                    self.error = "" if self.gate.configured else "gate not configured"
            except GateError as e:
                self._items, self.error = None, str(e)
            return self._items

    def invalidate(self) -> None:
        with self._lock:
            self._t = 0.0

    def folders(self) -> list[Folder]:
        static = {f.name: Folder(f.name, f.path, f.access) for f in self.s.folders}
        items = self._gate_items()
        if not items:
            return list(static.values())
        out = dict(static)
        for it in items:
            name, access = it.get("name"), it.get("access", "closed")
            if not name or access not in ("closed", "read", "write"):
                continue
            if name in static:
                path = static[name].path
            else:
                vol = str(it.get("vol_path") or "").strip("/")
                if not vol or "/" in vol or ".." in vol or "/" in name or name.startswith("."):
                    continue
                path = f"{self.host_root}/{vol}/{name}"
            if access == "write" and not os.access(path, os.W_OK):
                access = "read" if Path(path).is_dir() else access
            out[name] = Folder(name, path, access)
        return list(out.values())


_policy: FolderPolicy | None = None


def install(policy: FolderPolicy | None) -> None:
    global _policy
    _policy = policy


def effective(settings: Settings) -> list[Folder]:
    if _policy is not None and _policy.s is settings:
        return _policy.folders()
    return list(settings.folders)
