"""Read-only Docker Engine API client.

Talks to a docker-socket-proxy (POST disabled), never to the raw socket, so
even a bug here cannot change a container.
"""

from __future__ import annotations

import json
import struct
import time
from typing import Any, Iterator

import httpx


class DockerError(Exception):
    pass


def demux(raw: bytes) -> str:
    """Docker multiplexes stdout/stderr of non-TTY containers with 8-byte headers."""
    out: list[bytes] = []
    i = 0
    n = len(raw)
    while i + 8 <= n and raw[i] in (0, 1, 2) and raw[i + 1:i + 4] == b"\x00\x00\x00":
        size = struct.unpack(">I", raw[i + 4:i + 8])[0]
        out.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    if i == 0:  # TTY container: plain stream
        return raw.decode("utf-8", "replace")
    if i < n:
        out.append(raw[i:])
    return b"".join(out).decode("utf-8", "replace")


class DockerClient:
    def __init__(self, base_url: str, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport  # tests inject a mock transport

    def _get(self, path: str, params: dict[str, Any] | None = None, raw: bool = False):
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as c:
                r = c.get(f"{self.base}{path}", params=params)
        except httpx.HTTPError as e:
            raise DockerError(f"Cannot reach Docker at {self.base}: {e}") from e
        if r.status_code == 404:
            raise DockerError(f"Not found: {path}")
        if r.status_code >= 400:
            raise DockerError(f"Docker API {r.status_code} on {path}: {r.text[:200]}")
        return r.content if raw else r.json()

    # -- containers --------------------------------------------------------
    def containers(self) -> list[dict]:
        return self._get("/containers/json", {"all": "true"})

    def inspect(self, name_or_id: str) -> dict:
        return self._get(f"/containers/{name_or_id}/json")

    def find(self, name: str) -> dict | None:
        """Container by exact name, else the only one whose name contains `name`."""
        name = name.strip().lstrip("/")
        hits = []
        for c in self.containers():
            names = [n.lstrip("/") for n in c.get("Names", [])]
            if name in names or c.get("Id", "").startswith(name):
                return c
            if any(name.lower() in n.lower() for n in names):
                hits.append(c)
        return hits[0] if len(hits) == 1 else None

    def logs(self, name_or_id: str, tail: int = 200, since: int | None = None,
             timestamps: bool = True) -> str:
        params: dict[str, Any] = {"stdout": "true", "stderr": "true", "tail": str(tail),
                                  "timestamps": "true" if timestamps else "false"}
        if since:
            params["since"] = str(since)
        return demux(self._get(f"/containers/{name_or_id}/logs", params, raw=True))

    # -- images / system ---------------------------------------------------
    def images(self) -> list[dict]:
        return self._get("/images/json")

    def image(self, ref: str) -> dict:
        return self._get(f"/images/{ref}/json")

    def info(self) -> dict:
        return self._get("/info")

    def events(self, since: int, until: int | None = None) -> list[dict]:
        """Past events kept in the daemon's memory (lost when Docker restarts)."""
        until = until or int(time.time())
        raw = self._get("/events", {"since": str(since), "until": str(until)}, raw=True)
        return list(_parse_json_lines(raw))

    def stream_events(self) -> Iterator[dict]:
        """Blocking live event stream (used by the background recorder)."""
        with httpx.Client(timeout=httpx.Timeout(10.0, read=None)) as c:
            with c.stream("GET", f"{self.base}/events") as r:
                if r.status_code >= 400:
                    raise DockerError(f"Docker events {r.status_code}")
                for line in r.iter_lines():
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue


def _parse_json_lines(raw: bytes) -> Iterator[dict]:
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except ValueError:
                continue
