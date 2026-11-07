"""Optional link to the NAS gate (github.com/yaniv376/nas-gate)."""

from __future__ import annotations

from typing import Any

import httpx


class GateError(Exception):
    pass


class GateClient:
    def __init__(self, url: str, token: str, timeout: float = 15.0):
        self.base = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.base and self.token)

    def _get(self, path: str, text: bool = False) -> Any:
        if not self.configured:
            raise GateError("the NAS gate is not configured (gate_url / gate token)")
        try:
            r = httpx.get(f"{self.base}{path}", timeout=self.timeout,
                          headers={"Authorization": f"Bearer {self.token}"})
        except httpx.HTTPError as e:
            raise GateError(f"Cannot reach the gate at {self.base}: {e}") from e
        if r.status_code >= 400:
            raise GateError(f"gate replied {r.status_code}")
        return r.text if text else r.json()

    def status(self) -> dict:
        return self._get("/api/status")

    def scan(self) -> dict:
        data = self._get("/api/scan")
        out = {"score": data.get("score"), "counts": data.get("counts"),
               "finished_at": data.get("finished_at")}
        try:
            out["report"] = self._get("/api/scan/report", text=True)
        except GateError:
            out["findings"] = data.get("findings")
        return out
