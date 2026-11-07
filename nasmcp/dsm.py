"""Minimal Synology DSM Web API client (read side).

Each `with DSMClient(...)` block logs in and out, so no long-lived DSM
session is kept around.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("nasmcp.dsm")


class DSMError(Exception):
    pass


_ERRORS = {
    100: "Unknown error",
    101: "Invalid parameter",
    102: "API does not exist",
    103: "Method does not exist",
    104: "Version not supported",
    105: "Insufficient privileges (the DSM user must be an administrator)",
    106: "Session timeout",
    107: "Session interrupted (logged in elsewhere)",
    119: "SID not found",
    400: "Invalid account or password",
    401: "Account disabled",
    402: "Permission denied",
    403: "Two-step verification code required (turn it off for this user)",
    404: "Two-step verification failed",
}


class DSMClient:
    session_name = "NasMcp"

    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False,
                 timeout: float = 20.0):
        self.base = url.rstrip("/")
        self.user = user
        self.password = password
        self.verify = verify_tls
        self.timeout = timeout
        self._client: httpx.Client | None = None
        self._sid: str | None = None
        self._api_info: dict[str, dict] | None = None

    def __enter__(self) -> "DSMClient":
        if not self.user or not self.password:
            raise DSMError("DSM user or password is not configured")
        self._client = httpx.Client(verify=self.verify, timeout=self.timeout)
        self._login()
        return self

    def __exit__(self, *exc) -> None:
        try:
            self._logout()
        finally:
            if self._client:
                self._client.close()
                self._client = None

    def _call(self, path: str, params: dict[str, Any]) -> dict:
        assert self._client is not None
        if self._sid:
            params = {**params, "_sid": self._sid}
        try:
            r = self._client.get(f"{self.base}/webapi/{path}", params=params)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as e:
            raise DSMError(f"Cannot reach DSM at {self.base}: {e}") from e
        except ValueError as e:
            raise DSMError("DSM returned a non JSON reply") from e
        if not data.get("success"):
            code = (data.get("error") or {}).get("code", 0)
            raise DSMError(f"DSM error {code}: {_ERRORS.get(code, 'see DSM API docs')}")
        return data.get("data", {}) or {}

    def api_info(self, name: str) -> dict:
        if self._api_info is None:
            self._api_info = self._call("query.cgi", {
                "api": "SYNO.API.Info", "version": 1, "method": "query", "query": "all",
            })
        info = self._api_info.get(name)
        if not info:
            raise DSMError(f"DSM API {name} is not available on this NAS")
        return info

    def has_api(self, name: str) -> bool:
        try:
            self.api_info(name)
            return True
        except DSMError:
            return False

    def _login(self) -> None:
        info = self.api_info("SYNO.API.Auth")
        version = min(int(info.get("maxVersion", 3)), 6)
        data = self._call(info["path"], {
            "api": "SYNO.API.Auth", "version": version, "method": "login",
            "account": self.user, "passwd": self.password,
            "session": self.session_name, "format": "sid",
        })
        self._sid = data.get("sid")
        if not self._sid:
            raise DSMError("DSM login returned no session id")

    def _logout(self) -> None:
        if not self._sid or not self._client:
            return
        try:
            info = self.api_info("SYNO.API.Auth")
            self._call(info["path"], {
                "api": "SYNO.API.Auth", "version": 1, "method": "logout",
                "session": self.session_name,
            })
        except Exception as e:  # pragma: no cover - best effort
            log.debug("logout failed: %s", e)
        self._sid = None

    def request(self, api: str, method: str, version: int | None = None, **params) -> dict:
        info = self.api_info(api)
        if version is None:
            version = int(info.get("maxVersion", 1))
        else:
            version = min(version, int(info.get("maxVersion", version)))
        return self._call(info["path"], {"api": api, "version": version, "method": method, **params})

    def try_request(self, api: str, method: str, versions: list[int] | None = None,
                    **params) -> dict:
        """Call `method` with the newest version that knows it (DSM builds differ)."""
        info = self.api_info(api)
        lo, hi = int(info.get("minVersion", 1)), int(info.get("maxVersion", 1))
        candidates = versions or list(range(hi, lo - 1, -1))
        last: DSMError | None = None
        for v in candidates:
            try:
                return self.request(api, method, version=v, **params)
            except DSMError as e:
                last = e
                if "DSM error 103" not in str(e) and "DSM error 104" not in str(e):
                    raise
        raise DSMError(f"{api}.{method}: {last}")
