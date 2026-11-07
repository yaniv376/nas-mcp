"""OAuth 2.1 authorization server for Claude, approved from the owner's phone.

Flow:
1. Claude registers itself (dynamic client registration) and opens /authorize.
2. We park the request and send a phone notification with "Approve" / "Deny"
   buttons. Each button opens a one-time URL; the page Claude opened shows a
   short match code and waits.
3. On approve, the waiting page continues to Claude with an authorization code,
   which Claude exchanges for tokens (PKCE checked by the SDK).

Only SHA-256 hashes of tokens are stored, in /data/oauth.json.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

log = logging.getLogger("nasmcp.oauth")

PENDING_TTL = 600          # seconds an approval request stays valid
CODE_TTL = 300
MAX_PENDING = 3
SCOPE = "nas"


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Pending:
    id: str
    secret: str
    match: str
    client_id: str
    client_name: str
    params: AuthorizationParams
    created: float = field(default_factory=time.time)
    decision: str = ""      # "" | approved | denied
    redirect: str = ""


class Store:
    """Tiny JSON persistence for clients and token hashes."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[str, Any] = {"clients": {}, "access": {}, "refresh": {}}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except ValueError:
                log.warning("oauth.json unreadable, starting empty")

    def save(self) -> None:
        now = time.time()
        for kind in ("access", "refresh"):
            self.data[kind] = {k: v for k, v in self.data[kind].items()
                               if not v.get("expires_at") or v["expires_at"] > now}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        tmp.replace(self.path)


class PhoneApprovalProvider:
    def __init__(self, store: Store, public_url: str, static_token: str = "",
                 notify: Callable[[Pending, str, str], None] | None = None,
                 access_hours: int = 8, refresh_days: int = 90):
        self.store = store
        self.public = public_url.rstrip("/")
        self.static_token = static_token
        self.notify = notify
        self.access_ttl = access_hours * 3600
        self.refresh_ttl = refresh_days * 86400
        self.pending: dict[str, Pending] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.last_error = ""

    # -- clients ---------------------------------------------------------------
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self.store.data["clients"].get(client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        with self.store.lock:
            self.store.data["clients"][client_info.client_id] = client_info.model_dump(mode="json")
            self.store.save()

    # -- authorize: park the request and ask the phone --------------------------------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._expire()
        if len(self.pending) >= MAX_PENDING:
            raise AuthorizeError("temporarily_unavailable", "too many approval requests waiting")
        p = Pending(id=secrets.token_urlsafe(16), secret=secrets.token_urlsafe(32),
                    match=f"{secrets.randbelow(10000):04d}", client_id=client.client_id,
                    client_name=client.client_name or "Claude", params=params)
        self.pending[p.id] = p
        approve = f"{self.public}/oauth/decide/{p.id}/{p.secret}/approve"
        deny = f"{self.public}/oauth/decide/{p.id}/{p.secret}/deny"
        if self.notify:
            try:
                self.notify(p, approve, deny)
                self.last_error = ""
            except Exception as e:  # shown on the waiting page
                self.last_error = str(e)
                log.warning("approval notification failed: %s", e)
        return f"{self.public}/oauth/wait?{urlencode({'req': p.id})}"

    def decide(self, req: str, secret: str, action: str) -> str:
        """Returns 'approved', 'denied' or 'expired'."""
        self._expire()
        p = self.pending.get(req)
        if not p or not secrets.compare_digest(p.secret, secret):
            return "expired"
        if p.decision:
            return p.decision
        if action == "approve":
            code = secrets.token_urlsafe(32)
            self.codes[code] = AuthorizationCode(
                code=code, scopes=[SCOPE], expires_at=time.time() + CODE_TTL,
                client_id=p.client_id, code_challenge=p.params.code_challenge,
                redirect_uri=p.params.redirect_uri,
                redirect_uri_provided_explicitly=p.params.redirect_uri_provided_explicitly,
                resource=p.params.resource, subject="owner")
            p.redirect = construct_redirect_uri(str(p.params.redirect_uri), code=code,
                                                state=p.params.state)
            p.decision = "approved"
        else:
            p.redirect = construct_redirect_uri(str(p.params.redirect_uri), error="access_denied",
                                                state=p.params.state)
            p.decision = "denied"
        return p.decision

    def status(self, req: str) -> dict[str, Any]:
        self._expire()
        p = self.pending.get(req)
        if not p:
            return {"state": "expired"}
        if p.decision:
            self.pending.pop(req, None)
            return {"state": p.decision, "redirect": p.redirect}
        return {"state": "waiting", "match": p.match, "client": p.client_name,
                "notify_error": self.last_error}

    def match_code(self, req: str) -> str | None:
        p = self.pending.get(req)
        return p.match if p else None

    def _expire(self) -> None:
        now = time.time()
        for k in [k for k, p in self.pending.items() if now - p.created > PENDING_TTL]:
            self.pending.pop(k, None)
        for k in [k for k, c in self.codes.items() if c.expires_at < now]:
            self.codes.pop(k, None)

    # -- codes and tokens ----------------------------------------------------------
    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> AuthorizationCode | None:
        c = self.codes.get(authorization_code)
        if c and c.client_id == client.client_id and c.expires_at > time.time():
            return c
        return None

    def _issue(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(40)
        now = int(time.time())
        with self.store.lock:
            self.store.data["access"][_h(access)] = {
                "client_id": client_id, "scopes": scopes, "resource": resource,
                "expires_at": now + self.access_ttl, "refresh": _h(refresh)}
            self.store.data["refresh"][_h(refresh)] = {
                "client_id": client_id, "scopes": scopes, "resource": resource,
                "expires_at": now + self.refresh_ttl}
            self.store.save()
        return OAuthToken(access_token=access, expires_in=self.access_ttl,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: AuthorizationCode) -> OAuthToken:
        if not self.codes.pop(authorization_code.code, None):
            raise TokenError("invalid_grant", "code already used")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull,
                                 refresh_token: str) -> RefreshToken | None:
        rec = self.store.data["refresh"].get(_h(refresh_token))
        if not rec or rec["client_id"] != client.client_id or rec["expires_at"] < time.time():
            return None
        return RefreshToken(token=refresh_token, client_id=rec["client_id"], scopes=rec["scopes"],
                            expires_at=rec["expires_at"], resource=rec.get("resource"),
                            subject="owner")

    async def exchange_refresh_token(self, client: OAuthClientInformationFull,
                                     refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        with self.store.lock:
            if not self.store.data["refresh"].pop(_h(refresh_token.token), None):
                raise TokenError("invalid_grant", "refresh token already used")
            self.store.save()
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self.static_token and secrets.compare_digest(token, self.static_token):
            return AccessToken(token=token, client_id="static", scopes=[SCOPE], subject="owner")
        rec = self.store.data["access"].get(_h(token))
        if not rec or rec["expires_at"] < time.time():
            return None
        return AccessToken(token=token, client_id=rec["client_id"], scopes=rec["scopes"],
                           expires_at=rec["expires_at"], resource=rec.get("resource"),
                           subject="owner")

    async def revoke_token(self, token) -> None:
        with self.store.lock:
            h = _h(token.token)
            self.store.data["access"].pop(h, None)
            self.store.data["refresh"].pop(h, None)
            self.store.save()

    def revoke_all(self) -> int:
        with self.store.lock:
            n = len(self.store.data["refresh"])
            self.store.data["access"].clear()
            self.store.data["refresh"].clear()
            self.store.save()
        return n
