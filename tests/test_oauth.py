import base64
import hashlib
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn

from nasmcp.oauth import PhoneApprovalProvider, Store
from nasmcp.server import build_app

from .test_core import nas  # noqa: F401


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def oauth_server(nas, tmp_path):  # noqa: F811
    port = _port()
    base = f"http://127.0.0.1:{port}"
    nas.s.public_url = base
    sent = []
    provider = PhoneApprovalProvider(Store(tmp_path / "oauth.json"), base, "t",
                                     notify=lambda p, a, d: sent.append((p, a, d)))
    app, _ = build_app(nas, None, provider)
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield base, sent, provider, tmp_path
    srv.should_exit = True
    th.join(5)


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _authorize(base, client, challenge):
    return httpx.get(f"{base}/authorize", params={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz", "scope": "nas",
        "resource": f"{base}/mcp"}, follow_redirects=False)


def _register(base):
    r = httpx.post(f"{base}/register", json={
        "client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none"})
    assert r.status_code == 201, r.text
    return r.json()


def test_discovery_and_unauthorized(oauth_server):
    base, *_ = oauth_server
    r = httpx.post(f"{base}/mcp", json={})
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")
    meta = httpx.get(f"{base}/.well-known/oauth-authorization-server").json()
    assert meta["registration_endpoint"].endswith("/register")
    assert httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp").status_code == 200


def test_full_phone_approval_flow(oauth_server):
    base, sent, provider, tmp_path = oauth_server
    client = _register(base)
    verifier, challenge = _pkce()
    r = _authorize(base, client, challenge)
    assert r.status_code == 302 and "/oauth/wait" in r.headers["location"]
    wait_url = r.headers["location"]
    page = httpx.get(wait_url)
    assert len(sent) == 1
    p, approve, deny = sent[0]
    assert p.match in page.text
    req = parse_qs(urlparse(wait_url).query)["req"][0]
    assert httpx.get(f"{base}/oauth/status", params={"req": req}).json()["state"] == "waiting"

    # wrong secret does nothing
    bad = approve.replace(p.secret, "x" * len(p.secret))
    assert "expired" in httpx.get(bad).text.lower() or "פגה" in httpx.get(bad).text
    assert httpx.get(f"{base}/oauth/status", params={"req": req}).json()["state"] == "waiting"

    httpx.get(approve)
    st = httpx.get(f"{base}/oauth/status", params={"req": req}).json()
    assert st["state"] == "approved"
    q = parse_qs(urlparse(st["redirect"]).query)
    assert q["state"] == ["xyz"]
    code = q["code"][0]

    tok = httpx.post(f"{base}/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client["client_id"],
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "code_verifier": verifier,
        "resource": f"{base}/mcp"})
    assert tok.status_code == 200, tok.text
    access = tok.json()["access_token"]
    refresh = tok.json()["refresh_token"]
    # code is single use
    again = httpx.post(f"{base}/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client["client_id"],
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "code_verifier": verifier})
    assert again.status_code == 400

    r = httpx.post(f"{base}/mcp", headers={"Authorization": f"Bearer {access}",
                                           "Accept": "application/json, text/event-stream"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                       "protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}})
    assert r.status_code == 200

    # tokens stored only as hashes
    raw = (tmp_path / "oauth.json").read_text()
    assert access not in raw and refresh not in raw

    ref = httpx.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": refresh,
                                            "client_id": client["client_id"]})
    assert ref.status_code == 200, ref.text
    assert ref.json()["access_token"] != access
    # refresh tokens rotate
    reuse = httpx.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": refresh,
                                              "client_id": client["client_id"]})
    assert reuse.status_code == 400


def test_deny(oauth_server):
    base, sent, *_ = oauth_server
    client = _register(base)
    _, challenge = _pkce()
    wait_url = _authorize(base, client, challenge).headers["location"]
    p, approve, deny = sent[0]
    httpx.get(deny)
    req = parse_qs(urlparse(wait_url).query)["req"][0]
    st = httpx.get(f"{base}/oauth/status", params={"req": req}).json()
    assert st["state"] == "denied" and "error=access_denied" in st["redirect"]
    # approving after a deny changes nothing
    httpx.get(approve)


def test_status_page_still_needs_token(oauth_server):
    base, *_ = oauth_server
    assert httpx.get(f"{base}/").status_code == 401
    assert httpx.get(f"{base}/?token=t").status_code == 200


def test_static_token_still_works_on_mcp(oauth_server):
    base, *_ = oauth_server
    r = httpx.post(f"{base}/mcp", headers={"Authorization": "Bearer t",
                                           "Accept": "application/json, text/event-stream"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                       "protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}})
    assert r.status_code == 200


def test_ha_notification_payload(monkeypatch):
    from nasmcp import config, notify
    calls = []

    class R:
        status_code = 200

    monkeypatch.setattr(notify.httpx, "post", lambda url, **kw: calls.append((url, kw)) or R())
    s = config.Settings(notify_mode="ha", ha_url="http://ha:8123/", ha_token="x",
                        ha_notify_service="notify.mobile_app_phone")
    notify.send(s, "T", "M", actions=[{"title": "Approve", "uri": "https://a"}], tag="t1")
    url, kw = calls[0]
    assert url == "http://ha:8123/api/services/notify/mobile_app_phone"
    assert kw["json"]["data"]["actions"] == [{"action": "URI", "title": "Approve", "uri": "https://a"}]
    assert kw["headers"]["Authorization"] == "Bearer x"
    with pytest.raises(notify.NotifyError):
        notify.send(config.Settings(), "T", "M")
