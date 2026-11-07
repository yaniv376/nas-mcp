"""Entry point: python -m nasmcp.main"""

from __future__ import annotations

import logging
import os

import uvicorn

from . import config
from .core import NAS
from .docker import DockerClient
from .events import EventLog, Recorder
from .server import build_app


def _guess_lan_url(settings) -> str:
    """Same host as the DSM address, this server's port (usually right on a NAS)."""
    from urllib.parse import urlparse
    host = urlparse(settings.dsm_url).hostname
    if not host or host in ("127.0.0.1", "localhost"):
        return ""
    return f"http://{host}:{os.environ.get('NASMCP_PORT', '8790')}"


def main() -> None:
    logging.basicConfig(level=os.environ.get("NASMCP_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = config.load()
    if not settings.token:
        logging.getLogger("nasmcp").warning(
            "NASMCP_TOKEN is not set: every request will be refused until it is.")
    docker = DockerClient(settings.docker_url)
    events = EventLog(config.DATA_DIR / "events.jsonl")
    nas = NAS(settings, events, docker=docker)
    recorder = Recorder(docker, events)
    recorder.start()
    provider = None
    if settings.public_url:
        from . import notify
        from .oauth import PhoneApprovalProvider, Store
        he = settings.language == "he"

        def ask_phone(p, approve, deny):
            notify.send(settings,
                        "אישור כניסה ל-NAS" if he else "NAS login request",
                        (f"{p.client_name} מבקש גישה ל-MCP של ה-NAS. קוד: {p.match}" if he else
                         f"{p.client_name} asks for access to the NAS MCP. Code: {p.match}"),
                        actions=[{"title": "אשר" if he else "Approve", "uri": approve},
                                 {"title": "דחה" if he else "Deny", "uri": deny}],
                        tag=f"nasmcp-{p.id}")

        provider = PhoneApprovalProvider(
            Store(config.DATA_DIR / "oauth.json"), settings.public_url, settings.token,
            notify=ask_phone, access_hours=settings.access_token_hours,
            refresh_days=settings.refresh_token_days)
    if settings.public_url and settings.notify_mode != "none":
        from . import notify as _n
        he = settings.language == "he"

        def ask_change(a, approve, deny):
            title = "אישור פעולה ב-NAS" if he else "NAS change request"
            yes, no = ("אשר", "דחה") if he else ("Approve", "Deny")
            # Phone: push with buttons (public address works away from home).
            _n.send(settings, title, a.what, actions=[{"title": yes, "uri": approve},
                                                      {"title": no, "uri": deny}],
                    tag=f"nasmcp-act-{a.id}")
            # Computer: Home Assistant's notification panel, links via the home address.
            base_pub = settings.public_url.rstrip("/")
            base_lan = (settings.lan_url or _guess_lan_url(settings) or settings.public_url).rstrip("/")
            lan_yes, lan_no = approve.replace(base_pub, base_lan), deny.replace(base_pub, base_lan)
            _n.ha_panel(settings, title, f"{a.what}\n\n**[{yes}]({lan_yes})** · [{no}]({lan_no})",
                        f"nasmcp_act_{a.id}")
        nas.approvals.send = ask_change
        nas.approvals.on_done = lambda a: _n.ha_panel_dismiss(settings, f"nasmcp_act_{a.id}")
    from .updates import UpdateWatcher
    from pathlib import Path as _P
    dfolder = settings.folder("docker")
    he2 = settings.language == "he"

    def update_alert(u, paths):
        if settings.notify_mode == "none":
            return
        from . import notify as _n
        pub = settings.public_url.rstrip("/")
        lan = (settings.lan_url or _guess_lan_url(settings) or pub).rstrip("/")
        title = (f"{u.name} נשבר אחרי עדכון" if he2 else f"{u.name} broke after an update")
        body = "; ".join(u.problems)[:300]
        yes, no = ("החזר לגרסה הקודמת", "התעלם") if he2 else ("Roll back", "Ignore")
        if pub:
            _n.send(settings, title, body, actions=[{"title": yes, "uri": pub + paths["rollback"]},
                                                    {"title": no, "uri": pub + paths["ignore"]}],
                    tag=f"nasmcp-upd-{u.id}")
        _n.ha_panel(settings, title, f"{body}\n\n**[{yes}]({lan}{paths['rollback']})** · "
                                     f"[{no}]({lan}{paths['ignore']})", f"nasmcp_upd_{u.id}")

    watcher = UpdateWatcher(docker, config.DATA_DIR, notify=update_alert, audit=nas.audit,
                            docker_root=_P(dfolder.path) if dfolder and dfolder.access == "write" else None)
    nas.watcher = watcher
    watcher.start()
    app, _ = build_app(nas, recorder, provider)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("NASMCP_PORT", "8790")),
                log_level="info", proxy_headers=True)


if __name__ == "__main__":
    main()
