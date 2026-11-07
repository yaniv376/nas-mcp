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
    app, _ = build_app(nas, recorder, provider)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("NASMCP_PORT", "8790")),
                log_level="info", proxy_headers=True)


if __name__ == "__main__":
    main()
