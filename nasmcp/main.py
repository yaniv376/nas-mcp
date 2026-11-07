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
    app, _ = build_app(nas, recorder)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("NASMCP_PORT", "8790")),
                log_level="info", proxy_headers=True)


if __name__ == "__main__":
    main()
