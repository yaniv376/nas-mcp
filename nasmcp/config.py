"""Settings for nas-mcp.

Everything specific to one NAS lives in `config.yaml` inside the data volume
(never in the code or the repository). Secrets may instead come from
environment variables, which win over the file:

    NASMCP_TOKEN          bearer token Claude (or a test client) must send
    NASMCP_DSM_PASSWORD   password of the DSM user
    NASMCP_GATE_TOKEN     API token of the NAS gate (same one HA uses)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(os.environ.get("NASMCP_DATA_DIR", "/data"))
CONFIG_FILE = DATA_DIR / "config.yaml"

ACCESS_LEVELS = ("closed", "read", "write")


@dataclass
class Folder:
    name: str                 # shown to Claude, e.g. "docker"
    path: str                 # path inside the container, e.g. /host/docker
    access: str = "read"      # closed | read | write (write needs an open window, stage 1c)


@dataclass
class BackupTarget:
    name: str                 # e.g. "Home Assistant (NFS)"
    path: str                 # folder inside the container that receives the backups
    pattern: str = "*.tar"
    max_age_hours: int = 30   # older newest-file than this is a finding


@dataclass
class Settings:
    language: str = "en"                       # en | he (status page only)
    timezone: str = "UTC"

    # Docker, through a read-only socket proxy (never the raw socket)
    docker_url: str = "http://docker-proxy:2375"
    watchtower_container: str = "watchtower"   # name (or part of it) of the Watchtower container

    # DSM Web API (a dedicated administrator user, 2FA off for it)
    dsm_url: str = "https://127.0.0.1:5001"
    dsm_user: str = ""
    dsm_password: str = ""
    dsm_verify_tls: bool = False

    # NAS gate (optional): read its security scan and, from stage 1c, its MCP window
    gate_url: str = ""
    gate_token: str = ""

    # MCP endpoint protection. `token` is a static bearer token for the home
    # network and the status page. With `public_url` set (the Funnel or tunnel
    # address), OAuth is on: Claude registers itself and every new login waits
    # for the owner to approve it from a phone notification.
    token: str = ""
    public_url: str = ""
    # Home-network address of this server (e.g. http://192.168.1.10:8790). Approval
    # links in Home Assistant's notification panel use it, so approving works from
    # a computer at home too.
    lan_url: str = ""
    access_token_hours: int = 8
    refresh_token_days: int = 90

    # Notifications (OAuth approvals now, update alerts later)
    notify_mode: str = "none"                  # ha | webhook | none
    ha_url: str = ""
    ha_token: str = ""
    ha_notify_service: str = ""                # e.g. notify.mobile_app_myphone
    # A Home Assistant input_text (password mode) that this server fills in with
    # a read-only token for /api/health, so HA's health sensor needs no manual
    # setup. Empty turns it off; nothing happens if the helper does not exist.
    ha_token_entity: str = "input_text.nas_mcp_token"
    webhook_url: str = ""

    folders: list[Folder] = field(default_factory=list)
    backups: list[BackupTarget] = field(default_factory=list)

    # limits
    max_file_bytes: int = 512_000
    max_log_lines: int = 2000

    @property
    def health_token(self) -> str:
        """Read-only token, accepted only by /api/health (derived from `token`)."""
        if not self.token:
            return ""
        import hashlib
        import hmac
        return hmac.new(self.token.encode(), b"nas-mcp/api/health", hashlib.sha256).hexdigest()[:40]

    def folder(self, name: str) -> Folder | None:
        for f in self.folders:
            if f.name == name:
                return f
        return None


_ENV = {
    "token": "NASMCP_TOKEN",
    "dsm_password": "NASMCP_DSM_PASSWORD",
    "dsm_user": "NASMCP_DSM_USER",
    "dsm_url": "NASMCP_DSM_URL",
    "gate_url": "NASMCP_GATE_URL",
    "gate_token": "NASMCP_GATE_TOKEN",
    "docker_url": "NASMCP_DOCKER_URL",
    "timezone": "NASMCP_TIMEZONE",
    "language": "NASMCP_LANGUAGE",
    "watchtower_container": "NASMCP_WATCHTOWER",
    "public_url": "NASMCP_PUBLIC_URL",
    "lan_url": "NASMCP_LAN_URL",
    "notify_mode": "NASMCP_NOTIFY_MODE",
    "ha_url": "NASMCP_HA_URL",
    "ha_token": "NASMCP_HA_TOKEN",
    "ha_notify_service": "NASMCP_HA_NOTIFY_SERVICE",
    "ha_token_entity": "NASMCP_HA_TOKEN_ENTITY",
    "webhook_url": "NASMCP_WEBHOOK_URL",
}

DEFAULT_DOCKER_MOUNT = "/host/docker"
# Optional: DSM's own Web API definition files (read-only), used to look up
# which methods each DSM API offers before writing tools against it.
DEFAULT_WEBAPI_MOUNT = "/host/webapi"
# Further optional read-only mounts, picked up when present (name -> path).
OPTIONAL_MOUNTS = {
    "dsm_webapi": "/host/webapi",                 # /usr/syno/synoman/webapi
    "dsm_ui": "/host/webman",                     # /usr/syno/synoman/webman
    "container_manager": "/host/container-manager",  # /var/packages/ContainerManager/target
}


def _from_dict(raw: dict[str, Any]) -> Settings:
    s = Settings()
    names = {f.name for f in fields(Settings)}
    for key, value in (raw or {}).items():
        if key not in names or value is None:
            continue
        if key == "folders":
            out = []
            for item in value:
                f = Folder(name=str(item["name"]), path=str(item["path"]),
                           access=str(item.get("access", "read")))
                if f.access not in ACCESS_LEVELS:
                    raise ValueError(f"folder {f.name}: access must be one of {ACCESS_LEVELS}")
                out.append(f)
            s.folders = out
        elif key == "backups":
            s.backups = [BackupTarget(name=str(b["name"]), path=str(b["path"]),
                                      pattern=str(b.get("pattern", "*.tar")),
                                      max_age_hours=int(b.get("max_age_hours", 30)))
                         for b in value]
        else:
            setattr(s, key, value)
    return s


def load(path: Path | None = None) -> Settings:
    path = path or CONFIG_FILE
    raw: dict[str, Any] = {}
    if path.exists():
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    s = _from_dict(raw)
    for attr, env in _ENV.items():
        val = os.environ.get(env)
        if val:
            setattr(s, attr, val)
    # With no config.yaml, the docker folder mounted by docker-compose.yml is readable.
    if "folders" not in raw:
        if Path(DEFAULT_DOCKER_MOUNT).is_dir():
            # Writable only if mounted read-write; writes still need the gate window.
            access = "write" if os.access(DEFAULT_DOCKER_MOUNT, os.W_OK) else "read"
            s.folders.append(Folder("docker", DEFAULT_DOCKER_MOUNT, access))
        for name, path in OPTIONAL_MOUNTS.items():
            if Path(path).is_dir():
                s.folders.append(Folder(name, path, "read"))
    return s
