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

    # MCP endpoint protection (stage 1a: static bearer token, LAN only)
    token: str = ""

    folders: list[Folder] = field(default_factory=list)
    backups: list[BackupTarget] = field(default_factory=list)

    # limits
    max_file_bytes: int = 512_000
    max_log_lines: int = 2000

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
    return s
