"""MCP server: read-only NAS tools over streamable HTTP, plus a small status page."""

from __future__ import annotations

import hmac
import html
import json
import logging
import os
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from . import files as filesmod
from .config import Settings
from .core import NAS
from .docker import DockerError

log = logging.getLogger("nasmcp.server")
VERSION = os.environ.get("NASMCP_VERSION", "dev")

INSTRUCTIONS = """\
Tools for a Synology NAS: system health, disks and volumes, Docker containers
(state, logs, diagnosis), Watchtower update history, backups, the NAS gate's
security scan, and read access to the folders the owner allowed.
Start with nas_overview for "how is the NAS?", and container_diagnose when a
container misbehaves. Everything in this version is read-only.
Answer the owner in plain language; he is not a network or Docker expert.
"""

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                     openWorldHint=False)


def _safe(fn):
    """Turn expected failures into a readable tool error instead of a crash."""
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except (DockerError, filesmod.AccessDenied, ValueError) as e:
            raise ToolError(str(e)) from e
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__annotations__ = fn.__annotations__
    wrapper.__wrapped__ = fn
    return wrapper


def build_mcp(nas: NAS) -> MCPServer:
    m = MCPServer("nas-mcp", title="Synology NAS", version=VERSION, instructions=INSTRUCTIONS)
    s = nas.s

    @m.tool(annotations=RO)
    @_safe
    def nas_overview() -> dict:
        """Whole-NAS health in one call: system, disks and volume problems, containers
        with problems, backups, and the gate's security score."""
        return nas.overview()

    @m.tool(annotations=RO)
    @_safe
    def nas_system() -> dict:
        """Model, DSM version, uptime, temperature, CPU and memory use."""
        return nas.system()

    @m.tool(annotations=RO)
    @_safe
    def nas_storage() -> dict:
        """Disks (SMART, temperature, bad sectors), storage pools (RAID) and volumes
        (used space), with findings."""
        return nas.storage()

    @m.tool(annotations=RO)
    @_safe
    def containers_list() -> list[dict]:
        """All Docker containers with state, image, Compose project and published ports."""
        return nas.containers()

    @m.tool(annotations=RO)
    @_safe
    def container_details(name: str) -> dict:
        """One container: state, exit code and its meaning, restart policy and count,
        mounts, ports, command, image date and its last Watchtower update."""
        return nas.container(name)

    @m.tool(annotations=RO)
    @_safe
    def container_logs(name: str, tail: int = 200, errors_only: bool = False) -> str:
        """The container's own log (newest `tail` lines). Secrets are redacted."""
        return nas.logs(name, tail, errors_only)

    @m.tool(annotations=RO)
    @_safe
    def container_diagnose(name: str = "") -> dict:
        """Find problems and suggest fixes: crash loops, stops with no visible cause
        (matched against Watchtower), errors repeating in the log, permission and port
        errors, breakage after an update, missing auto-restart, standalone containers,
        services without a password, unmaintained images. Empty name = all containers."""
        return nas.diagnose(name or None)

    @m.tool(annotations=RO)
    @_safe
    def watchtower_history() -> dict:
        """What Watchtower updated, stopped and failed on, with times (read from its log)."""
        return nas.watchtower()

    @m.tool(annotations=RO)
    @_safe
    def nas_timeline(hours: int = 72, name: str = "") -> dict:
        """Everything that happened to containers and images in the last `hours`:
        starts, stops, crashes, out-of-memory kills, pulls and Watchtower updates,
        oldest first. Filter by container name if given."""
        return nas.timeline(hours, name or None)

    @m.tool(annotations=RO)
    @_safe
    def backups_status() -> list[dict]:
        """Newest file of each configured backup target and whether it is late."""
        return nas.backups()

    @m.tool(annotations=RO)
    @_safe
    def security_scan() -> dict:
        """The NAS gate's last security scan: score and findings with advice."""
        return nas.security_scan()

    @m.tool(annotations=RO)
    @_safe
    def gate_status() -> dict:
        """NAS gate state: which protections are open and for how long."""
        return nas.gate_status()

    @m.tool(annotations=RO)
    @_safe
    def folders_list() -> list[dict]:
        """Folders this server may read, with their access level."""
        return filesmod.list_folders(s)

    @m.tool(annotations=RO)
    @_safe
    def files_list(folder: str, path: str = "") -> dict:
        """List a directory inside an allowed folder."""
        return filesmod.list_dir(s, folder, path)

    @m.tool(annotations=RO)
    @_safe
    def file_read(folder: str, path: str) -> dict:
        """Read a text file (for example a compose.yaml) inside an allowed folder.
        Values of passwords, tokens and keys are redacted."""
        return filesmod.read_file(s, folder, path)

    @m.tool(annotations=RO)
    @_safe
    def files_search(folder: str, pattern: str, path: str = "") -> dict:
        """Find files by name pattern (for example '*.yaml') inside an allowed folder."""
        return filesmod.search(s, folder, pattern, path)

    return m


# -- HTTP app -------------------------------------------------------------------------

def _authorized(settings: Settings, request: Request) -> bool:
    if not settings.token:
        return False
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return hmac.compare_digest(auth[7:].strip(), settings.token)
    return False


class BearerGuard:
    """Every path except /health needs `Authorization: Bearer <token>`.

    The status page also accepts ?token=... once and remembers it in a cookie,
    so it can be opened from a phone browser.
    """

    def __init__(self, app, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health":
            return await self.app(scope, receive, send)
        request = Request(scope)
        ok = _authorized(self.settings, request)
        if not ok and scope["path"] == "/" and self.settings.token:
            supplied = request.query_params.get("token") or request.cookies.get("nasmcp", "")
            ok = bool(supplied) and hmac.compare_digest(supplied, self.settings.token)
        if not ok:
            msg = "token not configured" if not self.settings.token else "unauthorized"
            resp = JSONResponse({"error": msg}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
            return await resp(scope, receive, send)
        return await self.app(scope, receive, send)


def build_app(nas: NAS, recorder=None):
    m = build_mcp(nas)

    @m.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> Response:
        return JSONResponse({"ok": True, "version": VERSION})

    @m.custom_route("/", methods=["GET"])
    async def status_page(request: Request) -> Response:
        import anyio
        data = await anyio.to_thread.run_sync(lambda: _page_data(nas, recorder))
        resp = HTMLResponse(_render(data, nas.s.language))
        tok = request.query_params.get("token")
        if tok:
            resp.set_cookie("nasmcp", tok, httponly=True, samesite="strict", max_age=30 * 86400)
        return resp

    app = m.streamable_http_app(
        host="0.0.0.0",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    return BearerGuard(app, nas.s), m


def _page_data(nas: NAS, recorder) -> dict[str, Any]:
    data: dict[str, Any] = {"version": VERSION}
    data["system"] = nas.system()
    st = nas.storage()
    data["storage"] = st.get("findings", []) + [{"severity": "info", "title": e}
                                                for e in st.get("errors", [])]
    data["volumes"] = st.get("volumes", [])
    try:
        d = nas.diagnose()
        data["problems"] = d["problems"]
        data["healthy"] = d["healthy"]
    except DockerError as e:
        data["problems"] = [{"severity": "high", "container": "docker", "title": str(e)}]
        data["healthy"] = []
    data["backups"] = nas.backups()
    data["events"] = {"recording": bool(recorder and recorder.connected),
                      "error": getattr(recorder, "last_error", "")}
    return data


T = {
    "en": {"title": "NAS MCP", "system": "System", "storage": "Disks and volumes",
           "problems": "Container problems", "healthy": "Healthy containers",
           "backups": "Backups", "none": "No problems found", "events": "Event recorder",
           "on": "recording", "off": "not connected", "ro": "Read-only (stage 1a)"},
    "he": {"title": "MCP של ה-NAS", "system": "מערכת", "storage": "דיסקים ווולומים",
           "problems": "בעיות במכולות", "healthy": "מכולות תקינות",
           "backups": "גיבויים", "none": "לא נמצאו בעיות", "events": "מקליט האירועים",
           "on": "מקליט", "off": "לא מחובר", "ro": "קריאה בלבד (שלב 1א)"},
}


def _render(d: dict[str, Any], lang: str) -> str:
    t = T.get(lang, T["en"])
    e = html.escape
    rtl = lang == "he"
    sysd = d["system"]
    sys_line = " · ".join(str(x) for x in (
        sysd.get("model"), sysd.get("dsm_version"),
        f"{sysd['temperature_c']}°C" if sysd.get("temperature_c") is not None else None,
        f"CPU {sysd['cpu_percent']:.0f}%" if sysd.get("cpu_percent") is not None else None,
        f"RAM {sysd['memory_used_percent']}%" if sysd.get("memory_used_percent") is not None else None,
    ) if x)
    errs = "".join(f"<li class=info>{e(x)}</li>" for x in sysd.get("errors", []))

    def items(rows, fmt):
        return "".join(fmt(r) for r in rows) or f"<li class=ok>{t['none']}</li>"

    vols = "".join(f"<li>{e(str(v.get('path')))}: {v.get('used_percent')}% "
                   f"({v.get('used_gb')} / {v.get('total_gb')} GB)</li>" for v in d["volumes"])
    storage = items(d["storage"], lambda r: f"<li class={e(r['severity'])}>{e(r['title'])}</li>")
    probs = items(d["problems"], lambda r: (
        f"<li class={e(r['severity'])}><b>{e(r['container'])}</b>: {e(r['title'])}"
        f"{'<br><small>' + e(r.get('detail') or '') + '</small>' if r.get('detail') else ''}</li>"))
    backups = items(d["backups"], lambda b: (
        f"<li class={'ok' if b.get('status') == 'ok' else 'high'}>{e(b['name'])}: "
        f"{e(b.get('time') or b.get('detail', ''))}</li>"))
    rec = t["on"] if d["events"]["recording"] else f"{t['off']} {e(d['events']['error'] or '')}"
    return f"""<!doctype html><html lang="{lang}" dir="{'rtl' if rtl else 'ltr'}"><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{t['title']}</title><style>
body{{font-family:system-ui,sans-serif;margin:16px;font-size:18px;line-height:1.5;background:#111;color:#eee}}
h1{{font-size:24px}}h2{{font-size:20px;margin-top:24px}}ul{{padding-inline-start:18px}}
li{{margin:6px 0}}.high{{color:#ff8080}}.medium{{color:#ffc266}}.low,.info{{color:#aaa}}.ok{{color:#7ddf7d}}
small{{color:#bbb}}footer{{margin-top:30px;color:#888;font-size:14px}}</style></head><body>
<h1>{t['title']}</h1><p>{e(sys_line)}</p><ul>{errs}</ul>
<h2>{t['storage']}</h2><ul>{vols}{storage}</ul>
<h2>{t['problems']}</h2><ul>{probs}</ul>
<h2>{t['healthy']}</h2><p>{e(', '.join(d['healthy'])) or '-'}</p>
<h2>{t['backups']}</h2><ul>{backups}</ul>
<footer>{t['events']}: {rec} · {t['ro']} · v{e(d['version'])}</footer>
</body></html>"""


def dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
