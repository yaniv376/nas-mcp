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
from . import maintenance as mtmod
from .config import Settings
from .core import NAS, Changes
from . import writes as writesmod
from .docker import DockerError
from .dsm import DSMError

log = logging.getLogger("nasmcp.server")
VERSION = os.environ.get("NASMCP_VERSION", "dev")

INSTRUCTIONS = """\
Tools for a Synology NAS: system health, disks and volumes, Docker containers
(state, logs, diagnosis), Watchtower update history, backups, the NAS gate's
security scan, and access to the folders the owner allowed in the NAS gate
(closed, read, or read and write).
Start with nas_overview for "how is the NAS?", and container_diagnose when a
container misbehaves. Reading is always allowed. Changes (containers, Compose
files, files, storage maintenance) work only while the owner has the agent
window open in the NAS gate; if it is closed, tell him to open it. Nothing is
ever deleted: leftovers are renamed or moved to _to_delete.
Answer the owner in plain language; he is not a network or Docker expert.
"""

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                     openWorldHint=False)
CHANGE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                         openWorldHint=False)
DISRUPTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False,
                             openWorldHint=False)


def _safe(fn):
    """Turn expected failures into a readable tool error instead of a crash."""
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except (DockerError, filesmod.AccessDenied, ValueError, writesmod.WriteDenied,
                DSMError) as e:
            raise ToolError(str(e)) from e
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__annotations__ = fn.__annotations__
    wrapper.__wrapped__ = fn
    return wrapper


def build_mcp(nas: NAS, provider=None) -> MCPServer:
    kw: dict[str, Any] = {}
    if provider is not None:
        from mcp.server.auth.settings import (AuthSettings, ClientRegistrationOptions,
                                              RevocationOptions)
        from .oauth import SCOPE
        public = nas.s.public_url.rstrip("/")
        kw = dict(auth_server_provider=provider, auth=AuthSettings(
            issuer_url=public, resource_server_url=f"{public}/mcp",
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=[SCOPE], validate_token_resource=False))
    m = MCPServer("nas-mcp", title="Synology NAS", version=VERSION, instructions=INSTRUCTIONS, **kw)
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
        """Folders this server may use: access 'read' or 'write' (write also needs
        the agent window). The owner sets them per shared folder in the NAS gate."""
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

    ch = Changes(nas)

    @m.tool(annotations=RO)
    @_safe
    def nas_health_scan() -> dict:
        """Health score of the NAS (disks, space, data scrubbing, disk protection, DSM
        updates, backups, containers, broken updates) with findings and advice.
        The NAS gate's security_scan covers security separately."""
        return nas.health_scan()

    @m.tool(annotations=RO)
    @_safe
    def updates_recent() -> list[dict]:
        """Container updates seen by the post-update guard: which image changed, whether
        the 5-minute check passed, problems found, and rollbacks."""
        return nas.watcher.recent() if nas.watcher else []

    @m.tool(annotations=CHANGE)
    @_safe
    def update_rollback(name: str) -> dict:
        """Roll a container back to the image it ran before its last update: recreate
        it with the same settings and the previous image, keep Watchtower away from it,
        and pin the image in its Compose file if it has one. The broken container is
        renamed to_delete_<name>_broken_<time>."""
        return ch.rollback(name)

    @m.tool(annotations=RO)
    @_safe
    def projects_list() -> list[dict]:
        """Container Manager projects (Compose) with their folder and status."""
        return ch.projects()

    @m.tool(annotations=RO)
    @_safe
    def actions_log(limit: int = 30) -> list[dict]:
        """Changes this server made, newest last."""
        return nas.audit.recent(max(1, min(limit, 200)))

    @m.tool(annotations=CHANGE)
    @_safe
    def container_control(name: str, action: str) -> dict:
        """Start, stop or restart a container (action: start | stop | restart).
        Needs the gate's agent window open."""
        return ch.container(name, action)

    @m.tool(annotations=CHANGE)
    @_safe
    def container_set_auto_restart(name: str, policy: str = "unless-stopped") -> dict:
        """Set a container's restart policy (unless-stopped | always | on-failure | no),
        so it comes back by itself after a crash, update or reboot."""
        return ch.restart_policy(name, policy)

    @m.tool(annotations=DISRUPTIVE)
    @_safe
    def container_retire(name: str) -> dict:
        """Retire a container: stop it, turn off auto-restart and rename it
        to_delete_<name> for the owner to delete later. Asks for approval on the
        owner's phone and waits up to 2 minutes."""
        return ch.retire(name)

    @m.tool(annotations=CHANGE)
    @_safe
    def compose_write(project: str, content: str) -> dict:
        """Replace a project's Compose file (project = its folder under docker, for
        example 'rclone'). The YAML is checked first (indentation, services, image)
        and the old file is backed up. Run project_run(project, 'build') afterwards
        to apply it."""
        return ch.compose_write(project, content)

    @m.tool(annotations=CHANGE)
    @_safe
    def file_write(folder: str, path: str, content: str, overwrite: bool = False) -> dict:
        """Write a text file in a folder the owner set to read and write (see
        folders_list). An existing file is replaced only with overwrite=true, and
        its current copy is kept in .nas-mcp-history. Needs the agent window."""
        return ch.file_write(folder, path, content, overwrite)

    @m.tool(annotations=CHANGE)
    @_safe
    def file_move(folder: str, src: str, dest: str, dest_folder: str = "") -> dict:
        """Move or rename a file or folder (dest_folder: another read-and-write
        folder, default the same one). Never overwrites. Needs the agent window."""
        return ch.file_move(folder, src, dest, dest_folder)

    @m.tool(annotations=CHANGE)
    @_safe
    def file_retire(folder: str, path: str) -> dict:
        """Instead of deleting: move a file or folder into the folder's _to_delete
        subfolder, for the owner to delete later. Needs the agent window."""
        return ch.file_retire(folder, path)

    @m.tool(annotations=RO)
    @_safe
    def disk_smart_status(disk: str = "") -> list[dict]:
        """S.M.A.R.T. self-test state per disk: running or not, time left, last
        result and how long a quick or extended test takes. disk: 'Drive 2',
        'sata4', or empty for all."""
        with nas._dsm_factory() as dsm:
            return mtmod.smart_status(dsm, disk)

    @m.tool(annotations=CHANGE)
    @_safe
    def disk_smart_test(disk: str, test: str = "quick") -> dict:
        """Start a S.M.A.R.T. self-test on a disk: test = quick (about 2 minutes),
        extended (hours; reads the whole surface) or stop. The disk keeps working.
        Needs the agent window; no phone approval."""
        return ch.smart_test(disk, test)

    @m.tool(annotations=RO)
    @_safe
    def scrubbing_status() -> list[dict]:
        """Data scrubbing state per storage pool (ready, manual_running,
        schedule_running, paused, schedule_paused...)."""
        with nas._dsm_factory() as dsm:
            return mtmod.scrubbing_status(dsm)

    @m.tool(annotations=CHANGE)
    @_safe
    def scrubbing_start(pool: str) -> dict:
        """Start data scrubbing now on a storage pool ('reuse_2' or its volume,
        'volume1'). Checks the disks for silent errors; takes hours.
        Needs the agent window; no phone approval."""
        return ch.scrubbing_start(pool)

    @m.tool(annotations=CHANGE)
    @_safe
    def scrubbing_schedule_resume() -> dict:
        """Resume DSM's paused data scrubbing schedule (one schedule for all
        pools). Needs the agent window; no phone approval."""
        return ch.scrubbing_schedule_resume()

    @m.tool(annotations=RO)
    @_safe
    def compose_backups(project: str) -> list[str]:
        """Earlier versions of a project's Compose file, newest first."""
        return ch.compose_backups(project)

    @m.tool(annotations=CHANGE)
    @_safe
    def compose_restore(project: str, backup: str) -> dict:
        """Put back an earlier Compose file from compose_backups (the current one is
        backed up too). Run project_run(project, 'build') afterwards."""
        return ch.compose_restore(project, backup)

    @m.tool(annotations=CHANGE)
    @_safe
    def project_run(project: str, action: str) -> dict:
        """Run a Container Manager project action: stop | build | start | restart.
        'build' stops the project first, then rebuilds it from its Compose file
        (a plain restart does not apply Compose changes). Project = its name in
        Container Manager."""
        return ch.project(project, action)

    @m.tool(annotations=RO)
    @_safe
    def files_grep(folder: str, pattern: str, path: str = "", glob: str = "*",
                   max_hits: int = 40) -> dict:
        """Regex search inside the files of an allowed folder (for example a log or
        config, or DSM's own UI code to learn API parameters). Returns snippets."""
        return filesmod.grep(s, folder, pattern, path, glob, max_hits=max(1, min(max_hits, 200)))

    return m


# -- HTTP app -------------------------------------------------------------------------

def _authorized(settings: Settings, request: Request, health_only: bool = False) -> bool:
    if not settings.token:
        return False
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        got = auth[7:].strip()
        if hmac.compare_digest(got, settings.token):
            return True
        return health_only and hmac.compare_digest(got, settings.health_token)
    return False


class BearerGuard:
    """Without OAuth every path except /health needs `Authorization: Bearer <token>`.
    With OAuth the SDK protects /mcp and only the status page is guarded here.

    The status page also accepts ?token=... once and remembers it in a cookie,
    so it can be opened from a phone browser.
    """

    def __init__(self, app, settings: Settings, oauth: bool = False):
        self.app = app
        self.settings = settings
        self.oauth = oauth

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health" \
                or scope["path"].startswith(("/approve/", "/update/")):
            return await self.app(scope, receive, send)
        if self.oauth and scope["path"] != "/":
            return await self.app(scope, receive, send)
        request = Request(scope)
        ok = _authorized(self.settings, request, health_only=scope["path"] == "/api/health")
        if not ok and scope["path"] == "/" and self.settings.token:
            supplied = request.query_params.get("token") or request.cookies.get("nasmcp", "")
            ok = bool(supplied) and hmac.compare_digest(supplied, self.settings.token)
        if not ok:
            msg = "token not configured" if not self.settings.token else "unauthorized"
            resp = JSONResponse({"error": msg}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
            return await resp(scope, receive, send)
        return await self.app(scope, receive, send)


def build_app(nas: NAS, recorder=None, provider=None):
    m = build_mcp(nas, provider)
    if provider is not None:
        _oauth_routes(m, provider, nas.s.language)

    @m.custom_route("/approve/{aid}/{secret}/{action}", methods=["GET"])
    async def approve(request: Request) -> Response:
        p = request.path_params
        result = nas.approvals.decide(p["aid"], p["secret"], p["action"])
        t = OT.get(nas.s.language, OT["en"])
        title = {"approved": t["approved"].split(".")[0], "denied": t["denied"]}.get(result, t["expired"])
        return _page(nas.s.language, title, "")

    @m.custom_route("/update/{uid}/{secret}/{action}", methods=["GET"])
    async def update_decide(request: Request) -> Response:
        import anyio
        p = request.path_params
        if not nas.watcher:
            return _page(nas.s.language, "—", "")
        try:
            result = await anyio.to_thread.run_sync(
                lambda: nas.watcher.decide(p["uid"], p["secret"], p["action"]))
        except Exception as e:  # noqa: BLE001
            result = f"failed: {e}"
        he = nas.s.language == "he"
        titles = {"rolled back": "הוחזר לגרסה הקודמת" if he else "Rolled back",
                  "ignored": "סומן כתקין" if he else "Marked as fine",
                  "expired": "הקישור פג" if he else "Link expired"}
        return _page(nas.s.language, titles.get(result, str(result)), "")

    @m.custom_route("/api/health", methods=["GET"])
    async def api_health(request: Request) -> Response:
        """For Home Assistant: last health scan (bearer token); ?refresh=1 rescans."""
        import anyio
        if not _authorized(nas.s, request, health_only=True):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if request.query_params.get("refresh") or not nas.last_health:
            await anyio.to_thread.run_sync(nas.health_scan)
        h = nas.last_health or {}
        return JSONResponse({"score": h.get("score"), "counts": h.get("counts"),
                             "findings": h.get("findings", [])[:20],
                             "finished_at": h.get("finished_at")})

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
    return BearerGuard(app, nas.s, oauth=provider is not None), m


# -- phone approval pages -------------------------------------------------------------

OT = {
    "en": {"wait_t": "Approve on your phone", "wait": "A notification was sent to your phone. "
           "Tap Approve there if the code matches.", "code": "Code", "expired": "This request expired. "
           "Start the connection again from Claude.", "denied": "Access denied.",
           "approved": "Approved. You can return to Claude.", "notify_fail": "The notification could not be sent:"},
    "he": {"wait_t": "אשר בטלפון", "wait": "נשלחה התראה לטלפון שלך. לחץ שם על 'אשר' אם הקוד זהה.",
           "code": "קוד", "expired": "הבקשה פגה. התחל את החיבור מחדש מ-Claude.",
           "denied": "הגישה נדחתה.", "approved": "אושר. אפשר לחזור ל-Claude.",
           "notify_fail": "לא הצלחתי לשלוח את ההתראה:"},
}


def _page(lang: str, title: str, body: str, script: str = "") -> HTMLResponse:
    rtl = "rtl" if lang == "he" else "ltr"
    return HTMLResponse(
        f"<!doctype html><html dir={rtl}><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>body{{font-family:system-ui,sans-serif;"
        f"background:#111;color:#eee;margin:24px;font-size:20px;line-height:1.5}}"
        f".code{{font-size:48px;letter-spacing:8px;font-weight:700;margin:16px 0}}</style></head>"
        f"<body><h1>{html.escape(title)}</h1>{body}{script}</body></html>",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


def _oauth_routes(m: MCPServer, provider, lang: str) -> None:
    t = OT.get(lang, OT["en"])

    @m.custom_route("/oauth/wait", methods=["GET"])
    async def wait(request: Request) -> Response:
        req = request.query_params.get("req", "")
        st = provider.status(req) if req else {"state": "expired"}
        if st["state"] != "waiting":
            return _page(lang, t["expired"], "")
        fail = (f"<p style='color:#ff8080'>{t['notify_fail']} {html.escape(st['notify_error'])}</p>"
                if st.get("notify_error") else "")
        script = ("<script>const q=new URLSearchParams(location.search).get('req');"
                  "async function poll(){try{const r=await fetch('/oauth/status?req='+encodeURIComponent(q));"
                  "const s=await r.json();if(s.redirect){location.replace(s.redirect);return}"
                  "if(s.state==='expired'){location.reload();return}}catch(e){}setTimeout(poll,2000)}"
                  "setTimeout(poll,2000)</script>")
        return _page(lang, t["wait_t"], f"<p>{t['wait']}</p><p>{t['code']}:</p>"
                     f"<div class=code>{st['match']}</div>{fail}", script)

    @m.custom_route("/oauth/status", methods=["GET"])
    async def status(request: Request) -> Response:
        return JSONResponse(provider.status(request.query_params.get("req", "")),
                            headers={"Cache-Control": "no-store"})

    @m.custom_route("/oauth/decide/{req}/{secret}/{action}", methods=["GET"])
    async def decide(request: Request) -> Response:
        p = request.path_params
        result = provider.decide(p["req"], p["secret"], p["action"])
        return _page(lang, t.get(result, t["expired"]), "")


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
