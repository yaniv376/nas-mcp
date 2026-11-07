import threading
import time
from pathlib import Path

import httpx
import pytest

from nasmcp import writes as w
from nasmcp.core import Changes
from nasmcp.docker import DockerClient

from . import fakes
from .test_core import nas  # noqa: F401


class Gate:
    def __init__(self, agent=None, fail=False):
        self.agent, self.fail = agent, fail
        self.configured = True

    def status(self):
        if self.fail:
            from nasmcp.gate import GateError
            raise GateError("down")
        prot = {"ssh": {"managed": True, "is_open": False}}
        if self.agent is not None:
            prot["agent"] = self.agent
        return {"protections": prot}


OPEN = {"managed": True, "is_open": True, "remaining_seconds": 1800}


def test_window_rules():
    with pytest.raises(w.WriteDenied, match="update the gate"):
        w.require_window(Gate())
    with pytest.raises(w.WriteDenied, match="turned off"):
        w.require_window(Gate({"managed": False, "is_open": False}))
    with pytest.raises(w.WriteDenied, match="closed"):
        w.require_window(Gate({"managed": True, "is_open": False}))
    with pytest.raises(w.WriteDenied, match="Cannot ask"):
        w.require_window(Gate(fail=True))
    assert w.require_window(Gate(OPEN))["remaining_minutes"] == 30


@pytest.mark.parametrize("text,msg", [
    ("services:\n\tweb:\n", "tabs"),
    ("services:\n  web:\n    image: x\n   ports:\n", "line"),
    ("version: '3'\n", "services"),
    ("services:\n  web:\n    ports: ['80:80']\n", "neither"),
    ("services:\n  web:\n    image: x\n    volumes: /a:/b\n", "must be a list"),
])
def test_validate_compose_rejects(text, msg):
    with pytest.raises(ValueError, match=msg):
        w.validate_compose(text)


def test_write_backup_restore(tmp_path):
    d = tmp_path / "rclone"
    d.mkdir()
    (d / "compose.yaml").write_text("services:\n  a:\n    image: x:1\n")
    r = w.write_compose(d, "services:\n  a:\n    image: x:2\n")
    assert r["file"] == "compose.yaml" and r["backup"].startswith(w.HISTORY_DIR)
    assert "x:2" in (d / "compose.yaml").read_text()
    backups = w.list_backups(d)
    assert len(backups) == 1
    time.sleep(1.1)
    w.restore_compose(d, backups[0])
    assert "x:1" in (d / "compose.yaml").read_text()
    assert len(w.list_backups(d)) == 2           # restoring backs up the current one too
    with pytest.raises(ValueError):
        w.restore_compose(d, "../../etc/passwd")
    with pytest.raises(ValueError):
        w.write_compose(d, "services:\n\tbad")
    assert "x:1" in (d / "compose.yaml").read_text()   # bad YAML never written


def _writer_nas(nas, tmp_path, agent=OPEN, approve=None):  # noqa: F811
    posts = []

    def handler(req: httpx.Request):
        if req.method == "POST":
            posts.append((req.url.path, dict(req.url.params), req.content))
            return httpx.Response(204)
        return fakes.handler(req)

    nas.docker = DockerClient("http://proxy", transport=httpx.MockTransport(handler))
    nas.gate = Gate(agent)
    docker_dir = Path(nas.s.folders[0].path)
    nas.s.folders[0].access = "write"
    sent = []

    def send(a, ok, no):
        sent.append(a)
        if approve is not None:
            threading.Timer(0.2, lambda: nas.approvals.decide(a.id, a.secret, approve)).start()
    nas.approvals = w.Approvals("https://nas.example", send)
    return Changes(nas), posts, sent, docker_dir


def test_container_actions(nas, tmp_path):  # noqa: F811
    ch, posts, _, _ = _writer_nas(nas, tmp_path)
    r = ch.container("qbittorrent", "start")
    assert r["done"] and posts[-1][0].endswith("/start")
    ch.restart_policy("qbittorrent", "unless-stopped")
    assert b"unless-stopped" in posts[-1][2]
    assert nas.audit.recent()[-1]["action"] == "restart_policy"


def test_closed_window_blocks_and_nothing_posted(nas, tmp_path):  # noqa: F811
    ch, posts, _, _ = _writer_nas(nas, tmp_path, agent={"managed": True, "is_open": False})
    with pytest.raises(w.WriteDenied):
        ch.container("qbittorrent", "start")
    assert posts == []


def test_protected_containers(nas, tmp_path):  # noqa: F811
    ch, posts, _, _ = _writer_nas(nas, tmp_path)
    fakes_names = [c["Names"][0] for c in fakes.CONTAINERS]
    assert "/nas-gate" not in fakes_names  # sanity: guard is by name, not lookup
    with pytest.raises(w.WriteDenied):
        w.container_action(nas.docker, "x", "nas-gate", "stop")
    with pytest.raises(w.WriteDenied):
        w.retire_container(nas.docker, "x", "nas-mcp")
    assert posts == []


def test_retire_needs_phone(nas, tmp_path):  # noqa: F811
    ch, posts, sent, _ = _writer_nas(nas, tmp_path, approve="approve")
    r = ch.retire("filebrowser")
    assert r["renamed_to"] == "to_delete_filebrowser-1"
    assert [p[0].rsplit("/", 1)[1] for p in posts] == ["stop", "update", "rename"]
    assert sent and "filebrowser-1" in sent[0].what


def test_retire_denied(nas, tmp_path):  # noqa: F811
    ch, posts, _, _ = _writer_nas(nas, tmp_path, approve="deny")
    with pytest.raises(w.WriteDenied, match="Denied"):
        ch.retire("filebrowser")
    assert posts == []


def test_compose_write_through_changes(nas, tmp_path):  # noqa: F811
    ch, _, _, docker_dir = _writer_nas(nas, tmp_path)
    r = ch.compose_write("seerr", "services:\n  seerr:\n    image: ghcr.io/seerr-team/seerr:3.5.1\n")
    assert r["backup"]
    assert ch.compose_backups("seerr")
    with pytest.raises(w.WriteDenied):
        ch.compose_write("../escape", "services:\n  a:\n    image: x\n")


def test_compose_write_needs_rw_mount(nas, tmp_path):  # noqa: F811
    ch, _, _, _ = _writer_nas(nas, tmp_path)
    nas.s.folders[0].access = "read"
    with pytest.raises(w.WriteDenied, match=":rw"):
        ch.compose_write("seerr", "services:\n  a:\n    image: x\n")


def test_list_projects_shapes():
    class D:
        def __init__(self, data):
            self.data = data

        def request(self, *a, **k):
            return self.data
    as_dict = D({"abc": {"name": "seerr", "path": "/volume1/docker/seerr", "status": "RUNNING"}})
    assert w.list_projects(as_dict)[0] == {"id": "abc", "name": "seerr", "path": "/volume1/docker/seerr",
                                           "status": "RUNNING", "containers": None}
    as_list = D([{"id": "x", "name": "rclone"}])
    assert w.find_project(as_list, "rclone")["id"] == "x"
    with pytest.raises(ValueError, match="Projects: rclone"):
        w.find_project(as_list, "nope")


def test_approval_page_route(nas, tmp_path):  # noqa: F811
    from .test_server import _free_port  # reuse helper
    import uvicorn
    from nasmcp.server import build_app
    ch, _, sent, _ = _writer_nas(nas, tmp_path)
    app, _ = build_app(nas)
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    while not srv.started:
        time.sleep(0.05)
    result = {}

    def tap():
        while not sent:
            time.sleep(0.05)
        a = sent[0]
        httpx.get(f"http://127.0.0.1:{port}/approve/{a.id}/{a.secret}/approve")
    threading.Thread(target=tap, daemon=True).start()
    result["ok"] = nas.approvals.ask("test", wait_seconds=10, poll=0.1)
    srv.should_exit = True
    th.join(5)
    assert result["ok"] is True
