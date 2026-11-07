import copy
import json
from pathlib import Path

import httpx
import pytest

from nasmcp import updates as up
from nasmcp.diagnose import diagnose
from nasmcp.docker import DockerClient

from . import fakes
from .test_core import nas  # noqa: F401


class World:
    """Mutable fake Docker: containers with ImageID, logs, and recorded POSTs."""

    def __init__(self):
        self.containers = [
            {"Id": "a" * 64, "Names": ["/seerr"], "Image": "ghcr.io/seerr-team/seerr:latest",
             "ImageID": "sha256:old", "State": "running", "Labels": {}},
            {"Id": "b" * 64, "Names": ["/sonarr"], "Image": "linuxserver/sonarr:latest",
             "ImageID": "sha256:s1", "State": "running", "Labels": {}},
        ]
        self.inspect = {
            "seerr": {"Name": "/seerr", "Image": "sha256:new", "RestartCount": 0,
                      "State": {"Status": "running", "StartedAt": fakes.iso(fakes.NOW - 400),
                                "FinishedAt": "0001-01-01T00:00:00Z"},
                      "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"},
                                     "NetworkMode": "seerr_default", "Binds": ["/v:/app/config"]},
                      "Config": {"Image": "ghcr.io/seerr-team/seerr:latest", "Cmd": [], "Env": ["A=1"],
                                 "Labels": {"com.docker.compose.project": "seerr",
                                            "com.docker.compose.service": "seerr",
                                            "com.docker.compose.project.working_dir": "/volume1/docker/seerr"}},
                      "NetworkSettings": {"Networks": {"seerr_default": {"Aliases": ["seerr", "abcdef123456"]}}},
                      "Mounts": []},
        }
        self.logs = {"seerr": ""}
        self.posts = []
        self.created = None

    def handler(self, req: httpx.Request):
        path = req.url.path
        if req.method == "POST":
            self.posts.append(path.rsplit("/", 1)[-1] if "/containers/" in path else path)
            if path == "/containers/create":
                self.created = json.loads(req.content)
                return httpx.Response(201, json={"Id": "c" * 64})
            return httpx.Response(204)
        if path == "/containers/json":
            return httpx.Response(200, json=self.containers)
        if path.startswith("/containers/"):
            ident, _, what = path[len("/containers/"):].partition("/")
            name = {"a" * 64: "seerr", "b" * 64: "sonarr"}.get(ident, ident)
            if what == "json":
                return httpx.Response(200, json=self.inspect[name])
            if what == "logs":
                return httpx.Response(200, content=fakes.mux(self.logs.get(name, "")))
        if path.startswith("/images/"):
            return httpx.Response(200, json={"RepoDigests": ["ghcr.io/seerr-team/seerr@sha256:deadbeef"]})
        return httpx.Response(404)


@pytest.fixture
def world(tmp_path):
    w = World()
    docker = DockerClient("http://proxy", transport=httpx.MockTransport(w.handler))
    root = tmp_path / "docker"
    (root / "seerr").mkdir(parents=True)
    (root / "seerr" / "compose.yaml").write_text(
        "services:\n  seerr:\n    image: ghcr.io/seerr-team/seerr:latest\n    restart: unless-stopped\n")
    alerts = []
    watcher = up.UpdateWatcher(docker, tmp_path, notify=lambda u, p: alerts.append((u, p)),
                               docker_root=root, check_after=300)
    return w, watcher, alerts, root


def test_first_scan_records_without_alerts(world):
    w, watcher, alerts, _ = world
    assert watcher.scan(now=1000) == []
    assert watcher.seen["seerr"]["image_id"] == "sha256:old"


def test_update_detected_checked_ok(world):
    w, watcher, alerts, _ = world
    watcher.scan(now=1000)
    w.containers[0]["ImageID"] = "sha256:new"
    found = watcher.scan(now=1100)
    assert [u.name for u in found] == ["seerr"]
    assert watcher.check_due(now=1200) == []          # not yet 5 minutes
    done = watcher.check_due(now=1500)
    assert done[0].healthy is True and alerts == []
    assert watcher.recent()[-1]["status"] == "ok"


def test_broken_update_alerts_and_rolls_back(world):
    w, watcher, alerts, root = world
    watcher.scan(now=1000)
    w.containers[0]["ImageID"] = "sha256:new"
    w.inspect["seerr"]["State"]["Status"] = "restarting"
    w.inspect["seerr"]["RestartCount"] = 30
    w.logs["seerr"] = "".join(f"{fakes.iso(fakes.NOW - i)} Error: unknown flag --x\n" for i in range(12))
    watcher.scan(now=1100)
    u = watcher.check_due(now=1500)[0]
    assert u.healthy is False and alerts
    u_alert, paths = alerts[0]
    assert paths["rollback"].startswith(f"/update/{u.id}/")

    assert watcher.decide(u.id, "wrong", "rollback") == "expired"
    assert w.posts == []
    assert watcher.decide(u.id, u.secret, "rollback") == "rolled back"
    assert w.posts == ["stop", "update", "rename", "create", "start"]
    assert w.created["Image"] == "sha256:old"
    assert w.created["Labels"]["com.centurylinklabs.watchtower.enable"] == "false"
    assert w.created["NetworkingConfig"]["EndpointsConfig"]["seerr_default"]["Aliases"] == ["seerr"]
    compose = (root / "seerr" / "compose.yaml").read_text()
    assert "seerr@sha256:deadbeef" in compose and "watchtower.enable" in compose
    assert list((root / "seerr" / ".nas-mcp-history").iterdir())     # old file backed up
    assert watcher.recent()[-1]["status"] == "rolled back"
    assert watcher.decide(u.id, u.secret, "rollback") == "rolled back"   # idempotent


def test_ignore(world):
    w, watcher, alerts, _ = world
    watcher.scan(now=1000)
    w.containers[0]["ImageID"] = "sha256:new"
    w.inspect["seerr"]["State"]["Status"] = "exited"
    w.inspect["seerr"]["State"]["ExitCode"] = 1
    watcher.scan(now=1100)
    u = watcher.check_due(now=1500)[0]
    assert watcher.decide(u.id, u.secret, "ignore") == "ignored"
    assert w.posts == []


def test_state_persists(world, tmp_path):
    w, watcher, *_ = world
    watcher.scan(now=1000)
    w.containers[0]["ImageID"] = "sha256:new"
    watcher.scan(now=1100)
    again = up.UpdateWatcher(watcher.docker, tmp_path)
    assert again.find("seerr") and again.seen["seerr"]["image_id"] == "sha256:new"


def test_orphan_compose_rename_finding():
    c = {"Names": ["/36afb8f71bde_nas-mcp"], "Labels": {}, "Ports": []}
    insp = {"Name": "/36afb8f71bde_nas-mcp", "State": {"Status": "running"},
            "Config": {"Labels": {"com.docker.compose.project": "nas-mcp"}, "Cmd": [], "Env": []},
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}}}
    assert any(f.code == "orphan_compose_rename" for f in diagnose(c, insp, ""))


def test_health_scan(nas):  # noqa: F811
    h = nas.health_scan()
    titles = " | ".join(f["title"] for f in h["findings"])
    assert "85.0% full" in titles and "rclone" in titles
    assert 0 <= h["score"] < 100


def test_poke_wakes_only_on_container_start(world):
    _, watcher, _, _ = world
    watcher.poke({"type": "container", "action": "die", "name": "x"})
    assert not watcher.wake.is_set()
    watcher.poke({"type": "image", "action": "pull", "name": "x"})
    assert not watcher.wake.is_set()
    watcher.poke({"type": "container", "action": "start", "name": "x"})
    assert watcher.wake.is_set()


def test_next_wait_follows_due_checks(world):
    w, watcher, _, _ = world
    assert watcher.next_wait(now=1000) == up.FALLBACK     # nothing pending: slow safety scan
    watcher.scan(now=1000)
    w.containers[0]["ImageID"] = "sha256:new"
    watcher.scan(now=1100)
    assert watcher.next_wait(now=1200) == pytest.approx(200)   # check is due at 1400
    watcher.check_due(now=1500)
    assert watcher.next_wait(now=1500) == up.FALLBACK


def test_sync_ha_token(nas):  # noqa: F811
    from nasmcp import notify
    s = nas.s
    s.ha_url, s.ha_token = "http://ha", "ha-secret"
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path, req.content))
        if req.url.path.endswith(".missing"):
            return httpx.Response(404)
        return httpx.Response(200, json={"state": "old"})

    orig_get, orig_post = httpx.get, httpx.post
    tr = httpx.MockTransport(handler)
    httpx.get = lambda url, **k: httpx.Client(transport=tr).get(url, **k)
    httpx.post = lambda url, **k: httpx.Client(transport=tr).post(url, **k)
    try:
        assert notify.sync_ha_token(s) == "set"
        assert calls[-1][1] == "/api/services/input_text/set_value"
        assert json.loads(calls[-1][2])["value"] == s.health_token != s.token
        s.ha_token_entity = "input_text.missing"
        assert notify.sync_ha_token(s) == "missing"
        s.ha_token_entity = ""
        assert notify.sync_ha_token(s) == "off"
    finally:
        httpx.get, httpx.post = orig_get, orig_post
