import os
import time
from pathlib import Path

import pytest

from nasmcp import config, files, watchtower
from nasmcp.core import NAS
from nasmcp.docker import DockerClient, demux
from nasmcp.events import EventLog, compact
from nasmcp.gate import GateClient

from . import fakes


@pytest.fixture
def nas(tmp_path):
    docker_dir = tmp_path / "docker"
    (docker_dir / "seerr").mkdir(parents=True)
    (docker_dir / "seerr" / "compose.yaml").write_text(
        "services:\n  seerr:\n    image: ghcr.io/seerr-team/seerr\n    environment:\n"
        "      DB_PASSWORD: hunter2\n")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "x.txt").write_text("private")
    backups = tmp_path / "backups"
    backups.mkdir()
    old = backups / "ha_old.tar"
    old.write_bytes(b"x" * 10)
    os.utime(old, (time.time() - 50 * 3600,) * 2)
    s = config.Settings(token="t", watchtower_container="watchtower")
    s.folders = [config.Folder("docker", str(docker_dir), "read"),
                 config.Folder("private", str(secret), "closed")]
    s.backups = [config.BackupTarget("HA", str(backups), "*.tar", 30)]
    return NAS(s, EventLog(tmp_path / "events.jsonl"), dsm_factory=fakes.FakeDSM,
               docker=DockerClient("http://proxy", transport=fakes.TRANSPORT),
               gate=GateClient("", ""))


def by(diag, container, code):
    return [f for f in diag["problems"] + diag["notes"]
            if f["container"] == container and f["code"] == code]


def test_demux_plain_and_multiplexed():
    assert demux(fakes.mux("a\nb\n")) == "a\nb\n"
    assert demux(b"plain tty\n") == "plain tty\n"


def test_watchtower_parse():
    rep = watchtower.parse(fakes.WATCHTOWER_LOG)
    assert [u.container for u in rep.updates] == ["rclone"]
    assert rep.updates[0].image == "rclone/rclone:latest"
    assert [s["container"] for s in rep.stops] == ["qbittorrent", "rclone"]
    assert rep.errors and "Conflict" in rep.errors[0]["msg"]


def test_rclone_crash_loop_after_update(nas):
    d = nas.diagnose("rclone")
    assert by(d, "rclone", "restart_loop")
    assert by(d, "rclone", "log_flag_changed")
    assert by(d, "rclone", "broke_after_update")
    rep = by(d, "rclone", "repeated_error")
    assert rep and "superseded" in rep[0]["evidence"][0]


def test_qbittorrent_stopped_by_watchtower(nas):
    d = nas.diagnose("qbittorrent")
    stopped = by(d, "qbittorrent", "stopped")[0]
    assert stopped["severity"] == "high"
    assert "Watchtower" in stopped["evidence"][0]
    assert by(d, "qbittorrent", "no_restart_policy")
    assert by(d, "qbittorrent", "standalone")


def test_filebrowser_permission_and_archived(nas):
    d = nas.diagnose("filebrowser")
    assert by(d, "filebrowser-1", "log_permission")
    assert "1026:100" in by(d, "filebrowser-1", "log_permission")[0]["suggestion"]
    assert by(d, "filebrowser-1", "deprecated_image")


def test_all_containers_healthy_list(nas):
    d = nas.diagnose()
    assert "seerr" in d["healthy"] and "watchtower" in d["healthy"]
    assert d["checked"] == 5


def test_container_details(nas):
    c = nas.container("rclone")
    assert c["last_watchtower_update"]["image"] == "rclone/rclone:latest"
    assert c["image_version_label"] == "1.74.0"
    assert c["restart_count"] == 40


def test_logs_redacted(nas):
    os_log = nas.logs("seerr", tail=10)
    assert "Server ready" in os_log


def test_unknown_container_lists_names(nas):
    from nasmcp.docker import DockerError
    with pytest.raises(DockerError) as e:
        nas.container("nope")
    assert "seerr" in str(e.value)


def test_storage_findings(nas):
    st = nas.storage()
    titles = " | ".join(f["title"] for f in st["findings"])
    assert "85.0% full" in titles
    assert "hot" in titles and "unreadable sectors" in titles


def test_system(nas):
    s = nas.system()
    assert s["model"] == "DS920+" and s["cpu_percent"] == 9
    assert 0 < s["memory_used_percent"] < 100


def test_backups_late(nas):
    b = nas.backups()[0]
    assert b["status"] == "late" and b["age_hours"] > 49


def test_files_allowlist_and_redaction(nas):
    s = nas.s
    assert [e["name"] for e in files.list_dir(s, "docker")["entries"]] == ["seerr/"]
    content = files.read_file(s, "docker", "seerr/compose.yaml")["content"]
    assert "hunter2" not in content and "redacted" in content
    with pytest.raises(files.AccessDenied):
        files.read_file(s, "docker", "../secret/x.txt")
    with pytest.raises(files.AccessDenied):
        files.list_dir(s, "private")
    with pytest.raises(files.AccessDenied):
        files.list_dir(s, "volume1")
    assert files.search(s, "docker", "*.yaml")["results"] == ["seerr/compose.yaml"]


def test_symlink_escape_blocked(nas, tmp_path):
    link = Path(nas.s.folders[0].path) / "escape"
    link.symlink_to(tmp_path / "secret")
    with pytest.raises(files.AccessDenied):
        files.list_dir(nas.s, "docker", "escape")


def test_events_compact_and_timeline(nas):
    item = compact({"Type": "container", "Action": "die", "time": int(time.time()),
                    "Actor": {"ID": "abc", "Attributes": {"name": "rclone", "exitCode": "1"}}})
    assert item["name"] == "rclone" and item["exit"] == "1"
    assert compact({"Type": "container", "Action": "exec_start: sh", "Actor": {}}) is None
    nas.events.append(item)
    tl = nas.timeline(hours=24)
    actions = [(e["name"], e["action"]) for e in tl["events"]]
    assert ("rclone", "die") in actions and ("rclone", "update") in actions


def test_gate_not_configured(nas):
    assert "not configured" in nas.security_scan()["error"]


def test_overview(nas):
    o = nas.overview()
    assert o["system"]["model"] == "DS920+"
    assert o["containers"]["checked"] == 5
    assert any(p["container"] == "rclone" for p in o["containers"]["problems"])


def test_watchtower_tool_does_not_damage_cache(nas):
    nas.watchtower_report()
    nas.watchtower()
    assert by(nas.diagnose("qbittorrent"), "qbittorrent", "stopped")[0]["evidence"]


def test_env_file_blocked(nas):
    env = Path(nas.s.folders[0].path) / "seerr" / ".env"
    env.write_text("X=1")
    with pytest.raises(files.AccessDenied):
        files.read_file(nas.s, "docker", "seerr/.env")


def test_no_auth_only_when_running_and_retired_skipped(nas):
    from nasmcp.diagnose import diagnose
    insp = dict(fakes.INSPECT["rclone"])
    insp["State"] = dict(insp["State"], Status="running")
    assert any(f.code == "no_auth" for f in diagnose(fakes.CONTAINERS[1], insp, ""))
    insp["State"] = dict(insp["State"], Status="exited", ExitCode=143)
    assert not any(f.code == "no_auth" for f in diagnose(fakes.CONTAINERS[1], insp, ""))
    insp["Name"] = "/_to_delete_rclone"
    assert diagnose(fakes.CONTAINERS[1], insp, "") == []


def test_retired_names():
    from nasmcp.diagnose import is_retired
    assert is_retired("_to_delete_rclone") and is_retired("to_delete_watchtower")
    assert is_retired("todeletewatchtower") and not is_retired("watchtower")


def test_grep(nas):
    r = files.grep(nas.s, "docker", r"image:\s*\S+", glob="*.yaml")
    assert r["hits"] and "seerr" in r["hits"][0]["snippet"]
    assert "hunter2" not in str(r)
    with pytest.raises(files.AccessDenied):
        files.grep(nas.s, "private", "x")


def test_scrubbing_is_not_a_fault():
    from nasmcp.system import storage_findings
    from nasmcp.i18n_he import localize
    st = {"disks": [], "pools": [{"id": "reuse_2", "status": "background_scrubbing"},
                                 {"id": "reuse_9", "status": "degraded"}],
          "volumes": [{"path": "/volume1", "status": "background_scrubbing", "used_percent": 40}]}
    f = storage_findings(st)
    assert {"severity": "info", "title": "Data scrubbing is running on reuse_2"} in f
    assert not [x for x in f if "/volume1" in x["title"]]
    assert {"severity": "high", "title": "Storage pool reuse_9 status: degraded"} in f
    he = localize({"severity": "info", "area": "disks and space",
                   "title": "Data scrubbing is running on reuse_2", "advice": ""})
    assert "רצה עכשיו" in he["title"]
