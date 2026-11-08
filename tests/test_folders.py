import os

import pytest

from nasmcp import config, files, folders
from nasmcp.gate import GateError


class Gate:
    configured = True

    def __init__(self, items=None, fail=False, window=True):
        self.items, self.fail, self.window = items, fail, window

    def status(self):
        if self.fail:
            raise GateError("down")
        st = {"protections": {"agent": {"managed": True, "is_open": self.window,
                                        "remaining_seconds": 600}}}
        if self.items is not None:
            st["folders"] = {"items": self.items, "error": None}
        return st


@pytest.fixture
def world(tmp_path):
    host = tmp_path / "host"
    (host / "volume1" / "photo" / "2024").mkdir(parents=True)
    (host / "volume1" / "photo" / "2024" / "a.txt").write_text("old")
    (host / "volume1" / "photo" / ".env").write_text("SECRET=1")
    (host / "volume2" / "video").mkdir(parents=True)
    (host / "volume1" / "private").mkdir(parents=True)
    docker = tmp_path / "docker"
    docker.mkdir()
    s = config.Settings(token="t")
    s.folders = [config.Folder("docker", str(docker), "write"),
                 config.Folder("dsm_ui", str(tmp_path), "read")]
    items = [{"name": "docker", "vol_path": "/volume1", "access": "read"},
             {"name": "photo", "vol_path": "/volume1", "access": "write"},
             {"name": "video", "vol_path": "/volume2", "access": "read"},
             {"name": "private", "vol_path": "/volume1", "access": "closed"},
             {"name": "../etc", "vol_path": "/volume1", "access": "write"}]
    gate = Gate(items)
    pol = folders.FolderPolicy(s, gate, ttl=0, host_root=str(host))
    folders.install(pol)
    yield s, gate, host
    folders.install(None)


def test_gate_choices_are_merged(world):
    s, gate, host = world
    got = {f["name"]: f["access"] for f in files.list_folders(s)}
    # docker follows the gate (read), closed folders are hidden, bad names dropped,
    # the server's own read-only mounts stay.
    assert got == {"docker": "read", "photo": "write", "video": "read", "dsm_ui": "read"}
    assert s.folder("photo").path == str(host / "volume1" / "photo")
    with pytest.raises(files.AccessDenied):
        files.list_dir(s, "private")


def test_gate_down_keeps_only_own_mounts(world):
    s, gate, _ = world
    gate.fail = True
    names = {f["name"] for f in files.list_folders(s)}
    assert names == {"docker", "dsm_ui"}
    assert s.folder("docker").access == "write"      # the server's own default
    gate.fail, gate.items = False, None              # older gate without folders
    assert {f["name"] for f in files.list_folders(s)} == {"docker", "dsm_ui"}


def test_write_keeps_backup_and_owner(world):
    s, _, host = world
    photo = host / "volume1" / "photo"
    r = files.write_file(s, "photo", "2024/new/b.txt", "hello")
    assert (photo / "2024" / "new" / "b.txt").read_text() == "hello" and r["backup"] is None
    with pytest.raises(files.AccessDenied):
        files.write_file(s, "photo", "2024/a.txt", "new")          # exists, no overwrite
    r = files.write_file(s, "photo", "2024/a.txt", "new", overwrite=True)
    assert (photo / "2024" / "a.txt").read_text() == "new"
    assert (photo / r["backup"]).read_text() == "old"
    assert r["backup"].startswith(".nas-mcp-history/2024/a.txt.")
    for bad in (".env", ".nas-mcp-history/x", "../video/x", ""):
        with pytest.raises(files.AccessDenied):
            files.write_file(s, "photo", bad, "x", overwrite=True)
    with pytest.raises(files.AccessDenied):
        files.write_file(s, "video", "x.txt", "x")                  # read only


def test_move_and_retire_never_overwrite(world):
    s, _, host = world
    photo = host / "volume1" / "photo"
    files.write_file(s, "photo", "b.txt", "b")
    files.move(s, "photo", "b.txt", "sorted/b.txt")
    assert (photo / "sorted" / "b.txt").exists() and not (photo / "b.txt").exists()
    files.write_file(s, "photo", "c.txt", "c")
    with pytest.raises(files.AccessDenied):
        files.move(s, "photo", "c.txt", "sorted/b.txt")
    with pytest.raises(files.AccessDenied):
        files.move(s, "photo", "sorted", "sorted/inner")
    with pytest.raises(files.AccessDenied):
        files.move(s, "photo", "c.txt", "x.txt", dest_folder="video")   # read only
    r = files.retire(s, "photo", "2024")
    assert r["to"] == "photo/_to_delete/2024" and (photo / "_to_delete" / "2024" / "a.txt").exists()
    (photo / "2024").mkdir()
    r = files.retire(s, "photo", "2024")
    assert r["to"].startswith("photo/_to_delete/2024.")              # second copy gets a time suffix
    with pytest.raises(files.AccessDenied):
        files.retire(s, "photo", "_to_delete/2024")


def test_changes_need_the_window(world, tmp_path):
    s, gate, host = world
    from nasmcp.core import NAS
    from nasmcp.events import EventLog
    from nasmcp import writes as w
    nas = NAS(s, EventLog(tmp_path / "ev.jsonl"), gate=gate)
    nas.audit = w.Audit(tmp_path / "actions.jsonl")
    ch = __import__("nasmcp.core", fromlist=["Changes"]).Changes(nas)
    assert ch.file_write("photo", "w.txt", "x")["done"]
    gate.window = False
    with pytest.raises(w.WriteDenied):
        ch.file_write("photo", "w2.txt", "x")
    assert not (host / "volume1" / "photo" / "w2.txt").exists()
