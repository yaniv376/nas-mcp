"""File access limited to the allowed folders (see folders.py).

Every path is resolved (symlinks included) and must stay inside its folder.
Writes need a folder set to "write" and the agent window (checked by the
caller). Nothing is ever deleted: an overwritten file is copied to
.nas-mcp-history first, and "retire" moves things into the folder's _to_delete.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import time
from pathlib import Path
from typing import Any

from .config import Folder, Settings


class AccessDenied(Exception):
    pass


# Never shown even inside an allowed folder: they only hold secrets.
BLOCKED_NAMES = (".env", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*.kdbx", "secrets.yaml")


def _blocked(path: Path) -> bool:
    return any(fnmatch.fnmatch(path.name.lower(), pat) for pat in BLOCKED_NAMES)


def _resolve(folder: Folder, rel: str) -> Path:
    root = Path(folder.path).resolve()
    rel = (rel or "").lstrip("/")
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise AccessDenied("path leaves the allowed folder")
    return target


def _folder(settings: Settings, name: str, need: str = "read") -> Folder:
    f = settings.folder(name)
    if not f:
        names = ", ".join(x.name for x in settings.all_folders() if x.access != "closed") or "none"
        raise AccessDenied(f"unknown folder '{name}'. Allowed: {names}")
    if f.access == "closed" or (need == "write" and f.access != "write"):
        raise AccessDenied(f"folder '{name}' is {f.access}")
    return f


def list_folders(settings: Settings) -> list[dict[str, Any]]:
    return [{"name": f.name, "access": f.access, "exists": Path(f.path).is_dir()}
            for f in settings.all_folders() if f.access != "closed"]


def list_dir(settings: Settings, folder: str, path: str = "", max_entries: int = 500) -> dict:
    f = _folder(settings, folder)
    target = _resolve(f, path)
    if not target.is_dir():
        raise AccessDenied("not a directory")
    items = []
    for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        try:
            st = entry.stat()
        except OSError:
            continue
        items.append({"name": entry.name + ("/" if entry.is_dir() else ""),
                      "size": st.st_size if entry.is_file() else None,
                      "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))})
        if len(items) >= max_entries:
            break
    return {"folder": folder, "path": path or "/", "entries": items}


def read_file(settings: Settings, folder: str, path: str) -> dict:
    f = _folder(settings, folder)
    target = _resolve(f, path)
    if not target.is_file():
        raise AccessDenied("not a file")
    if _blocked(target):
        raise AccessDenied("this file only holds secrets and is never shown")
    size = target.stat().st_size
    with target.open("rb") as fh:
        data = fh.read(settings.max_file_bytes)
    if b"\x00" in data[:4096]:
        return {"path": path, "size": size, "binary": True}
    return {"path": path, "size": size, "truncated": size > settings.max_file_bytes,
            "content": redact(data.decode("utf-8", "replace"))}


def search(settings: Settings, folder: str, pattern: str, path: str = "",
           max_results: int = 200) -> dict:
    f = _folder(settings, folder)
    root = _resolve(f, path)
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(("@", "#recycle"))]
        for name in filenames + [d + "/" for d in dirnames]:
            if fnmatch.fnmatch(name.rstrip("/").lower(), pattern.lower()):
                rel = os.path.relpath(os.path.join(dirpath, name), Path(f.path).resolve())
                hits.append(rel)
                if len(hits) >= max_results:
                    return {"results": hits, "truncated": True}
    return {"results": hits, "truncated": False}


_SECRET_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")


def redact(text: str) -> str:
    """Hide values of obvious secrets in config files (KEY: value / KEY=value)."""
    out = []
    for line in text.splitlines(keepends=True):
        low = line.lower()
        if any(k in low for k in _SECRET_KEYS):
            for sep in (":", "="):
                if sep in line:
                    key, _, val = line.partition(sep)
                    if val.strip() and any(k in key.lower() for k in _SECRET_KEYS):
                        nl = "\n" if line.endswith("\n") else ""
                        line = f"{key}{sep} ***redacted***{nl}"
                    break
        out.append(line)
    return "".join(out)


def newest_file(path: str, pattern: str) -> dict | None:
    p = Path(path)
    if not p.is_dir():
        return None
    best = None
    for dirpath, _dirs, files in os.walk(p):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                full = Path(dirpath) / name
                try:
                    st = full.stat()
                except OSError:
                    continue
                if not best or st.st_mtime > best[1]:
                    best = (full, st.st_mtime, st.st_size)
    if not best:
        return None
    return {"file": best[0].name, "modified": best[1], "size_mb": round(best[2] / 1e6, 1)}


def grep(settings: Settings, folder: str, pattern: str, path: str = "", glob: str = "*",
         context: int = 160, max_hits: int = 40, max_file_mb: int = 25) -> dict:
    """Regex search inside files of an allowed folder. Returns short snippets
    around each hit (works on one-line minified files too)."""
    import re
    f = _folder(settings, folder)
    root = _resolve(f, path)
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise AccessDenied(f"bad pattern: {e}") from e
    base = Path(f.path).resolve()
    hits: list[dict] = []
    files_scanned = 0
    targets = [root] if root.is_file() else None
    walker = ([(str(root.parent), [], [root.name])] if targets else os.walk(root))
    for dirpath, dirnames, filenames in walker:
        dirnames[:] = [d for d in dirnames if not d.startswith(("@", "#recycle"))]
        for name in filenames:
            if not fnmatch.fnmatch(name, glob):
                continue
            full = Path(dirpath) / name
            try:
                if full.is_symlink() or _blocked(full) or full.stat().st_size > max_file_mb * 1_000_000:
                    continue
                if name.endswith(".gz"):
                    import gzip
                    with gzip.open(full, "rb") as gz:
                        text = gz.read(max_file_mb * 4_000_000).decode("utf-8", "replace")
                else:
                    text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            for m in rx.finditer(text):
                a, b = max(0, m.start() - context), min(len(text), m.end() + context)
                hits.append({"file": os.path.relpath(full, base),
                             "snippet": redact(text[a:b]).replace("\n", " ")})
                if len(hits) >= max_hits:
                    return {"hits": hits, "truncated": True, "files_scanned": files_scanned}
    return {"hits": hits, "truncated": False, "files_scanned": files_scanned}


# -- writing (stage 1c-2) ----------------------------------------------------------

HISTORY_DIR = ".nas-mcp-history"
RETIRE_DIR = "_to_delete"
MAX_WRITE_BYTES = 1_000_000


def _rel(root: Path, p: Path) -> str:
    return str(p.relative_to(root)) if p != root else ""


def _match_owner(path: Path) -> None:
    """Give a new file or folder the owner of its parent, so the NAS user who
    owns the folder keeps full use of it (this server runs as root)."""
    try:
        st = path.parent.stat()
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


def _mkdirs(root: Path, d: Path) -> None:
    missing = []
    while d != root and not d.exists():
        missing.append(d)
        d = d.parent
    for m in reversed(missing):
        m.mkdir()
        _match_owner(m)


def _writable_target(settings: Settings, folder: str, path: str) -> tuple[Path, Path]:
    f = _folder(settings, folder, "write")
    root = Path(f.path).resolve()
    target = _resolve(f, path)
    if target == root:
        raise AccessDenied("give a path inside the folder, not the folder itself")
    if _blocked(target):
        raise AccessDenied("that file holds secrets and is never touched")
    if HISTORY_DIR in target.relative_to(root).parts:
        raise AccessDenied(f"{HISTORY_DIR} keeps the backups and is not changed from here")
    return root, target


def _backup(root: Path, target: Path) -> str:
    rel = target.relative_to(root)
    dest = root / HISTORY_DIR / rel.parent / f"{rel.name}.{time.strftime('%Y%m%d-%H%M%S')}"
    _mkdirs(root, dest.parent)
    shutil.copy2(target, dest)
    return _rel(root, dest)


def write_file(settings: Settings, folder: str, path: str, content: str,
               overwrite: bool = False) -> dict:
    root, target = _writable_target(settings, folder, path)
    data = content.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        raise AccessDenied(f"content is larger than {MAX_WRITE_BYTES} bytes")
    if target.is_dir():
        raise AccessDenied("that path is a folder")
    backup = None
    if target.exists():
        if not overwrite:
            raise AccessDenied("the file exists: pass overwrite=true to replace it "
                               "(the current copy is kept in " + HISTORY_DIR + ")")
        backup = _backup(root, target)
    _mkdirs(root, target.parent)
    is_new = not target.exists()
    tmp = target.with_name(target.name + ".nas-mcp.tmp")
    tmp.write_bytes(data)
    if not is_new:
        shutil.copymode(target, tmp)
        st = target.stat()
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
    tmp.replace(target)
    if is_new:
        _match_owner(target)
    return {"folder": folder, "path": _rel(root, target), "bytes": len(data), "backup": backup}


def move(settings: Settings, folder: str, src: str, dest: str, dest_folder: str = "") -> dict:
    root, s = _writable_target(settings, folder, src)
    droot, d = _writable_target(settings, dest_folder or folder, dest)
    if not s.exists():
        raise AccessDenied(f"'{src}' does not exist")
    if d.exists():
        raise AccessDenied(f"'{dest}' already exists; nothing is overwritten by a move")
    if s == d or s in d.parents:
        raise AccessDenied("cannot move a folder into itself")
    _mkdirs(droot, d.parent)
    shutil.move(str(s), str(d))
    return {"from": f"{folder}/{_rel(root, s)}", "to": f"{dest_folder or folder}/{_rel(droot, d)}"}


def retire(settings: Settings, folder: str, path: str) -> dict:
    """Move a file or folder into <folder>/_to_delete, keeping its relative path,
    for the owner to delete later in one go."""
    root, s = _writable_target(settings, folder, path)
    rel = s.relative_to(root)
    if rel.parts[0] == RETIRE_DIR:
        raise AccessDenied(f"already in {RETIRE_DIR}")
    dest = root / RETIRE_DIR / rel
    if dest.exists():
        dest = dest.with_name(f"{dest.name}.{time.strftime('%Y%m%d-%H%M%S')}")
    return move(settings, folder, str(rel), _rel(root, dest))
