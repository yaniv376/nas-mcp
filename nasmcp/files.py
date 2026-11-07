"""File access limited to the folders listed in config.yaml.

Every path is resolved (symlinks included) and must stay inside its folder.
Stage 1a is read-only; writing arrives with the MCP window in stage 1c.
"""

from __future__ import annotations

import fnmatch
import os
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
        names = ", ".join(x.name for x in settings.folders if x.access != "closed") or "none"
        raise AccessDenied(f"unknown folder '{name}'. Allowed: {names}")
    if f.access == "closed" or (need == "write" and f.access != "write"):
        raise AccessDenied(f"folder '{name}' is {f.access}")
    return f


def list_folders(settings: Settings) -> list[dict[str, Any]]:
    return [{"name": f.name, "access": f.access, "exists": Path(f.path).is_dir()}
            for f in settings.folders]


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
