"""NAS health scan: one score for disks, space, data protection, updates,
backups and containers (security has its own scan in the NAS gate)."""

from __future__ import annotations

import re
import time
from typing import Any

from .dsm import DSMClient, DSMError

PENALTY = {"high": 15, "medium": 6, "low": 2, "info": 0}


def _f(severity: str, area: str, title: str, advice: str = "") -> dict:
    return {"severity": severity, "area": area, "title": title, "advice": advice}


def dsm_checks(dsm: DSMClient, storage: dict) -> list[dict]:
    out: list[dict] = []
    # Data scrubbing state per pool (from the storage info already read).
    for p in storage.get("pools", []):
        sc = str(p.get("scrubbing") or "").lower()
        if "pause" in sc:
            out.append(_f("medium", "data protection", f"Data scrubbing schedule is paused on {p['id']}",
                          "Resume it in Storage Manager > Storage > Data Scrubbing; it finds silent "
                          "disk errors while they can still be repaired."))
        if str(p.get("raid") or "").endswith("without_disk_protect") or p.get("raid") in ("basic", "raid0"):
            out.append(_f("medium", "data protection",
                          f"Storage pool {p['id']} has no disk protection",
                          "If its disk fails, everything on it is lost: keep a backup of it."))
    # DSM update available?
    try:
        up = dsm.try_request("SYNO.Core.Upgrade.Server", "check")
        info = up.get("update") or up
        if isinstance(info, dict) and info.get("available"):
            ver = info.get("version") or info.get("version_name") or ""
            out.append(_f("low", "updates", f"DSM update available {ver}".strip(),
                          "Install it from Control Panel > Update & Restore."))
    except DSMError:
        pass
    return out


def scan(nas) -> dict[str, Any]:
    findings: list[dict] = []
    st = nas.storage()
    for e in st.get("errors", []):
        findings.append(_f("info", "storage", f"Could not read storage: {e}"))
    for f in st.get("findings", []):
        findings.append(_f(f["severity"], "disks and space", f["title"]))
    try:
        with nas._dsm_factory() as dsm:
            findings += dsm_checks(dsm, st)
    except DSMError as e:
        findings.append(_f("info", "dsm", f"DSM checks skipped: {e}"))
    # Backups
    for b in nas.backups():
        if b.get("status") != "ok":
            findings.append(_f("high", "backups", f"Backup '{b['name']}' is {b.get('status')}",
                               b.get("detail") or f"newest file is {b.get('age_hours')} hours old"))
    if not nas.s.backups:
        findings.append(_f("info", "backups", "No backup targets configured to watch"))
    # Containers
    try:
        d = nas.diagnose()
        for p in d["problems"]:
            findings.append(_f(p["severity"], "containers", f"{p['container']}: {p['title']}",
                               p.get("suggestion") or ""))
    except Exception as e:  # noqa: BLE001
        findings.append(_f("info", "containers", f"Containers not checked: {e}"))
    # Broken updates waiting
    if getattr(nas, "watcher", None):
        for u in nas.watcher.recent():
            if u["status"] == "broken":
                findings.append(_f("high", "updates", f"{u['name']} broke after an update",
                                   "Use the rollback button in the alert, or ask Claude to roll back."))
    score = max(0, 100 - sum(PENALTY.get(f["severity"], 0) for f in findings))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"score": score, "counts": counts, "findings": findings,
            "finished_at": time.time(), "volumes": st.get("volumes", [])}


ORPHAN = re.compile(r"^[0-9a-f]{12}_(.+)$")
