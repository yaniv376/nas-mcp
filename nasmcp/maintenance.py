"""Storage maintenance through the DSM Web API: S.M.A.R.T. tests and data
scrubbing, the same calls Storage Manager makes (DSM 7.2).

Starting a test or a scrub is a change (agent window, audited) but needs no
phone approval: neither touches data. Nothing here can delete, repair, or
change a pool.
"""

from __future__ import annotations

import json
from typing import Any

from .dsm import DSMClient

TEST_TYPES = {"quick": "quick", "extended": "extend", "stop": "stop"}
RESULTS_HE = {"completed": "הסתיימה תקין", "damage": "נמצאה בעיה", "aborted": "בוטלה",
              "interrupted": "נקטעה", "extended_test_suggested": "מומלצת בדיקה מורחבת"}


def _p(**params: Any) -> dict:
    """DSM 7 web API parameters are JSON values."""
    return {k: json.dumps(v) for k, v in params.items()}


def _info(dsm: DSMClient) -> dict:
    return dsm.request("SYNO.Storage.CGI.Storage", "load_info", version=1)


def _disk_name(d: dict) -> str:
    return d.get("longName") or d.get("name") or d.get("id", "")


def find_disk(info: dict, disk: str) -> dict:
    """Accept 'Drive 2', '2', 'sata4' or '/dev/sata4'."""
    want = disk.strip().lower()
    for d in info.get("disks", []):
        names = {str(d.get("id", "")).lower(), str(d.get("device", "")).lower(),
                 _disk_name(d).lower()}
        if want in names or want == _disk_name(d).lower().replace("drive ", "").strip():
            return d
    known = ", ".join(f"{_disk_name(d)} ({d.get('id')})" for d in info.get("disks", []))
    raise ValueError(f"No disk '{disk}'. Disks: {known}")


def smart_status(dsm: DSMClient, disk: str = "") -> list[dict]:
    info = _info(dsm)
    disks = [find_disk(info, disk)] if disk else info.get("disks", [])
    out = []
    for d in disks:
        dev = d.get("device") or f"/dev/{d.get('id')}"
        log = dsm.request("SYNO.Core.Storage.Disk", "get_smart_test_log", version=1, **_p(device=dev))
        t = (log.get("testInfo") or [{}])[0]
        out.append({
            "disk": _disk_name(d), "id": d.get("id"), "model": d.get("model"),
            "testing": bool(t.get("testing")),
            "remaining": (t.get("remain") or "").strip() or None,
            "last_result": t.get("latest_test_result") or None,
            "last_type": {1: "quick", 2: "extended"}.get(t.get("latest_test_type")),
            "last_test_time": log.get("latest_test_time") or None,
            "minutes_quick": _int(t.get("quickTime")), "minutes_extended": _int(t.get("extendTime")),
            "unreadable_sectors": d.get("unc"),
        })
    return out


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def smart_test(dsm: DSMClient, disk: str, test: str) -> dict:
    if test not in TEST_TYPES:
        raise ValueError("test must be quick, extended or stop")
    info = _info(dsm)
    d = find_disk(info, disk)
    dev = d.get("device") or f"/dev/{d.get('id')}"
    before = smart_status(dsm, d["id"])[0]
    if test != "stop" and before["testing"]:
        raise ValueError(f"{before['disk']} is already running a test ({before['remaining'] or 'in progress'}).")
    dsm.request("SYNO.Core.Storage.Disk", "do_smart_test", version=1,
                **_p(device=dev, type=TEST_TYPES[test]))
    minutes = before["minutes_quick"] if test == "quick" else before["minutes_extended"]
    return {"disk": before["disk"], "id": d["id"], "test": test,
            "expected_minutes": None if test == "stop" else minutes,
            "note": "The disk keeps working during the test; check with disk_smart_status."}


def _pools(info: dict) -> list[dict]:
    vols = {v.get("id"): v.get("vol_path") for v in info.get("volumes", [])}
    out = []
    for p in info.get("storagePools", []):
        dp = p.get("deploy_path") or ""
        out.append({"id": p.get("id"), "raid": p.get("raidType") or p.get("device_type"),
                    "volume": vols.get(dp) or (f"/{dp.replace('_', '')}" if dp.startswith("volume") else None),
                    "disks": p.get("disks") or [], "status": p.get("scrubbingStatus"),
                    "scheduled": bool(p.get("is_scheduled")), "_raw": p})
    return out


def find_pool(info: dict, pool: str) -> dict:
    want = pool.strip().lower().lstrip("/")
    for p in _pools(info):
        vol = (p["volume"] or "").lstrip("/").lower()
        if want in (str(p["id"]).lower(), vol, vol.replace("volume", "volume_")):
            return p
    known = ", ".join(f"{p['id']} ({p['volume'] or 'no volume'})" for p in _pools(info))
    raise ValueError(f"No storage pool '{pool}'. Pools: {known}")


def scrubbing_status(dsm: DSMClient) -> list[dict]:
    info = _info(dsm)
    out = []
    for p in _pools(info):
        st = dsm.request("SYNO.Storage.CGI.Scrubbing", "get_state", version=1, **_p(space_id=p["id"]))
        out.append({"pool": p["id"], "volume": p["volume"], "disks": p["disks"],
                    "state": st.get("state") or p["status"], "scheduled": p["scheduled"]})
    return out


def _scrub_api(raw: dict) -> str:
    """Same choice as Storage Manager (storage_panel.js scrubbingAPIType)."""
    single = raw.get("raidType") == "single"
    dp = raw.get("deploy_path") or ""
    if single and "volume" in dp:
        return "SYNO.Storage.CGI.Volume"
    if single and "iscsilun" in dp:
        return "SYNO.Core.Storage.iSCSILUN"
    return "SYNO.Storage.CGI.Pool"


def scrubbing_start(dsm: DSMClient, pool: str) -> dict:
    info = _info(dsm)
    p = find_pool(info, pool)
    state = dsm.request("SYNO.Storage.CGI.Scrubbing", "get_state", version=1,
                        **_p(space_id=p["id"])).get("state", "")
    if state.endswith("running"):
        raise ValueError(f"Data scrubbing is already running on {p['id']}.")
    dsm.request(_scrub_api(p["_raw"]), "data_scrubbing", version=1, **_p(space_id=p["id"], force=False))
    return {"pool": p["id"], "volume": p["volume"], "started": True,
            "note": "It can take many hours and slows the NAS a little; follow it with scrubbing_status."}


def scrubbing_schedule_resume(dsm: DSMClient) -> dict:
    dsm.request("SYNO.Storage.CGI.Storage", "set_data_scrubbing_schedule_status", version=1,
                **_p(schedule_status="0"))
    return {"schedule": "resumed",
            "note": "DSM keeps one data scrubbing schedule for all pools; it runs on its next date."}
