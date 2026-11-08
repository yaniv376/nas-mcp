"""NAS facts from the DSM Web API: system, utilisation, disks and volumes.

DSM builds differ, so every collector tolerates missing APIs and returns
what it could read plus an `errors` list.
"""

from __future__ import annotations

from typing import Any

from .dsm import DSMClient, DSMError


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def system(dsm: DSMClient) -> dict[str, Any]:
    out: dict[str, Any] = {"errors": []}
    try:
        info = dsm.try_request("SYNO.DSM.Info", "getinfo")
        out.update({
            "model": info.get("model"),
            "dsm_version": info.get("version_string"),
            "ram_mb": info.get("ram"),
            "temperature_c": info.get("temperature"),
            "temperature_warning": info.get("temperature_warn"),
            "uptime_seconds": info.get("uptime"),
            "serial_hidden": True,
        })
    except DSMError as e:
        out["errors"].append(f"DSM.Info: {e}")
    try:
        u = dsm.try_request("SYNO.Core.System.Utilization", "get")
        cpu = u.get("cpu") or {}
        mem = u.get("memory") or {}
        out["cpu_percent"] = sum(_num(cpu.get(k)) or 0 for k in ("user_load", "system_load", "other_load"))
        out["load_1m"] = cpu.get("1min_load")
        total = _num(mem.get("total_real")) or 0
        avail = _num(mem.get("avail_real")) or 0
        cached = _num(mem.get("cached")) or 0
        buffers = _num(mem.get("buffer")) or 0
        if total:
            used = total - avail - cached - buffers
            out["memory_used_percent"] = round(max(used, 0) / total * 100, 1)
        out["swap_used_percent"] = mem.get("swap_usage")
    except DSMError as e:
        out["errors"].append(f"Utilization: {e}")
    return out


def storage(dsm: DSMClient) -> dict[str, Any]:
    out: dict[str, Any] = {"disks": [], "pools": [], "volumes": [], "errors": []}
    try:
        data = dsm.try_request("SYNO.Storage.CGI.Storage", "load_info")
    except DSMError as e:
        out["errors"].append(f"Storage: {e}")
        return out
    for d in data.get("disks") or []:
        out["disks"].append({
            "id": d.get("id") or d.get("name"),
            "name": d.get("longName") or d.get("name"),
            "model": d.get("model"),
            "vendor": (d.get("vendor") or "").strip(),
            "size_gb": round((_num(d.get("size_total")) or 0) / 1e9),
            "temperature_c": d.get("temp"),
            "status": d.get("status") or d.get("overview_status"),
            "smart_status": d.get("smart_status"),
            "remaining_life": d.get("remain_life"),
            "unc_sectors": d.get("unc"),
            "used_by": d.get("used_by"),
        })
    for p in data.get("storagePools") or []:
        out["pools"].append({
            "id": p.get("id"),
            "raid": p.get("device_type") or p.get("raidType"),
            "status": p.get("status"),
            "disks": p.get("disks"),
            "scrubbing": (p.get("scrubbingStatus") or p.get("data_scrubbing")),
        })
    for v in data.get("volumes") or []:
        size = v.get("size") or {}
        total = _num(size.get("total")) or 0
        used = _num(size.get("used")) or 0
        out["volumes"].append({
            "id": v.get("id"),
            "path": v.get("vol_path"),
            "fs": v.get("fs_type"),
            "status": v.get("status"),
            "total_gb": round(total / 1e9, 1),
            "used_gb": round(used / 1e9, 1),
            "used_percent": round(used / total * 100, 1) if total else None,
        })
    return out


_MAINTENANCE_STATES = ("scrubbing", "parity_check", "parity_consistency")


def _is_maintenance(status: str) -> bool:
    """Pool/volume states DSM shows during routine upkeep (e.g. background_scrubbing)."""
    return any(k in status for k in _MAINTENANCE_STATES)


def storage_findings(st: dict[str, Any]) -> list[dict[str, Any]]:
    """Plain problems worth telling the owner about."""
    out = []
    for d in st.get("disks", []):
        status = str(d.get("status") or "").lower()
        smart = str(d.get("smart_status") or "").lower()
        if status and status not in ("normal", "initialized", "not_use"):
            out.append({"severity": "high", "title": f"Disk {d['name']} status: {d['status']}"})
        if smart and smart not in ("normal", "safe", ""):
            out.append({"severity": "high", "title": f"Disk {d['name']} SMART: {d['smart_status']}"})
        if d.get("unc_sectors") not in (None, 0, "0"):
            out.append({"severity": "medium",
                        "title": f"Disk {d['name']} has {d['unc_sectors']} unreadable sectors"})
        t = _num(d.get("temperature_c"))
        if t is not None and t >= 55:
            out.append({"severity": "medium", "title": f"Disk {d['name']} is hot: {t:.0f}°C"})
    for p in st.get("pools", []):
        ps = str(p.get("status") or "").lower()
        if _is_maintenance(ps):
            # Data scrubbing / parity check running: routine upkeep, not a fault.
            out.append({"severity": "info", "title": f"Data scrubbing is running on {p['id']}"})
        elif ps not in ("normal", ""):
            out.append({"severity": "high", "title": f"Storage pool {p['id']} status: {p['status']}"})
    for v in st.get("volumes", []):
        pct = v.get("used_percent")
        if pct is not None and pct >= 90:
            out.append({"severity": "high", "title": f"Volume {v['path']} is {pct}% full"})
        elif pct is not None and pct >= 80:
            out.append({"severity": "medium", "title": f"Volume {v['path']} is {pct}% full"})
        vs = str(v.get("status") or "").lower()
        # A volume mirrors its pool while scrubbing; the pool line already says so.
        if vs not in ("normal", "") and not _is_maintenance(vs):
            out.append({"severity": "high", "title": f"Volume {v['path']} status: {v['status']}"})
    return out
