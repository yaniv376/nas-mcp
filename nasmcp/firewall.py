"""DSM firewall rules through the DSM Web API, the same calls Control Panel >
Security > Firewall makes (DSM 7.2+).

Reading is always allowed. Adding a rule or putting back an earlier profile:
  * needs the gate's agent window and a tap on the phone,
  * saves the whole current profile to data/firewall-history first,
  * never removes or edits an existing rule (restore is the only way back),
  * refuses a deny rule that would cover a network that must stay reachable
    (home LAN, Docker, Tailscale by default: Home Assistant, backups and this
    server itself come in through them).
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any

from .dsm import DSMClient, DSMError

FW = "SYNO.Core.Security.Firewall"
PROFILE = "SYNO.Core.Security.Firewall.Profile"
APPLY = "SYNO.Core.Security.Firewall.Profile.Apply"

DEFAULT_KEEP_OPEN = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10"]
HISTORY = "firewall-history"


def _p(**params: Any) -> dict:
    return {k: json.dumps(v) for k, v in params.items()}


# -- reading ---------------------------------------------------------------------------

def status(dsm: DSMClient) -> dict:
    st = dsm.request(FW, "get", version=1)
    return {"enabled": bool(st.get("enable_firewall")), "profile": st.get("profile_name") or ""}


def get_profile(dsm: DSMClient, name: str) -> dict:
    return dsm.request(PROFILE, "get", version=1, **_p(name=name))


def _adapters(profile: dict) -> dict[str, dict]:
    return {k: v for k, v in profile.items()
            if isinstance(v, dict) and isinstance(v.get("rules"), list)}


def _source_text(r: dict) -> str:
    g, ip = r.get("source_ip_group"), r.get("source_ip", "")
    if g == "all" or ip == "all":
        return "all"
    if g == "netmask" and "/" in str(ip):
        net, mask = str(ip).split("/", 1)
        try:
            return str(ipaddress.ip_network(f"{net}/{mask}", strict=False))
        except ValueError:
            return str(ip)
    return str(ip)


def _ports_text(r: dict) -> str:
    if r.get("port_group") == "all" or r.get("ports") == "all":
        return "all"
    ports = r.get("ports")
    if isinstance(ports, list):
        return ", ".join(str(p) for p in ports)
    return str(ports)


def describe(r: dict) -> dict:
    return {"action": "allow" if r.get("policy") == "allow" else "deny",
            "source": _source_text(r), "ports": _ports_text(r),
            "protocol": r.get("protocol") or "all", "enabled": bool(r.get("enable", True)),
            "name": r.get("name") or ""}


def rules(dsm: DSMClient) -> dict:
    st = status(dsm)
    out: dict[str, Any] = {**st, "adapters": {}}
    if not st["profile"]:
        return out
    prof = get_profile(dsm, st["profile"])
    for name, a in _adapters(prof).items():
        out["adapters"][name] = {
            "when_no_rule_matches": "allow" if a.get("policy") == "allow" else "deny",
            "rules": [dict(describe(r), position=i + 1) for i, r in enumerate(a["rules"])],
        }
    return out


# -- building a rule --------------------------------------------------------------------

def parse_source(source: str) -> tuple[str, str, ipaddress._BaseNetwork | None]:
    """'all', '1.2.3.4' or '1.2.3.0/24' -> (source_ip, source_ip_group, network)."""
    s = (source or "").strip()
    if s.lower() in ("all", "any", "*"):
        return "all", "all", ipaddress.ip_network("0.0.0.0/0")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError as e:
        raise ValueError(f"source must be 'all', an IPv4 address or a network like "
                         f"192.168.4.0/24 (got '{source}')") from e
    if net.version != 4:
        raise ValueError("only IPv4 sources are supported")
    if net.prefixlen == 32:
        return str(net.network_address), "ip", net
    return f"{net.network_address}/{net.netmask}", "netmask", net


def parse_ports(ports: str) -> str:
    """'all' or a list like '8191,8192' or '6000-6010' -> DSM ports text."""
    p = (ports or "all").replace(" ", "")
    if p.lower() == "all":
        return "all"
    parts = []
    for item in p.split(","):
        lo, _, hi = item.partition("-")
        for n in (lo, hi) if hi else (lo,):
            if not n.isdigit() or not 1 <= int(n) <= 65535:
                raise ValueError(f"bad port '{item}': use numbers 1-65535, e.g. 8191,8192 or 6000-6010")
        if hi and int(hi) < int(lo):
            raise ValueError(f"bad port range '{item}'")
        parts.append(f"{lo}:{hi}" if hi else lo)
    return ",".join(parts)


def _template(all_rules: list[dict], **want) -> dict:
    """Copy the shape of an existing rule DSM wrote, so unknown keys match this DSM."""
    for r in all_rules:
        if all(r.get(k) == v for k, v in want.items()):
            return dict(r)
    return {}


def build_rule(all_rules: list[dict], action: str, source: str, ports: str,
               protocol: str, name: str) -> dict:
    if action not in ("allow", "deny"):
        raise ValueError("action must be allow or deny")
    protocol = (protocol or "all").lower()
    if protocol not in ("all", "tcp", "udp"):
        raise ValueError("protocol must be all, tcp or udp")
    src_ip, src_group, _ = parse_source(source)
    port_text = parse_ports(ports)
    deny_value = next((r.get("policy") for r in all_rules if r.get("policy") not in (None, "allow")), "drop")
    rule = {"enable": True, "log": False, "name": "", "policy": "allow",
            "port_direction": "", "port_group": "all", "ports": "all", "protocol": "all",
            "source_ip": "all", "source_ip_group": "all"}
    rule.update(_template(all_rules, source_ip_group=src_group) or {})
    rule.update({"enable": True, "name": (name or "")[:32], "source_ip": src_ip,
                 "source_ip_group": src_group,
                 "policy": "allow" if action == "allow" else deny_value})
    if port_text == "all":
        rule.update({"port_group": "all", "ports": "all", "protocol": "all", "port_direction": ""})
    else:
        tpl = _template(all_rules, port_group="custom")
        rule.update({"port_group": "custom", "ports": port_text,
                     "port_direction": tpl.get("port_direction") or "destination",
                     "protocol": "all" if protocol == "all" else protocol})
    return rule


def check_safe(rule: dict, keep_open: list[str]) -> None:
    if rule["policy"] == "allow":
        return
    _, _, net = parse_source(_source_text(rule))
    for keep in keep_open:
        k = ipaddress.ip_network(keep, strict=False)
        if net is not None and net.overlaps(k):
            raise ValueError(
                f"A deny rule for {_source_text(rule)} would also block {keep}, which must stay "
                "reachable (home network, Docker, Tailscale: Home Assistant, backups and this "
                "server come in that way). Nothing was changed.")


def _same(a: dict, b: dict) -> bool:
    return describe(a) | {"name": ""} == describe(b) | {"name": ""}


# -- changing -----------------------------------------------------------------------------

def _history(data_dir: Path) -> Path:
    d = data_dir / HISTORY
    d.mkdir(parents=True, exist_ok=True)
    return d


def backup(data_dir: Path, profile_name: str, profile: dict) -> str:
    stem = f"{time.strftime('%Y%m%d-%H%M%S')}-{profile_name}"
    name, n = f"{stem}.json", 1
    while (_history(data_dir) / name).exists():   # never overwrite an earlier copy
        n += 1
        name = f"{stem}-{n}.json"
    (_history(data_dir) / name).write_text(json.dumps({"profile_name": profile_name,
                                                       "profile": profile}, ensure_ascii=False,
                                                      indent=1), encoding="utf-8")
    return name


def list_backups(data_dir: Path) -> list[str]:
    d = data_dir / HISTORY
    return sorted((p.name for p in d.glob("*.json")), reverse=True) if d.is_dir() else []


def _apply(dsm: DSMClient, profile_name: str, profile: dict, wait: float = 60) -> None:
    dsm.request(PROFILE, "set", version=1, **_p(profile=profile, profile_applying=True))
    task = dsm.request(APPLY, "start", version=1, **_p(name=profile_name, profile_applying=True))
    tid = task.get("task_id")
    if not tid:
        return
    deadline = time.time() + wait
    while time.time() < deadline:
        st = dsm.request(APPLY, "status", version=1, **_p(task_id=tid))
        if "success" in st:
            if not st["success"]:
                raise DSMError(f"DSM could not apply the firewall profile: {st}")
            return
        time.sleep(1)
    raise DSMError("DSM did not finish applying the firewall profile within a minute; "
                   "check Control Panel > Security > Firewall.")


def plan_add(dsm: DSMClient, action: str, source: str, ports: str = "all",
             protocol: str = "all", name: str = "", adapter: str = "",
             keep_open: list[str] | None = None) -> dict:
    """Everything needed to add the rule, without changing anything."""
    st = status(dsm)
    if not st["enabled"] or not st["profile"]:
        raise ValueError("The DSM firewall is off; turn it on in Control Panel first.")
    prof = get_profile(dsm, st["profile"])
    adapters = _adapters(prof)
    if not adapters:
        raise DSMError("DSM returned a firewall profile without rules lists")
    ad = adapter or ("global" if "global" in adapters else next(iter(adapters)))
    if ad not in adapters:
        raise ValueError(f"No adapter '{ad}'. Adapters: {', '.join(adapters)}")
    current = adapters[ad]["rules"]
    rule = build_rule(current, action, source, ports, protocol, name)
    check_safe(rule, keep_open or DEFAULT_KEEP_OPEN)
    if any(_same(rule, r) for r in current):
        raise ValueError("An identical rule already exists; nothing to add.")
    # Allow rules go first; deny rules go first too (they cannot cover the
    # networks that must stay reachable, check_safe made sure of that).
    new = json.loads(json.dumps(prof))
    new[ad]["rules"] = [rule] + current
    new.setdefault("name", st["profile"])
    return {"profile_name": st["profile"], "adapter": ad, "rule": rule,
            "old": prof, "new": new}


def add_rule(dsm: DSMClient, plan: dict, data_dir: Path) -> dict:
    saved = backup(data_dir, plan["profile_name"], plan["old"])
    _apply(dsm, plan["profile_name"], plan["new"])
    after = _adapters(get_profile(dsm, plan["profile_name"])).get(plan["adapter"], {})
    if not any(_same(plan["rule"], r) for r in after.get("rules", [])):
        raise DSMError(f"DSM accepted the change but the rule is not in the profile; the old "
                       f"profile is saved as {saved} (firewall_restore).")
    return {"added": describe(plan["rule"]), "position": 1, "adapter": plan["adapter"],
            "profile": plan["profile_name"], "backup": saved,
            "still_enabled": status(dsm)["enabled"]}


def restore(dsm: DSMClient, data_dir: Path, backup_name: str) -> dict:
    if "/" in backup_name or backup_name.startswith("."):
        raise ValueError("give the backup file name only (see firewall_backups)")
    src = data_dir / HISTORY / backup_name
    if not src.is_file():
        raise ValueError(f"no firewall backup named {backup_name}")
    saved = json.loads(src.read_text(encoding="utf-8"))
    name, prof = saved["profile_name"], saved["profile"]
    current = get_profile(dsm, name)
    before = backup(data_dir, name, current)
    _apply(dsm, name, prof)
    return {"restored": backup_name, "profile": name, "backup_of_current": before}
