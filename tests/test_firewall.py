import json

import pytest

from nasmcp import firewall as fw

LAN = {"enable": True, "log": False, "name": "", "policy": "allow", "port_direction": "",
       "port_group": "all", "ports": "all", "protocol": "all",
       "source_ip": "192.168.4.0/255.255.255.0", "source_ip_group": "netmask"}
DOCKER = dict(LAN, source_ip="172.16.0.0/255.240.0.0")
DENY_ALL = dict(LAN, policy="drop", source_ip="all", source_ip_group="all")


class DSM:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.profile = {"name": "default", "global": {"policy": "none",
                                                      "rules": [LAN, DOCKER, DENY_ALL]}}
        self.calls = []

    def request(self, api, method, version=None, **params):
        p = {k: json.loads(v) for k, v in params.items()}
        self.calls.append((api, method, p))
        if api == fw.FW and method == "get":
            return {"enable_firewall": self.enabled, "profile_name": "default"}
        if api == fw.PROFILE and method == "get":
            return json.loads(json.dumps(self.profile))
        if api == fw.PROFILE and method == "set":
            self.profile = p["profile"]
            return {}
        if api == fw.APPLY and method == "start":
            return {"task_id": "t1"}
        if api == fw.APPLY and method == "status":
            return {"success": True}
        return {}


def test_rules_are_described_in_order():
    r = fw.rules(DSM())
    rows = r["adapters"]["global"]["rules"]
    assert r["enabled"] and r["profile"] == "default"
    assert rows[0]["source"] == "192.168.4.0/24" and rows[0]["action"] == "allow"
    assert rows[1]["source"] == "172.16.0.0/12"
    assert rows[2] == dict(rows[2], action="deny", source="all", position=3)


@pytest.mark.parametrize("src,ip,group", [
    ("all", "all", "all"),
    ("100.64.0.0/10", "100.64.0.0/255.192.0.0", "netmask"),
    ("192.168.4.15", "192.168.4.15", "ip"),
])
def test_parse_source(src, ip, group):
    assert fw.parse_source(src)[:2] == (ip, group)


def test_bad_input():
    with pytest.raises(ValueError):
        fw.parse_source("my-pc")
    with pytest.raises(ValueError):
        fw.parse_ports("80,http")
    assert fw.parse_ports("8191, 8192") == "8191,8192"
    assert fw.parse_ports("6000-6010") == "6000:6010"


def test_add_allow_goes_on_top_with_backup(tmp_path):
    d = DSM()
    plan = fw.plan_add(d, "allow", "100.64.0.0/10", name="Tailscale")
    r = fw.add_rule(d, plan, tmp_path)
    rules = d.profile["global"]["rules"]
    assert rules[0]["source_ip"] == "100.64.0.0/255.192.0.0" and rules[0]["policy"] == "allow"
    assert rules[1:] == [LAN, DOCKER, DENY_ALL]        # nothing else touched
    assert r["backup"] in fw.list_backups(tmp_path)
    assert ("SYNO.Core.Security.Firewall.Profile.Apply", "start",
            {"name": "default", "profile_applying": True}) in d.calls


def test_deny_uses_dsm_value_and_custom_ports():
    plan = fw.plan_add(DSM(), "deny", "203.0.113.7", ports="8191,8192", protocol="tcp")
    rule = plan["rule"]
    assert rule["policy"] == "drop" and rule["port_group"] == "custom"
    assert rule["ports"] == "8191,8192" and rule["protocol"] == "tcp"


@pytest.mark.parametrize("src", ["all", "192.168.4.15", "172.17.0.0/16", "100.116.185.110"])
def test_deny_never_covers_networks_that_must_stay_open(src):
    with pytest.raises(ValueError, match="must stay"):
        fw.plan_add(DSM(), "deny", src)


def test_refuses_duplicates_and_firewall_off():
    with pytest.raises(ValueError, match="identical"):
        fw.plan_add(DSM(), "allow", "192.168.4.0/24")
    with pytest.raises(ValueError, match="off"):
        fw.plan_add(DSM(enabled=False), "allow", "1.2.3.4")


def test_restore_puts_back_saved_profile(tmp_path):
    d = DSM()
    fw.add_rule(d, fw.plan_add(d, "allow", "1.2.3.4"), tmp_path)
    first = fw.list_backups(tmp_path)[0]
    r = fw.restore(d, tmp_path, first)
    assert d.profile["global"]["rules"] == [LAN, DOCKER, DENY_ALL]
    assert r["backup_of_current"] in fw.list_backups(tmp_path)
    assert len(fw.list_backups(tmp_path)) == 2     # same second, still two copies
    with pytest.raises(ValueError):
        fw.restore(d, tmp_path, "../x.json")
