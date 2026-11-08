import json

import pytest

from nasmcp import maintenance as mt

INFO = {
    "disks": [{"id": "sata1", "device": "/dev/sata1", "longName": "Drive 3", "model": "WD30EFRX", "unc": 0},
              {"id": "sata4", "device": "/dev/sata4", "longName": "Drive 2", "model": "WD30EFRX", "unc": 5},
              {"id": "sata3", "device": "/dev/sata3", "longName": "Drive 1", "model": "MG10ADA400E", "unc": 0}],
    "storagePools": [{"id": "reuse_3", "raidType": "multiple", "scrubbingStatus": "ready",
                      "is_scheduled": False, "disks": ["sata3"]},
                     {"id": "reuse_2", "raidType": "single", "deploy_path": "volume_1",
                      "scrubbingStatus": "schedule_paused", "is_scheduled": True,
                      "disks": ["sata1", "sata4"]}],
    "volumes": [{"id": "volume_1", "vol_path": "/volume1"}],
}


class DSM:
    def __init__(self, testing=False, state="schedule_paused"):
        self.calls, self.testing, self.state = [], testing, state

    def request(self, api, method, version=None, **params):
        p = {k: json.loads(v) for k, v in params.items()}
        self.calls.append((api, method, p))
        if method == "load_info":
            return INFO
        if method == "get_smart_test_log":
            return {"latest_test_time": "", "testInfo": [{
                "device": p["device"], "extendTime": " 400", "quickTime": "   2",
                "testing": self.testing, "remain": "20%" if self.testing else "",
                "latest_test_result": "completed", "latest_test_type": 2}]}
        if method == "get_state":
            return {"state": self.state}
        return {}


def test_disk_names_match_dsm_labels():
    assert mt.find_disk(INFO, "Drive 2")["id"] == "sata4"   # Drive 2 is sata4, not sata2
    assert mt.find_disk(INFO, "2")["id"] == "sata4"
    assert mt.find_disk(INFO, "/dev/sata1")["longName"] == "Drive 3"
    with pytest.raises(ValueError, match="Disks:"):
        mt.find_disk(INFO, "sata9")


def test_smart_test_calls_storage_manager_api():
    d = DSM()
    r = mt.smart_test(d, "Drive 2", "extended")
    assert d.calls[-1] == ("SYNO.Core.Storage.Disk", "do_smart_test", {"device": "/dev/sata4", "type": "extend"})
    assert r["expected_minutes"] == 400 and r["disk"] == "Drive 2"
    with pytest.raises(ValueError, match="already running"):
        mt.smart_test(DSM(testing=True), "Drive 2", "quick")
    d = DSM(testing=True)
    mt.smart_test(d, "sata4", "stop")
    assert d.calls[-1][2]["type"] == "stop"
    with pytest.raises(ValueError):
        mt.smart_test(DSM(), "Drive 2", "format")


def test_smart_status_summary():
    st = mt.smart_status(DSM(testing=True), "Drive 2")[0]
    assert st == {"disk": "Drive 2", "id": "sata4", "model": "WD30EFRX", "testing": True,
                  "remaining": "20%", "last_result": "completed", "last_type": "extended",
                  "last_test_time": None, "minutes_quick": 2, "minutes_extended": 400,
                  "unreadable_sectors": 5}


def test_scrubbing_uses_the_right_api():
    d = DSM()
    r = mt.scrubbing_start(d, "volume1")
    assert r["pool"] == "reuse_2"
    assert d.calls[-1] == ("SYNO.Storage.CGI.Volume", "data_scrubbing", {"space_id": "reuse_2", "force": False})
    d = DSM(state="ready")
    mt.scrubbing_start(d, "reuse_3")
    assert d.calls[-1][0] == "SYNO.Storage.CGI.Pool"
    with pytest.raises(ValueError, match="already running"):
        mt.scrubbing_start(DSM(state="manual_running"), "reuse_2")
    d = DSM()
    mt.scrubbing_schedule_resume(d)
    assert d.calls[-1] == ("SYNO.Storage.CGI.Storage", "set_data_scrubbing_schedule_status",
                           {"schedule_status": "0"})
    st = mt.scrubbing_status(DSM())
    assert [(s["pool"], s["volume"], s["state"]) for s in st] == [
        ("reuse_3", None, "schedule_paused"), ("reuse_2", "/volume1", "schedule_paused")]
