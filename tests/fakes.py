"""A fake Docker API and DSM, replaying the 7.11 repair session."""

from __future__ import annotations

import json
import struct
import time

import httpx

NOW = time.time()


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".123456789Z"


def mux(text: str) -> bytes:
    out = b""
    for line in text.splitlines(keepends=True):
        b = line.encode()
        out += bytes([1, 0, 0, 0]) + struct.pack(">I", len(b)) + b
    return out


T_UPDATE = NOW - 3 * 3600
T_QB_STOP = NOW - 26 * 3600

WATCHTOWER_LOG = "\n".join([
    f'{iso(T_QB_STOP)} time="{iso(T_QB_STOP)[:19]}Z" level=info msg="Found new linuxserver/qbittorrent:latest image (sha256:aaa111)"',
    f'{iso(T_QB_STOP)} time="{iso(T_QB_STOP)[:19]}Z" level=info msg="Stopping /qbittorrent (1234abcd) with SIGTERM"',
    f'{iso(T_QB_STOP)} time="{iso(T_QB_STOP)[:19]}Z" level=error msg="Error response from daemon: Conflict"',
    f'{iso(T_QB_STOP)} time="{iso(T_QB_STOP)[:19]}Z" level=info msg="Session done" Failed=1 Scanned=12 Updated=0 notify=no',
    f'{iso(T_UPDATE)} time="{iso(T_UPDATE)[:19]}Z" level=info msg="Found new rclone/rclone:latest image (sha256:bbb222)"',
    f'{iso(T_UPDATE)} time="{iso(T_UPDATE)[:19]}Z" level=info msg="Stopping /rclone (5678efgh) with SIGTERM"',
    f'{iso(T_UPDATE)} time="{iso(T_UPDATE)[:19]}Z" level=info msg="Creating /rclone"',
    f'{iso(T_UPDATE)} time="{iso(T_UPDATE)[:19]}Z" level=info msg="Session done" Failed=0 Scanned=12 Updated=1 notify=no',
]) + "\n"

RCLONE_LOG = "".join(
    f"{iso(NOW - 60 * i)} 2026/11/07 10:{i:02d}:00 CRITICAL: Failed to start remote control: "
    f"--rc-web-gui has been superseded by the `rclone gui` command\n" for i in range(12, 0, -1))
FB_LOG = f"{iso(NOW - 500)} 2026/11/07 open /srv: permission denied\n"


def _c(cid, name, image, state, status, project=None, ports=None):
    labels = {"com.docker.compose.project": project} if project else {}
    return {"Id": cid, "Names": [f"/{name}"], "Image": image, "State": state, "Status": status,
            "Labels": labels, "Ports": ports or []}


CONTAINERS = [
    _c("1234abcd" * 8, "qbittorrent", "linuxserver/qbittorrent:latest", "exited", "Exited (143) 26 hours ago",
       ports=[{"PublicPort": 8090, "PrivatePort": 8090, "Type": "tcp"}]),
    _c("5678efgh" * 8, "rclone", "rclone/rclone:latest", "restarting", "Restarting (1) 5 seconds ago",
       project="rclone-rclone-1"),
    _c("9999aaaa" * 8, "filebrowser-1", "filebrowser/filebrowser:latest", "exited", "Exited (1) 1 hour ago"),
    _c("7777bbbb" * 8, "seerr", "ghcr.io/seerr-team/seerr:latest", "running", "Up 2 days", project="seerr"),
    _c("8888cccc" * 8, "watchtower", "nickfedor/watchtower:latest", "running", "Up 7 days", project="wt"),
]

INSPECT = {
    "qbittorrent": {"Name": "/qbittorrent", "Image": "sha256:old", "RestartCount": 0,
                    "Created": iso(NOW - 90 * 86400),
                    "State": {"Status": "exited", "ExitCode": 143, "OOMKilled": False,
                              "StartedAt": iso(NOW - 40 * 86400), "FinishedAt": iso(T_QB_STOP + 20),
                              "Error": ""},
                    "HostConfig": {"RestartPolicy": {"Name": "no"}},
                    "Config": {"Image": "linuxserver/qbittorrent:latest", "Labels": {}, "Cmd": [], "Env": []},
                    "Mounts": []},
    "rclone": {"Name": "/rclone", "Image": "sha256:bbb222", "RestartCount": 40,
               "Created": iso(T_UPDATE + 5),
               "State": {"Status": "restarting", "ExitCode": 1, "StartedAt": iso(NOW - 5),
                         "FinishedAt": iso(NOW - 6)},
               "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
               "Config": {"Image": "rclone/rclone:latest",
                          "Labels": {"com.docker.compose.project": "rclone-rclone-1"},
                          "Cmd": ["rcd", "--rc-web-gui", "--rc-addr", ":5572", "--rc-no-auth"], "Env": []},
               "Mounts": [{"Source": "/volume1/docker/Rclone/config", "Destination": "/config/rclone", "RW": True}]},
    "filebrowser-1": {"Name": "/filebrowser-1", "Image": "sha256:fb", "RestartCount": 0,
                      "Created": iso(NOW - 200 * 86400),
                      "State": {"Status": "exited", "ExitCode": 1, "StartedAt": iso(NOW - 600),
                                "FinishedAt": iso(NOW - 500)},
                      "HostConfig": {"RestartPolicy": {"Name": "no"}},
                      "Config": {"Image": "filebrowser/filebrowser:latest", "Labels": {}, "Cmd": [], "Env": []},
                      "Mounts": []},
    "seerr": {"Name": "/seerr", "Image": "sha256:se", "RestartCount": 0, "Created": iso(NOW - 8 * 86400),
              "State": {"Status": "running", "ExitCode": 0, "StartedAt": iso(NOW - 2 * 86400),
                        "FinishedAt": "0001-01-01T00:00:00Z"},
              "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
              "Config": {"Image": "ghcr.io/seerr-team/seerr:latest",
                         "Labels": {"com.docker.compose.project": "seerr"},
                         "Cmd": [], "Env": ["DB_PASSWORD=hunter2"]},
              "Mounts": []},
    "watchtower": {"Name": "/watchtower", "Image": "sha256:wt", "RestartCount": 0, "Created": iso(NOW - 8 * 86400),
                   "State": {"Status": "running", "ExitCode": 0, "StartedAt": iso(NOW - 7 * 86400),
                             "FinishedAt": "0001-01-01T00:00:00Z"},
                   "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
                   "Config": {"Image": "nickfedor/watchtower:latest",
                              "Labels": {"com.docker.compose.project": "wt"}, "Cmd": [], "Env": []},
                   "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}]},
}
LOGS = {"rclone": RCLONE_LOG, "filebrowser-1": FB_LOG, "watchtower": WATCHTOWER_LOG,
        "seerr": f"{iso(NOW - 100)} Server ready on port 5055\n", "qbittorrent": ""}

BY_ID = {c["Id"]: c["Names"][0].lstrip("/") for c in CONTAINERS}


def handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if request.method != "GET":
        return httpx.Response(403, text="POST disabled")
    if path == "/containers/json":
        return httpx.Response(200, json=CONTAINERS)
    if path.startswith("/containers/"):
        ident, _, what = path[len("/containers/"):].partition("/")
        name = BY_ID.get(ident, ident)
        if name not in INSPECT:
            return httpx.Response(404, json={"message": "no such container"})
        if what == "json":
            return httpx.Response(200, json=INSPECT[name])
        if what == "logs":
            tail = int(request.url.params.get("tail", "100"))
            text = "\n".join(LOGS.get(name, "").splitlines()[-tail:]) + "\n"
            return httpx.Response(200, content=mux(text))
    if path.startswith("/images/"):
        return httpx.Response(200, json={"Created": iso(T_UPDATE - 3600),
                                         "Config": {"Labels": {"org.opencontainers.image.version": "1.74.0"}}})
    if path == "/events":
        ev = {"Type": "container", "Action": "die", "time": int(NOW - 10),
              "Actor": {"ID": "5678efgh", "Attributes": {"name": "rclone", "exitCode": "1",
                                                         "image": "rclone/rclone:latest"}}}
        return httpx.Response(200, content=(json.dumps(ev) + "\n").encode())
    return httpx.Response(404, json={"message": "unknown"})


TRANSPORT = httpx.MockTransport(handler)


class FakeDSM:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def try_request(self, api, method, versions=None, **params):
        if api == "SYNO.DSM.Info":
            return {"model": "DS920+", "version_string": "DSM 7.4.1", "ram": 12288,
                    "temperature": 48, "uptime": 272000}
        if api == "SYNO.Core.System.Utilization":
            return {"cpu": {"user_load": 5, "system_load": 3, "other_load": 1, "1min_load": 40},
                    "memory": {"total_real": 12_000_000, "avail_real": 3_000_000, "cached": 4_000_000,
                               "buffer": 500_000, "swap_usage": 2}}
        if api == "SYNO.Storage.CGI.Storage":
            return {"disks": [{"id": "sata1", "longName": "Drive 1", "model": "WD80EFZZ", "temp": 41,
                               "status": "normal", "smart_status": "normal", "unc": 0, "size_total": 8e12},
                              {"id": "sata2", "longName": "Drive 2", "model": "WD80EFZZ", "temp": 57,
                               "status": "normal", "smart_status": "normal", "unc": 3, "size_total": 8e12}],
                    "storagePools": [{"id": "reuse_1", "device_type": "shr_with_1_disk_protect",
                                      "status": "normal"}],
                    "volumes": [{"id": "volume_1", "vol_path": "/volume1", "fs_type": "btrfs",
                                 "status": "normal", "size": {"total": "8000000000000",
                                                              "used": "6800000000000"}}]}
        from nasmcp.dsm import DSMError
        raise DSMError(f"DSM error 102: {api}")
