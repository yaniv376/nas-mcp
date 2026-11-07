# nas-mcp

An MCP server that lets Claude look after a Synology NAS: system health,
disks and volumes, Docker containers (state, logs, diagnosis), Watchtower
update history, backups, and the [NAS gate](https://github.com/yaniv376/nas-gate)
security scan.

**Reads always; changes only while the NAS gate's "Agent (MCP)" window is open.** Nothing here can change the NAS:
Docker is reached through a socket proxy with POST disabled, and mounted
folders are read-only.

## Tools

| Tool | What it answers |
| --- | --- |
| `nas_overview` | How is the NAS? (everything below, summarised) |
| `nas_system` | Model, DSM version, uptime, temperature, CPU, memory |
| `nas_storage` | Disks (SMART, temperature, bad sectors), pools, volumes |
| `containers_list` | Every container with state, image, project, ports |
| `container_details` | One container: exit code and meaning, restarts, mounts, last update |
| `container_logs` | The container's log, secrets redacted |
| `container_diagnose` | Problems and suggested fixes (see below) |
| `watchtower_history` | What Watchtower updated or stopped, and when |
| `nas_timeline` | Starts, stops, crashes, OOM kills, pulls and updates over time |
| `backups_status` | Newest file per backup target, late or not |
| `security_scan` / `gate_status` | From the NAS gate, if configured |
| `folders_list`, `files_list`, `file_read`, `files_search` | Allowed folders only |

### What `container_diagnose` finds

- crash loops and errors that repeat in the log
- containers stopped with no visible cause, matched against Watchtower's own log
  (Container Manager does not show what Watchtower does)
- breakage that started right after a Watchtower update, with a rollback suggestion
- permission errors (suggests `user: "1026:100"`), ports in use, missing bind folders,
  options a new version removed, wrong architecture, full disk, out of memory
- no restart policy, standalone containers (suggests a Compose project), `:latest` tags
- services without a password, privileged mode, unmaintained images

Docker forgets past events when it restarts, so a small recorder keeps its
own log in `data/events.jsonl` for `nas_timeline`.

## Install (Container Manager)

1. Create a DSM administrator user for the server (2-step verification off for it).
2. Create the folder `/volume1/docker/nas-mcp` and inside it a folder `data`.
3. Put `docker-compose.yml` in it, `.env.example` as `.env`, and
   `config.example.yaml` as `data/config.yaml`; fill them in.
4. Container Manager → Project → Create → path `/volume1/docker/nas-mcp`.
5. Open `http://<nas>:8790/?token=<your token>` for the status page.

Everything specific to one NAS lives in `data/config.yaml` and `.env`,
never in this repository.

## Connecting Claude from anywhere (stage 1b)

1. Give the server a public HTTPS address without opening router ports, for example
   Tailscale Funnel on the NAS: `tailscale funnel --bg 8790`.
2. Set `NASMCP_PUBLIC_URL` to that address and configure notifications
   (`NASMCP_NOTIFY_MODE=ha` with `NASMCP_HA_URL`, `NASMCP_HA_TOKEN`,
   `NASMCP_HA_NOTIFY_SERVICE`, or `webhook`).
3. In Claude add a custom connector with `<public url>/mcp`.
4. Claude registers itself and opens a page with a 4-digit code; your phone gets a
   notification with Approve / Deny buttons. Tokens are stored only as hashes,
   access tokens last 8 hours and rotate through refresh tokens.

## Changes (stage 1c)

| Tool | Does |
| --- | --- |
| `container_control` | start / stop / restart |
| `container_set_auto_restart` | restart policy (unless-stopped by default) |
| `container_retire` | stop, no auto-restart, rename `to_delete_<name>`; phone approval |
| `compose_write` / `compose_restore` | edit a project's Compose file, validated, with backups |
| `project_run` | Container Manager project stop / build / start / restart |
| `projects_list`, `compose_backups`, `actions_log` | read-only helpers |

Every change asks the gate first and fails closed, is logged to
`data/actions.jsonl`, and never deletes anything. `nas-mcp`, its Docker proxy
and `nas-gate` can never be stopped or retired from here.

## After every update (stage 1d)

A watcher notices when a container starts running a new image (Watchtower or a
rebuild), checks it 5 minutes later (crash loop, stopped, repeated errors), and if
it is broken sends an alert with **Roll back** / **Ignore** (phone push and Home
Assistant's notification panel). Rollback recreates the container with the same
settings and the previous image (keep Watchtower's cleanup off), labels it so
Watchtower leaves it alone, pins the image by digest in its Compose file, and
renames the broken one `to_delete_<name>_broken_<time>`. Tapping the alert is the
approval; from chat, `update_rollback` needs the agent window.

`nas_health_scan` (and `GET /api/health` for Home Assistant) scores disks, space,
data scrubbing, disk protection, DSM updates, backups, containers and broken updates.

## Roadmap

- 1c: write tools behind an "MCP" window in the NAS gate, phone approval for
  destructive actions, nothing ever deleted (renamed `_to_delete_…`)
- 2: media apps (Seerr, Radarr, Sonarr, Jellyfin)

## Development

```
pip install -r requirements.txt pytest
python -m pytest -q
```
