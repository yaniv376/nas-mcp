# nas-mcp

An MCP server that lets Claude look after a Synology NAS: system health,
disks and volumes, Docker containers (state, logs, diagnosis), Watchtower
update history, backups, and the [NAS gate](https://github.com/yaniv376/nas-gate)
security scan.

**Read-only so far (stages 1a and 1b).** Nothing here can change the NAS:
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

## Roadmap

- 1c: write tools behind an "MCP" window in the NAS gate, phone approval for
  destructive actions, nothing ever deleted (renamed `_to_delete_…`)
- 1d: post-update checks with a one-tap rollback, NAS health scan
- 2: media apps (Seerr, Radarr, Sonarr, Jellyfin)

## Development

```
pip install -r requirements.txt pytest
python -m pytest -q
```
