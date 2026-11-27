# rprobe

Rust-based fleet probe. The first development slice targets milestone M1: host telemetry collection, authenticated agent ingest, live overview, and group-based display.

## Workspace

- `crates/common`: versioned JSON protocol and shared data structures.
- `crates/agent`: small synchronous agent using `/proc`, cgroup, and OpenVZ counters.
- `crates/server`: Tokio/Axum ingest, a SQLite registry and latest reports, an in-memory dashboard cache, SSE, and group APIs.

## Development run

Configure the server with a 0600 agent credential file (one `id=token` per line) and a separate 0600 dashboard token file:

```sh
RPROBE_AGENT_TOKENS_FILE=/etc/rprobe/agents.tokens \
RPROBE_ADMIN_TOKEN_FILE=/etc/rprobe/admin.token \
RPROBE_DB_PATH=/var/lib/rprobe/rprobe.sqlite \
cargo run -p rprobe-server
```

By default the server listens on `127.0.0.1:8080`. Put it behind an HTTPS reverse proxy for production; the agent uses `wss://` at `/ws/agent` and falls back to HTTPS POST at `/api/report` on the same server. Plain HTTP is accepted by the agent only for loopback development.

Create one token per agent. Store it in a file readable only by the agent's service account (`chmod 600 /etc/rprobe/agent.token`), then run:

```sh
cargo run -p rprobe-agent -- \
  --server https://monitor.example.com \
  --id node-a \
  --token-file /etc/rprobe/agent.token \
  --group free
```

The agent refuses token files that are group/world accessible on Unix. Passing a token directly on the command line is disabled because process listings can expose arguments.

Open `/` and enter the administrator token to load the dashboard. All dashboard APIs, including `/api/events`, require this token. Groups can be created with `POST /api/groups` and hosts reassigned with `PATCH /api/hosts/{id}/group`, both using `Authorization: Bearer <admin-token>`. See [communication and security](docs/communication-security.md) for limits, TLS setup, token rotation, and remaining boundaries.

## M1 boundaries

Registered hosts, groups, manual assignments, latest accepted reports and their receive times are persisted in a local SQLite file (WAL, synchronous FULL). Each successful write commits before the cache is updated. Restarting restores these records; hosts remain offline until a new report is accepted. Credential files remain the authority for agent access. Database failure stops startup or returns a write error; it never silently falls back to memory. Historical time series/downsampling, alerts, active probes and asset/renewal management remain later milestones.

Set `RPROBE_DB_PATH` explicitly for services; the development default is `./rprobe.sqlite`. Use a durable directory owned by the server account, mode 0700, and database files mode 0600. On systemd, `StateDirectory=rprobe`, `StateDirectoryMode=0700` and `RPROBE_DB_PATH=/var/lib/rprobe/rprobe.sqlite` keep the database writable under `ProtectSystem=strict`. For backups, stop the server and copy the database plus any `-wal`/`-shm` sidecars together, or use the SQLite backup API. A copy of only the main file while WAL writes are active is not a valid backup procedure.

`scripts/verify_persistence.py` starts the prebuilt server, creates registered hosts/groups, forces SIGKILL, restarts against the same database and verifies restoration without an agent reconnect. It also tests explicit ungrouping, duplicate-report liveness, and rejection of corrupt/volatile database paths. CI runs this alongside the security checks.

## GitHub CI and Linux validation

Linux binaries are built on [GitHub Actions](https://github.com/yous1r/probe-rs/actions/workflows/linux-ci.yml), not on the validation VPS. Each run checks formatting, Clippy, and unit tests on `x86_64-unknown-linux-musl`, then uploads two independently downloadable artifacts:

| Actions artifact | Archive | Executable |
| --- | --- | --- |
| `rprobe-agent-x86_64-unknown-linux-musl` | `rprobe-agent-x86_64-unknown-linux-musl.tar.gz` | `rprobe-agent` |
| `rprobe-server-x86_64-unknown-linux-musl` | `rprobe-server-x86_64-unknown-linux-musl.tar.gz` | `rprobe-server` |

Each archive contains only its own static executable, plus `COMMIT`, `TOOLCHAIN.txt`, `BINARIES.txt`, and `SHA256SUMS`. Download the required artifact from the intended workflow run; GitHub wraps the `.tar.gz` in an artifact ZIP. Extract the ZIP, then unpack the `.tar.gz` into its own directory and run `sha256sum -c SHA256SUMS` there. Confirm that `COMMIT` matches the intended revision before running.

For the joint validation scripts below, download both packages from the same run and verify them in separate directories so their metadata does not overwrite each other. Copy the two executables into one directory, such as `/path/to/artifact`, and pass that directory as `--bin-dir`. Python 3.10+ and the repository's scripts are required:

```sh
python3 scripts/verify_linux.py --bin-dir /path/to/artifact --output-dir /tmp/rprobe-check \
  --sample-secs 30 --outage-secs 120
```

The script starts temporary agent/server processes on random loopback ports and checks authentication, real metrics, grouping, offline state, HTTP fallback, process resource usage, and WebSocket replay after a 120-second listener outage. A failed check produces a nonzero exit code and JSON details. It does not build, install, or modify existing services.

For a separate 256 MiB / 0.1 CPU check on a systemd host with passwordless sudo:

```sh
python3 scripts/verify_limits.py --bin-dir /path/to/artifact --output-dir /tmp/rprobe-limits \
  --sample-secs 60
```

This uses a temporary systemd unit and removes it after the test. CPU results include both percent of one logical CPU and percent of the 0.1-CPU allowance. These loopback tests do not validate TLS termination or Linux 2.6.32 compatibility.

The collection and transport design was compared with [ServerStatus-Rust](https://github.com/zdz/ServerStatus-Rust), especially its interface filtering and bounded network timeouts. rprobe retains its direct procfs/cgroup collector and synchronous transport to match its memory and legacy-kernel constraints; no implementation source was copied.

For an agent installed as a dedicated systemd service to monitor the whole VPS/container, set `RPROBE_CGROUP_SCOPE=mount` in that service. This reads counters and quotas at the mounted cgroup root instead of the agent service's child cgroup. The default `process` scope remains suitable for agents embedded in application containers. Use `mount` only when the mount root represents the machine/container you intend to monitor.

The server holds an exclusive `.lock` file beside the SQLite file for its lifetime; only one server process may use a registry. Do not remove that lock file while the server is running. Unknown SQLite schemas or versions are rejected before changing journal mode.
