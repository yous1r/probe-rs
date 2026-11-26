# rprobe

Rust-based fleet probe. The first development slice targets milestone M1: host telemetry collection, authenticated agent ingest, live overview, and group-based display.

## Workspace

- `crates/common`: versioned JSON protocol and shared data structures.
- `crates/agent`: small synchronous agent using `/proc`, cgroup, and OpenVZ counters.
- `crates/server`: Tokio/Axum ingest server, live in-memory state, SSE dashboard, and group APIs.

## Development run

Configure the server with an agent ID/token pair and a separate dashboard token:

```sh
RPROBE_AGENT_TOKENS='node-a=replace-with-a-long-random-token' \
RPROBE_ADMIN_TOKEN='replace-with-another-long-random-token' \
cargo run -p rprobe-server
```

By default the server listens on `127.0.0.1:8080`. Put it behind an HTTPS reverse proxy for production; the agent uses `wss://` and the server accepts the upgraded WebSocket at `/ws/agent`. Plain HTTP report fallback is available at `/api/report`.

Run an agent with the matching identity and token:

```sh
cargo run -p rprobe-agent -- \
  --server https://monitor.example.com \
  --id node-a \
  --token replace-with-a-long-random-token \
  --group free
```

Open `/` and enter `RPROBE_ADMIN_TOKEN` to load the dashboard. Groups can be created with `POST /api/groups` and hosts reassigned with `PATCH /api/hosts/{id}/group`, both using `Authorization: Bearer <admin-token>`.

## M1 boundaries

The current slice keeps latest host state and groups in memory; restarting the server clears them. Historical storage/downsampling, alert delivery, active probes, advanced asset/renewal management, and persistent configuration are later milestones. Authentication is required for dashboard data and group changes. TLS termination, durable secrets, and network exposure controls belong in the deployment layer.

## GitHub CI and Linux validation

Linux binaries are built on [GitHub Actions](https://github.com/yous1r/probe-rs/actions/workflows/linux-ci.yml), not on the validation VPS. Each run checks formatting, Clippy, and unit tests on `x86_64-unknown-linux-musl`, then uploads a release archive containing both static binaries, `COMMIT`, build information, and `SHA256SUMS`.

Download the artifact for the intended commit and unpack it on the test host. Verify `sha256sum -c SHA256SUMS` and `COMMIT` before running. With Python 3.10+ and the repository's scripts available:

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
