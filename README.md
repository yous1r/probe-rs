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
