# Tuyau — MVP Plan

## How to Use This Document

This is the **MVP plan** for Tuyau: connect a client to a server over QUIC with a pre-shared token. Nothing more.

When asked to work on a milestone:

1. Read the milestone requirements
2. Implement all checkboxes
3. Write all specified tests
4. Run `cargo test` for the affected crates — must pass
5. Run `cargo clippy --workspace --all-targets -- -D warnings` — must be clean
6. Run `cargo fmt --all`
7. Commit referencing the milestone (e.g. `M2: server accepts QUIC + validates token`)
8. **STOP.** Do not proceed unless asked.

## What is the MVP?

A tuyau server listens on a UDP port for QUIC connections from authenticated clients. Each client presents a pre-shared token. Server config lists the accepted tokens. Successful handshake = connection established and held open. That's it.

No public HTTP listener. No hostname registration. No data plane. No reconnect logic. No multi-client. No ACME. No TLS termination beyond what QUIC mandates internally.

The point: prove the bottom layer works in a single sandbox VM. Iterations after the MVP add the rest.

## Configs

Single TOML file per side. No external files needed in default mode.

### `server.toml`

```toml
listen_addr = "0.0.0.0:4433"
# tunnel_cert_dir = "/var/lib/tuyau"   # optional; defaults to the directory of the --config file
# Auto-generated tunnel-cert.pem + tunnel-key.pem live there.

[[clients]]
name = "service-a"
token = "<32-byte hex>"

[[clients]]
name = "service-b"
token = "<32-byte hex>"
```

### `client.toml`

```toml
server_addr = "127.0.0.1:4433"          # or tunnel.example.com:4433
server_cert_fingerprint_sha256 = "<64 hex chars>"  # printed by server on startup
token = "<32-byte hex>"
client_name = "service-a"
```

## Architecture

```
client.toml ──► tuyau client ──QUIC──► tuyau server ◄── server.toml
                                          │
                                          └── validates token against clients[].token
```

That's the whole picture for the MVP.

## Tech Stack

| Layer        | Crate                            |
| ------------ | -------------------------------- |
| QUIC         | `quinn` 0.11                     |
| TLS (in QUIC)| `rustls` 0.23                    |
| Cert gen     | `rcgen`                          |
| Serialization| `serde` + `ciborium` (CBOR)      |
| Framing      | `tokio-util` (LengthDelimited)   |
| Async        | `tokio`                          |
| CLI          | `clap` 4 (derive)                |
| Config       | `toml` + `serde`                 |
| Logging      | `tracing` + `tracing-subscriber` |
| Errors       | `thiserror` (libs), `anyhow` (bin)|
| Constant-time| `subtle`                         |
| Random       | `rand`                           |

## Repo Layout

```
tuyau/
├── Cargo.toml             (workspace)
├── README.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── plan.md
├── .github/workflows/ci.yml
├── crates/
│   ├── tuyau-protocol/    Hello/Welcome frames + CBOR codec
│   ├── tuyau-server/      QUIC listener + token validation
│   ├── tuyau-client/      QUIC dialer + token send
│   └── tuyau-cli/         Binary `tuyau` with `server` and `client` subcommands
└── crates/tuyau-cli/tests/
    └── integration.rs     End-to-end handshake test
```

## Wire Protocol (MVP)

Two frames, exchanged on the first bidi stream of the QUIC connection:

```rust
pub struct Hello {
    pub token: [u8; 32],     // raw bytes on the wire; hex in TOML
    pub client_name: String, // informational, for server logs
}

pub enum HelloResponse {
    Welcome,
    Reject { reason: String }, // free-form, server-controlled, debug-friendly
}
```

Encoding: each frame is a u32 big-endian length prefix followed by ciborium-encoded CBOR. Max frame size 64 KiB (this is a tiny handshake).

After Welcome: connection stays open (server holds it; future iterations will use it). Client logs "connected" and waits.

**Connection liveness**: QUIC-level keep-alive only — no application heartbeat. Both sides set `keep_alive_interval = 15s` and `max_idle_timeout = 60s` on `quinn::TransportConfig`. If the connection drops (network failure, peer exit), both sides notice via QUIC and exit. No reconnect.

---

# Implementation Plan

## M0 — Workspace setup

- [ ] Workspace `Cargo.toml` with members `tuyau-protocol`, `tuyau-server`, `tuyau-client`, `tuyau-cli`
- [ ] Each crate has `Cargo.toml` and `src/lib.rs` (or `src/main.rs` for `tuyau-cli`)
- [ ] `tuyau-cli` declares a binary named `tuyau` via `[[bin]]`
- [ ] `[workspace.dependencies]` populated with all deps from the Tech Stack table
- [ ] `LICENSE-MIT` and `LICENSE-APACHE` at the repo root
- [ ] `README.md` with one paragraph + "status: pre-alpha"
- [ ] `.github/workflows/ci.yml`: matrix `os: [ubuntu-latest, macos-latest]` (macos-latest = Apple Silicon), running `cargo build --workspace`, `cargo test --workspace`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `.gitignore` for Rust + editor artifacts + `*.pem`

**Test**: `cargo build --workspace` and `cargo test --workspace` succeed. CI green on a push.

---

## M1 — `tuyau-protocol`

Frames + codec. No networking.

- [ ] Define `Hello`, `HelloResponse` with serde derives
- [ ] Define `FrameCodec<F>` impl `tokio_util::codec::Encoder<F>` and `Decoder<Item = F>` for any `F: Serialize + DeserializeOwned`:
  - 4-byte big-endian length prefix
  - Max frame 64 KiB (constant)
  - Payload encoded with ciborium
- [ ] Define `ProtocolError` (`thiserror`): `Io`, `Cbor`, `OversizedFrame`
- [ ] Constants: `ALPN: &[u8] = b"tuyau/0"` (used as quinn ALPN), `MAX_FRAME_SIZE: usize = 64 * 1024`

**Tests**:
- [ ] Round-trip serialize/deserialize `Hello`
- [ ] Round-trip every variant of `HelloResponse`
- [ ] Codec handles split reads (bytes arriving across multiple `decode` calls)
- [ ] Codec rejects an oversized frame
- [ ] `cargo test -p tuyau-protocol` passes

---

## M2 — `tuyau-server`: accept QUIC + validate token

Server-side: listen, accept, read Hello, validate, respond.

- [ ] Define `ServerConfig` matching `server.toml` schema:
  ```rust
  pub struct ServerConfig {
      pub listen_addr: SocketAddr,
      pub tunnel_cert_dir: Option<PathBuf>, // defaults to dir of --config file
      pub clients: Vec<ClientEntry>,
  }
  pub struct ClientEntry {
      pub name: String,
      pub token: [u8; 32], // 64-hex-chars in TOML, parsed via custom deserialize_with
  }
  ```
- [ ] Cert handling: load `<tunnel_cert_dir>/tunnel-cert.pem` + `tunnel-key.pem`; if missing, generate via `rcgen` (CN = "tuyau-tunnel", validity 10 years, EC P-256) and persist (key file with mode 0600 on Unix)
- [ ] Compute SHA-256 fingerprint of the cert DER, log at INFO at startup so it can be copied into a client config
- [ ] Build quinn server config with rustls, ALPN = `tuyau/0`, bound to `listen_addr`. Set `TransportConfig::keep_alive_interval = Some(15s)` and `max_idle_timeout = Some(60s)`.
- [ ] Accept loop: per incoming connection, spawn a task that:
  1. Awaits `connection.accept_bi()` for the first bidirectional stream (5s timeout)
  2. Wraps the recv half in `FrameCodec<Hello>` and send half in `FrameCodec<HelloResponse>`
  3. Reads exactly one `Hello` frame
  4. Validates `hello.token` (`[u8; 32]`) against `config.clients[].token` using `subtle::ConstantTimeEq`
  5. On match: logs `INFO "client connected" name=<matched_name>`, sends `HelloResponse::Welcome`, holds the connection open
  6. On no match: sends `HelloResponse::Reject { reason: "invalid token" }`, closes
  7. On bad frame / timeout: sends `Reject { reason: "protocol error" }`, closes
- [ ] Public API: `TunnelServer::start(config: ServerConfig) -> Result<TunnelServer>` returning a handle. `TunnelServer::shutdown()` closes the endpoint gracefully.

**Tests** (in `crates/tuyau-server/tests/`):
- [ ] Spin up server in-process on port 0, get assigned port back from the handle
- [ ] Connect a raw quinn client, complete TLS, open bi stream, send valid Hello → receive Welcome
- [ ] Send Hello with wrong token → receive `Reject { InvalidToken }`
- [ ] Send malformed bytes on the stream → receive `Reject { ProtocolError }` (or connection closes)
- [ ] Don't send anything → connection closed by server after 5s timeout
- [ ] Start server twice with the same `tunnel_cert_dir`, fingerprint stable across runs
- [ ] Connect with a wrong ALPN → rustls rejects the handshake
- [ ] `cargo test -p tuyau-server` passes

---

## M3 — `tuyau-client`: dial QUIC + send token

Client-side: connect, send Hello, read response.

- [ ] Define `ClientConfig` matching `client.toml` schema:
  ```rust
  pub struct ClientConfig {
      pub server_addr: String,                       // host:port
      pub server_cert_fingerprint_sha256: [u8; 32],  // 64 hex chars in TOML → [u8; 32] via custom deserialize_with
      pub token: [u8; 32],                            // same hex → [u8; 32] custom deserializer
      pub client_name: String,
  }
  ```
- [ ] Build quinn client config with rustls; install a custom `ServerCertVerifier` that:
  - Computes SHA-256 of the leaf cert DER
  - Compares to `server_cert_fingerprint_sha256` with constant-time compare
  - Returns Ok if match, error otherwise (no PKI chain validation)
- [ ] ALPN = `tuyau/0`. Set `TransportConfig::keep_alive_interval = Some(15s)` and `max_idle_timeout = Some(60s)`.
- [ ] Resolve `server_addr` (DNS), dial, complete TLS
- [ ] Open first bidi stream
- [ ] Send `Hello { token, client_name }`
- [ ] Read `HelloResponse` (5s timeout)
- [ ] On `Welcome`: log INFO "connected", hold the connection. Stay alive until the connection closes (peer-initiated or local Ctrl-C).
- [ ] On `Reject { reason }`: log the reason, exit non-zero
- [ ] On any other error: log, exit non-zero
- [ ] Public API: `TunnelClient::connect(config: ClientConfig) -> Result<TunnelClient>` returning a handle that resolves when the connection ends. `TunnelClient::shutdown()` for graceful close.

**Tests** (in `crates/tuyau-client/tests/`):
- [ ] Spin up the M2 server with a known token, connect a `TunnelClient` with that token → handshake succeeds, both sides log connection
- [ ] Wrong token → client receives Reject, exits non-zero
- [ ] Wrong fingerprint (bogus pinned fingerprint in client config) → connection fails at TLS verify
- [ ] Server unreachable (connect to closed port) → client returns a clear connection error
- [ ] `cargo test -p tuyau-client` passes

---

## M4 — `tuyau-cli`: binary + config loading

Tie it together into a runnable binary.

- [ ] `tuyau-cli/src/main.rs` with clap-derived CLI:
  ```
  tuyau server --config <PATH>
  tuyau client --config <PATH>
  ```
  Token bootstrap: `openssl rand -hex 32` (documented in README). Fingerprint bootstrap: server logs it at startup (M2). No utility subcommands in the MVP.
- [ ] Load TOML config via serde, fail-fast on validation errors with clear messages (which field, what's wrong)
- [ ] `tracing-subscriber` setup with `RUST_LOG` env-filter, default `info`
- [ ] On SIGINT/SIGTERM: call `shutdown()` on the running component, wait up to 2s, exit
- [ ] Sample configs in `examples/`:
  - `examples/server.toml`
  - `examples/client.toml`
  - Both runnable together; the README explains the bootstrap loop (run server once to get the fingerprint, paste it into client.toml)

**Tests** (in `tests/integration.rs`):
- [ ] Parse a sample server.toml and client.toml; verify config struct matches expectations
- [ ] Reject a config with empty `clients` list; reject malformed token (not 64 hex chars); reject malformed fingerprint hex
- [ ] **End-to-end smoke test**: in-process, launch `TunnelServer` + `TunnelClient` with matching token, verify they handshake successfully and both log "connected"

**MVP success criterion**: this end-to-end smoke test passes in CI on every push.

---

# Notes for Implementation

## Error Handling
- `thiserror` for library error types in each lib crate
- `anyhow` only in `tuyau-cli`
- Every config validation error names the field and explains the constraint

## Logging
- `tracing` everywhere with structured fields (`client_name`, `peer_addr`, `connection_id`)
- INFO at startup: server listen addr, tunnel cert fingerprint, count of configured clients
- INFO on connection: peer addr, matched client name (or "rejected: <reason>")
- DEBUG for frame send/receive

## Security
- Token comparison uses `subtle::ConstantTimeEq` on every byte
- Tokens never appear in logs, never in error messages
- Auto-generated cert key file has mode 0600 on Unix (best-effort on Windows)

## What's NOT in this plan
Everything beyond "client and server connect with a token." Out of scope, planned separately after MVP:

- HTTP request/response data plane
- Public HTTP listener on the server
- Hostname routing (static or dynamic)
- Heartbeat / keepalive
- Reconnect logic
- Multiple clients per hostname / load balancing
- Public TLS (rustls cert resolver, ACME, Let's Encrypt)
- Multi-POP
- CONNECT-TCP / arbitrary TCP forwarding
- Web UI / management API
- Metrics / Prometheus

---

# Phase 2 — Public data plane (M5+)

Phase 2 turns the QUIC tunnel from the MVP into a Cloudflare Tunnel-shaped reverse-proxy data plane: public listener on the server side, hostname-routed dispatch, forwarding to local services on the client side.

## Architecture decisions locked at the start of Phase 2

- **CF-style hostnames.** A client token = pure identity. The hostname-to-client binding lives entirely server-side, in `server.toml`'s top-level `[[hostnames]]` table. The client never claims or sends hostnames on the wire. Rationale: one source of truth, ergonomic for managed B2B, embed-friendly for the lib SDK use case.
- **Client config is flag/env-first.** TOML is opt-in via `--config`. Designed for Docker/Compose/k8s: secrets through `--token-file` or `TUYAU_TOKEN_FILE`, never a bare `--token <hex>` (would leak in `ps` and shell history).
- **Routing table is mutable at runtime in M5**, even if only populated from static config. Designed so M6 (dynamic config / hot reload / admin API) layers in without rework.
- **Last-write-wins per matched client name.** A reconnecting client kicks its previous active connection. Smooth container restarts, no `max_idle_timeout` wait.

## Milestone breakdown

| Milestone | What it ships                                                          |
| --------- | ---------------------------------------------------------------------- |
| M5a       | Server `[[hostnames]]` config + routing table on connect/disconnect + client CLI/env layer. No public listener yet. |
| M5b       | Public TCP/TLS listener + SNI/Host parsing + `DataStreamHeader` frame + dispatch QUIC stream. ALPN bumps to `tuyau/1`. |
| M5c       | Client accept loop + `[[ingress]]` mapping + forward to `local_addr`. First end-to-end HTTP. |
| M5d       | `axum::serve::Listener` adapter (lib-first API surface).               |
| M5e       | ACME / Let's Encrypt cert issuance per hostname.                       |
| M5f       | Passthrough TLS mode (SNI-only routing, no termination).               |

---

## M5a — Server hostname table + client CLI/env layer

**Goal.** Restructure the server config to be the source of truth for hostnames, build an in-memory routing table populated at connect time, and switch the client to a flags/env-first config layer. M5b will consume the routing table.

Wire protocol unchanged in M5a (ALPN still `tuyau/0`). Config + runtime plumbing only — no observable end-to-end behavior change yet.

### Server config additions (`server.toml`)

```toml
listen_addr = "0.0.0.0:4433"

[[clients]]
name = "service-a"
token = "<64 hex>"

[[hostnames]]
host = "alpha.example.com"
client = "service-a"
# tls_mode = "terminated"   # default; alt: "passthrough"
```

- [ ] Add top-level `hostnames: Vec<HostnameEntry>` parsed from `[[hostnames]]`
- [ ] `HostnameEntry { host: String, client: String, tls_mode: TlsMode }`
- [ ] `enum TlsMode { Terminated, Passthrough }` with `#[serde(rename_all = "snake_case")]`; default `Terminated`
- [ ] Validation: no duplicate `host` across `[[hostnames]]`
- [ ] Validation: every `[[hostnames]].client` references an existing `[[clients]].name`
- [ ] A `[[clients]]` entry with zero matching `[[hostnames]]` is permitted (client connects, no hostnames activate)

### Server runtime — routing table

- [ ] New module `tuyau-server/src/routes.rs`:
  ```rust
  pub struct RouteEntry {
      pub client_name: String,
      pub tls_mode: TlsMode,
      pub conn: quinn::Connection,
  }
  pub struct RoutingTable {
      inner: Arc<RwLock<HashMap<String /*host*/, RouteEntry>>>,
  }
  ```
- [ ] On successful Hello (token validated → matched client name resolved):
  - Compute the set of hosts this client owns by config (filter `hostnames[]` by `client == matched_name`)
  - If any of those hosts currently have a `RouteEntry` owned by a *different* `quinn::Connection` with the *same* matched name, close that previous connection (last-write-wins), wait briefly for cleanup
  - Insert/replace all `(host → RouteEntry { client_name, tls_mode, conn })` for the new connection
  - Log `INFO "client connected" name=... hosts=[...]`
- [ ] On connection close (any reason): remove every routing-table entry whose `conn.stable_id()` matches this connection
- [ ] Public API: `TunnelServer::active_hostnames() -> Vec<String>` (sorted) for tests/observability

### Client config layer (`tuyau-cli`)

CLI: `tuyau client [flags...]` OR `tuyau client --config <path>`. Mutually exclusive.

- [ ] Flags: `--server <addr>`, `--fingerprint <hex>`, `--token-file <path>`, `--name <s>`, `--config <path>`
- [ ] Env vars: `TUYAU_SERVER`, `TUYAU_FINGERPRINT`, `TUYAU_TOKEN` (hex), `TUYAU_TOKEN_FILE` (path), `TUYAU_NAME`
- [ ] Resolution per field: flag > env > error (or default for `name`)
- [ ] Token resolution priority: `--token-file` → `TUYAU_TOKEN_FILE` → `TUYAU_TOKEN`. File contents trimmed of trailing whitespace, parsed as 64 hex chars.
- [ ] `--config <path>` is mutually exclusive with `--server`, `--fingerprint`, `--token-file`, `--name`: any combination is a hard error (clap-level `conflicts_with`)
- [ ] Default `client_name` = `hostname::get()` (add `hostname = "0.4"` to workspace deps); fallback `"unknown"` if the call errors
- [ ] Update `examples/client.toml` (still works for `--config` path) and add `examples/docker-compose.yml` demonstrating env + secret-file usage

### Tests

`tuyau-server`:
- [ ] `from_toml_str` parses a config with top-level `[[hostnames]]`
- [ ] Rejects duplicate `host` across `[[hostnames]]`
- [ ] Rejects `[[hostnames]].client` referencing a non-existent `[[clients]].name`
- [ ] `tls_mode` defaults to `Terminated` when omitted
- [ ] Client connects with valid token → `active_hostnames()` returns the sorted set of its assigned hosts
- [ ] Client disconnects cleanly → `active_hostnames()` no longer includes them
- [ ] Last-write-wins: connection A established; same matched name reconnects as B; A is closed, B owns the routes. `active_hostnames()` reflects this within ~1s.
- [ ] Client whose token has zero `[[hostnames]]` entries connects successfully; `active_hostnames()` unchanged

`tuyau-cli`:
- [ ] `--config` + any other config flag → clap conflict error
- [ ] Flags-only invocation with all required fields → builds a valid `ClientConfig`
- [ ] Env-only invocation with all required fields → builds the same `ClientConfig`
- [ ] Flag overrides env when both are set
- [ ] Missing token (no flag, no env) → error message names the field
- [ ] `--token-file` reads from disk; trailing whitespace stripped
- [ ] Default `client_name` matches `hostname::get()` when not specified

`tuyau-cli` smoke (`tests/smoke.rs`):
- [ ] Updated server config carries at least one `[[hostnames]]` entry pointing at the test client; the smoke asserts `active_hostnames()` is empty before connect, populated during, empty after shutdown

### Out of scope for M5a (deferred)

- Public TCP/TLS listener (M5b)
- `DataStreamHeader` frame, ALPN bump to `tuyau/1` (M5b)
- Client `[[ingress]]` config / accept loop / forward (M5c)
- Wildcards in `host` (M6 or later)
- Dynamic config (hot reload, admin API) — see M6 sketch below

### Acceptance

- [ ] All M5a tests pass
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo fmt --all` clean
- [ ] Commit: `M5a: server hostname routing table + client CLI/env config layer`

---

## M6 sketch — dynamic config (post-M5, not yet committed)

Once Phase 2 ships, the natural extension is managing hostnames without bouncing the server. Sketched here because M5 design choices anticipate it.

| Milestone | Idea                                                                                                |
| --------- | --------------------------------------------------------------------------------------------------- |
| M6a       | **Hot reload via SIGHUP / file-watch.** Server diffs on-disk TOML against the in-memory routing table; applies adds/removes; existing connections kept. Cheapest dynamic story; matches how IaC tools (Ansible/Terraform) write TOML. |
| M6b       | **Local admin HTTP API.** Second listener on `127.0.0.1:9000` with REST endpoints for hostname CRUD; auth via shared secret. Persistence still in TOML (API writes back to disk). Door opener for a `tuyau ctl` CLI and a dashboard. |
| M6c       | **Pluggable persistence.** `HostnameStore` trait with TOML / sqlite / postgres / redis backends. Required for multi-instance clustering (anycast / HA). |

M5 decisions that keep M6 cheap:

- Routing table is `Arc<RwLock<HashMap<...>>>` — mutable at runtime, not a constant built at boot.
- Hostname entries will track their *origin* (TOML vs API vs DB) so reload doesn't clobber dynamic entries (added in M6b).
- Client config layer is already flag/env/TOML-pluggable, so future credential sources (Vault, k8s downward API, GCP/AWS secret managers) are additive.
- Last-write-wins reconnect semantics already handle the case where a managed control plane rotates tokens and clients reconnect with new credentials.

