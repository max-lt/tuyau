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

[tunnel_cert]
mode = "auto"  # generate self-signed cert on first run, persist next to config
# Alternatives: mode = "inline" with cert_pem/key_pem, or mode = "files" with paths

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
└── tests/
    └── integration.rs     End-to-end handshake test
```

## Wire Protocol (MVP)

Two frames, exchanged on the first bidi stream of the QUIC connection:

```rust
pub struct Hello {
    pub token: String,
    pub client_name: String,    // informational, for server logs
    pub client_version: String, // e.g. "tuyau-client/0.1.0"
}

pub enum HelloResponse {
    Welcome {
        server_version: String,
    },
    Reject {
        reason: RejectReason,
    },
}

pub enum RejectReason {
    InvalidToken,
    ProtocolError,
}
```

Encoding: each frame is a u32 big-endian length prefix followed by ciborium-encoded CBOR. Max frame size 64 KiB (this is a tiny handshake).

After Welcome: connection stays open (server holds it; future iterations will use it). Client logs "connected" and waits. The connection lifetime + heartbeat behavior is **explicitly out of scope** for the MVP — if the connection drops, both sides notice and exit. No reconnect.

---

# Implementation Plan

## M0 — Workspace setup

- [ ] Workspace `Cargo.toml` with members `tuyau-protocol`, `tuyau-server`, `tuyau-client`, `tuyau-cli`
- [ ] Each crate has `Cargo.toml` and `src/lib.rs` (or `src/main.rs` for `tuyau-cli`)
- [ ] `tuyau-cli` declares a binary named `tuyau` via `[[bin]]`
- [ ] `[workspace.dependencies]` populated with all deps from the Tech Stack table
- [ ] `LICENSE-MIT` and `LICENSE-APACHE` at the repo root
- [ ] `README.md` with one paragraph + "status: pre-alpha"
- [ ] `.github/workflows/ci.yml`: `cargo build --workspace`, `cargo test --workspace`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `.gitignore` for Rust + editor artifacts + `*.local.toml` + `*.pem`

**Test**: `cargo build --workspace` and `cargo test --workspace` succeed. CI green on a push.

---

## M1 — `tuyau-protocol`

Frames + codec. No networking.

- [ ] Define `Hello`, `HelloResponse`, `RejectReason` with serde derives
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
      pub tunnel_cert: TunnelCertConfig,
      pub clients: Vec<ClientEntry>,
  }
  pub struct ClientEntry { pub name: String, pub token: String }
  pub enum TunnelCertConfig {
      Auto { storage_dir: Option<PathBuf> },
      Inline { cert_pem: String, key_pem: String },
      Files { cert_path: PathBuf, key_path: PathBuf },
  }
  ```
- [ ] Cert handling per `TunnelCertConfig`:
  - `Auto`: load `<storage_dir>/tunnel-cert.pem` + `tunnel-key.pem`; if missing, generate via `rcgen` (CN = "tuyau-tunnel", validity 10 years, EC P-256) and persist (key file with mode 0600 on Unix)
  - `Inline`: parse PEM strings from config
  - `Files`: read from disk
- [ ] Compute SHA-256 fingerprint of the cert DER, log at INFO at startup so it can be copied into a client config
- [ ] Build quinn server config with rustls, ALPN = `tuyau/0`, bound to `listen_addr`
- [ ] Accept loop: per incoming connection, spawn a task that:
  1. Awaits `connection.accept_bi()` for the first bidirectional stream (5s timeout)
  2. Wraps the recv half in `FrameCodec<Hello>` and send half in `FrameCodec<HelloResponse>`
  3. Reads exactly one `Hello` frame
  4. Validates `hello.token` against `config.clients[].token` using `subtle::ConstantTimeEq`
  5. On match: logs `INFO "client connected" name=<matched_name>`, sends `HelloResponse::Welcome`, holds the connection open
  6. On no match: sends `HelloResponse::Reject { InvalidToken }`, closes
  7. On bad frame / timeout: sends `Reject { ProtocolError }`, closes
- [ ] Public API: `TunnelServer::start(config: ServerConfig) -> Result<TunnelServer>` returning a handle. `TunnelServer::shutdown()` closes the endpoint gracefully.

**Tests** (in `crates/tuyau-server/tests/`):
- [ ] Spin up server in-process on port 0, get assigned port back from the handle
- [ ] Connect a raw quinn client, complete TLS, open bi stream, send valid Hello → receive Welcome
- [ ] Send Hello with wrong token → receive `Reject { InvalidToken }`
- [ ] Send malformed bytes on the stream → receive `Reject { ProtocolError }` (or connection closes)
- [ ] Don't send anything → connection closed by server after 5s timeout
- [ ] `Auto` cert mode: start server twice with the same `storage_dir`, fingerprint stable
- [ ] `Inline` cert mode: start server with PEM strings, verify it accepts a connection
- [ ] `cargo test -p tuyau-server` passes

---

## M3 — `tuyau-client`: dial QUIC + send token

Client-side: connect, send Hello, read response.

- [ ] Define `ClientConfig` matching `client.toml` schema:
  ```rust
  pub struct ClientConfig {
      pub server_addr: String,                       // host:port
      pub server_cert_fingerprint_sha256: [u8; 32],  // pinned cert fingerprint
      pub token: String,
      pub client_name: String,
  }
  ```
- [ ] Build quinn client config with rustls; install a custom `ServerCertVerifier` that:
  - Computes SHA-256 of the leaf cert DER
  - Compares to `server_cert_fingerprint_sha256` with constant-time compare
  - Returns Ok if match, error otherwise (no PKI chain validation)
- [ ] ALPN = `tuyau/0`
- [ ] Resolve `server_addr` (DNS), dial, complete TLS
- [ ] Open first bidi stream
- [ ] Send `Hello { token, client_name, client_version }`
- [ ] Read `HelloResponse` (5s timeout)
- [ ] On `Welcome`: log INFO "connected", hold the connection. Stay alive until the connection closes (peer-initiated or local Ctrl-C).
- [ ] On `Reject { reason }`: log error, exit non-zero with a distinct exit code per reason
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
  tuyau gen-token              # prints 32 random bytes hex to stdout
  tuyau show-fingerprint <PATH-TO-CERT>
  ```
- [ ] Load TOML config via serde, fail-fast on validation errors with clear messages (which field, what's wrong)
- [ ] `tracing-subscriber` setup with `RUST_LOG` env-filter, default `info`
- [ ] On SIGINT/SIGTERM: call `shutdown()` on the running component, wait up to 2s, exit
- [ ] Sample configs in `examples/`:
  - `examples/server.toml`
  - `examples/client.toml`
  - Both runnable together; the README explains the bootstrap loop (run server once to get the fingerprint, paste it into client.toml)

**Tests** (in `tests/integration.rs`):
- [ ] Parse a sample server.toml and client.toml; verify config struct matches expectations
- [ ] Reject a config with empty `clients` list; reject a config with empty `token`; reject malformed fingerprint hex
- [ ] `tuyau gen-token` outputs exactly 64 hex chars + newline, exit 0
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

