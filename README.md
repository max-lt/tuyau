# Tuyau

A hostname-routed reverse tunnel over QUIC: expose local services on a public
HTTPS endpoint without opening inbound ports. Shaped like Cloudflare Tunnel,
but **open source and self-hostable**, with an optional **passthrough** mode
that never decrypts the tunneled traffic.

A public `tuyau-server` terminates (or peeks, in passthrough) public TLS on
port 443 and forwards each connection over a QUIC tunnel to the
`tuyau-client` that owns the requested hostname. The client forwards it on to
a local service.

```text
  internet                              your machine / cluster
  ────────                              ─────────────────────
       │
   TLS │  alpha.example.com           ┌──────────────┐
       └─────► tuyau-server ──QUIC──► │ tuyau-client │ ──► 127.0.0.1:8080
              (public 443)            └──────────────┘
              (tunnel 4433/UDP)
```

> **Status:** pre-alpha. Wire protocol may change between milestones. See
> [`.claude/plan.md`](.claude/plan.md) for the build plan.

## Features

- **Hostname routing**: one server fronts many services on shared 443, routed
  by SNI / Host header. Server config is the single source of truth for the
  hostname → client binding.
- **Two TLS modes per hostname**: `terminated` (server decrypts, plaintext
  flows over the tunnel) or `passthrough` (server only peeks the SNI, raw
  TLS bytes flow over the tunnel — the server never sees plaintext).
- **Library-first client**: `tuyau-client` is a Rust crate. With the `axum`
  feature, swap a `TcpListener` for a `TunnelListener` in one line and serve
  your existing axum/hyper app through the tunnel. CLI is a thin wrapper
  around the library.
- **Container-native CLI**: client config via flags + `TUYAU_*` env vars,
  token via `--token-file` / `TUYAU_TOKEN_FILE` (Docker secrets), no bare
  hex on the command line. TOML config is opt-in via `--config`.
- **Pinned tunnel cert**: the client pins the server's tunnel cert by SHA-256
  fingerprint — no PKI, no LE for the tunnel itself.
- **ACME / Let's Encrypt for public certs**: enable an optional `[acme]`
  block in `server.toml` to fetch real browser-trusted certs via
  TLS-ALPN-01. Without it, the public listener serves a dev self-signed
  multi-SAN cert (`curl -k` works; browsers complain).

## Build

Requires Rust 1.85+ (edition 2024). Both `server` and `client` ship as
subcommands of the same `tuyau` binary.

```bash
cargo build --release                     # binary at target/release/tuyau
cargo install --path crates/tuyau-cli     # or put `tuyau` on PATH
```

Container image (server + client in one):

```bash
docker build -t tuyau .
```

Embedding the client as a library: add `tuyau-client` as a dependency and
enable the `axum` feature for the [`axum::serve`](#3-or-embed-it-in-your-axum-app)
adapter.

## Quick start

### 1. Run the server

```toml
# server.toml
listen_addr = "0.0.0.0:4433"            # QUIC tunnel listener
public_listen_addr = "0.0.0.0:443"      # public TLS listener

[[clients]]
name = "service-a"
token = "<openssl rand -hex 32>"

[[hostnames]]
host = "alpha.example.com"
client = "service-a"
# tls_mode = "terminated"   # default; or "passthrough"
```

```bash
tuyau server --config server.toml
# logs the cert SHA-256 fingerprint at startup — copy it
```

### 2. Run the client (Docker-style with env + secret file)

```bash
TUYAU_SERVER=tunnel.example.com:4433 \
TUYAU_FINGERPRINT=<copied from server logs> \
TUYAU_TOKEN_FILE=./tuyau-token.hex \
tuyau client --ingress alpha.example.com=127.0.0.1:8080
```

Or via TOML (see `examples/client.toml`). See `examples/docker-compose.yml`
for a complete Compose setup with Docker secrets.

### 3. Or embed it in your axum app

```rust
use tuyau_client::{ClientConfig, TunnelClient};

let tunnel = TunnelClient::connect(cfg).await?;
let listener = tunnel.listener();
let shutdown = listener.closed();

axum::serve(listener, my_router)
    .with_graceful_shutdown(shutdown)
    .await?;
```

Requires the `axum` feature on `tuyau-client`. Full example:
[`crates/tuyau-client/examples/axum.rs`](crates/tuyau-client/examples/axum.rs).

## Deployment shapes

Tuyau is designed for three distinct shapes:

- **Self-host (OSS)** — you run both ends on your own infrastructure.
- **Cloud Marketplace** (planned) — pre-built AMI / container image you
  launch on your own AWS / Scaleway / OVH account. You stay sovereign.
- **Managed** (planned) — passthrough-only hosted service for teams that
  want the tunnel without operating the server, where "the operator cannot
  read your traffic" is a structural property of the OSS code.

## Workspace

```
crates/
├── tuyau-protocol/   wire frames + length-delimited CBOR codec
├── tuyau-server/     QUIC listener + public TLS listener + routing table
├── tuyau-client/     QUIC dialer + listener adapter (axum, lib-first)
└── tuyau-cli/        binary `tuyau` with `server` and `client` subcommands
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option.
