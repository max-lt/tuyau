# Tuyau

A hostname-routed reverse tunnel over QUIC: expose local services on a public
HTTPS endpoint without opening inbound ports. Shaped like Cloudflare Tunnel,
but **open source and self-hostable**, with an optional **passthrough** mode
that never decrypts the tunneled traffic.

A public `tuyau-server` terminates (or peeks, in passthrough) public TLS on
port 443 and forwards each connection over a QUIC tunnel to the
`tuyau-client` that owns the requested hostname. The client forwards it on to
a local service. UDP services (WireGuard, DNS, game servers) go the same way,
routed by port instead of hostname.

```text
  internet                              your machine / cluster
  ────────                              ─────────────────────
       │
   TLS │  alpha.example.com           ┌──────────────┐
       ├─────► tuyau-server ──QUIC──► │ tuyau-client │ ──► 127.0.0.1:8080
       │      (public 443)            └──────────────┘
   UDP │      (public 443/udp)               │
       └─────►                               └──────────► 127.0.0.1:51820
              (tunnel 4433/UDP)
```

> **Status:** alpha. Running in production, but the wire protocol may still
> change between releases.

## Features

- **Hostname routing**: one server fronts many services on shared 443, routed
  by SNI / Host header. Server config is the single source of truth for the
  hostname → client binding.
- **Per-client balancing**: when several tunnels share one client token, the
  server either hands over to the newest (`last-write-wins`, default — clean
  reconnects) or spreads public connections across them (`round-robin` —
  active-active fan-out / HA), set per `[[clients]]` entry.
- **Three TLS modes per hostname**: `terminated` (server decrypts and
  reverse-proxies HTTP — h2→h1 bridge), `tls_offload` (server decrypts and
  byte-pipes the plaintext to a cleartext, non-HTTP backend — Postgres, Redis,
  MQTT… — so the backend never deals with certificates), or `passthrough`
  (server only peeks the SNI, raw TLS bytes flow over the tunnel — the server
  never sees plaintext).
- **UDP forwarding**: expose a UDP service — WireGuard on 443/udp so it
  survives airport and hotel networks, DNS, anything datagram-based — through
  the same tunnel, carried on QUIC DATAGRAM frames rather than streams. Routed
  per port, with sessions that survive a client roaming between addresses and
  cannot be redirected by a spoofed packet. See
  [UDP forwarding](#udp-forwarding).
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
  block in `server.toml` and the server fetches real browser-trusted certs
  via TLS-ALPN-01 — per hostname, on demand, including hostnames added at
  runtime. Without it, the public listener serves a dev self-signed
  multi-SAN cert (`curl -k` works; browsers complain).
- **Bring your own cert**: when inbound TLS-ALPN-01 can't run (public 443 is
  held by another service, or inbound IPv6 is unreliable for the CA's
  validation), set `tls_cert_file` / `tls_key_file` to serve a cert obtained
  out-of-band — e.g. Let's Encrypt via DNS-01. No inbound validation needed.
- **Custom 502 page**: when a terminated hostname has no live tunnel, the
  server answers with a proper 502 page instead of dropping the connection
  — overridable per deployment via `error_502_file`.
- **Built to stay up**: non-poisoning routing locks, global + per-IP
  connection caps, accept-loop backpressure, and a liveness probe
  (`TunnelServer::healthy()`) ready to wire into a systemd watchdog.

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
# tls_mode = "terminated"   # default; also "tls_offload" or "passthrough"
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

## UDP forwarding

TCP routing has SNI to work with; UDP has nothing. Every datagram carries the
same destination, there is no handshake to peek at, and the kernel hands every
peer's traffic to one socket. So tuyau routes UDP **per port**: one `[[udp]]`
entry binds one UDP socket, and everything arriving there belongs to that
route. Any protocol works, and nothing shares a port.

```toml
# server.toml — forward UDP/443 over service-a's tunnel
[[udp]]
name = "wireguard"
listen_addr = "0.0.0.0:443"
client = "service-a"

# …or straight to a local service, no tunnel (the UDP [[upstreams]])
[[udp]]
name = "dns"
listen_addr = "0.0.0.0:5353"
local_addr = "127.0.0.1:53"
```

```toml
# client.toml — `name` is the routing key, the UDP counterpart of a hostname
[[udp_ingress]]
name = "wireguard"
local_addr = "127.0.0.1:51820"
```

Or with flags: `tuyau client --udp-ingress wireguard=127.0.0.1:51820`.

The QUIC tunnel is itself UDP, so a `[[udp]]` route can't share `listen_addr`
with it — config validation rejects that instead of letting one silently eat
the other. To put WireGuard on UDP/443, run the tunnel on another port (4433)
or give it its own address.

Sharing **one** UDP port between several targets would need per-protocol
payload inspection — QUIC Initial packets can be decrypted for their SNI, DTLS
carries SNI in clear, WireGuard has no SNI but handshake initiations can be
matched against known server keys via `mac1`. That isn't implemented: a route
is a port. The design leaves room for it, because a matcher can only ever
narrow a port that already routes somewhere.

### Roaming, and why a spoofed packet can't hijack a session

UDP has no connections, so sessions are a fiction tuyau maintains: `(route,
source address)` → a session, expired on idle. **A session's return address is
fixed when it is created and nothing can change it.**

That matters because client addresses move constantly — NAT rebinding, wifi →
4G. WireGuard and QUIC survive that natively: a mid-session packet carries an
identifier (WireGuard's receiver index, QUIC's connection id) that the
*endpoint* can authenticate. A proxy holds no keys, so it can't. Matching on
those identifiers and repointing the session would let anyone who ever saw a
packet redirect that session to themselves, kill it, or use tuyau to reflect
traffic.

So tuyau doesn't try to. A datagram from an unknown address is simply a new
session, and the tunnel client gives each session **its own local socket**. The
service behind the tunnel therefore sees a roamed peer as a new source address
— exactly what it sees when a peer roams with no proxy in the path — and its
own cryptography decides. WireGuard authenticates the packet, moves the peer's
endpoint, and replies flow back down the new session; the abandoned one idles
out. A spoofed packet from a third address takes the same path and gets the
same treatment: its own session, its own socket, and a far side that rejects
it. It never touches the session it was aiming at.

The rest of the posture, since source addresses are forgeable:

- **No amplification.** Until a peer shows evidence of a round trip (it keeps
  sending after a reply), tuyau sends it at most `amplification_factor` bytes
  per byte received — default 3, the bound QUIC applies to unvalidated paths.
  Protocols whose first answer dwarfs its question (DNS — and DNS is exactly
  what gets reflected) need it raised, which is a deliberate per-route trade:
  the port can then amplify that much toward a spoofed victim.
- **Bounded tables.** `max_sessions` per route (default 4096) plus a per-IP
  share, so a flood of forged sources costs memory that was capped in advance.
  Sessions the backend has never answered expire early.
- **Nothing is answered on an unrouted port.** No tunnel, no capacity, no
  matching `[[udp_ingress]]` → the datagram is dropped. UDP has no "no backend"
  to send, and inventing one would make the port an amplifier.

### MTU

Datagrams ride QUIC DATAGRAM frames (streams would add head-of-line blocking
and reordering, which hurt WireGuard). A packet that doesn't fit after
encapsulation is **dropped, not fragmented** — a lost fragment costs the whole
packet anyway, and reassembly state is exactly the unbounded per-peer memory
this design avoids.

Encapsulation costs 10 bytes plus the route name. On a normal 1500-byte path
that leaves **1276 bytes** of UDP payload before QUIC finishes MTU discovery
and ~1400 after, for a short route name. Size the tunneled protocol to the
lower figure so it works from the first packet:

```ini
# wg0.conf on the WireGuard client — 1240 + WireGuard's 32 bytes of overhead
# sits comfortably under the budget.
MTU = 1240
```

Oversized packets are dropped with a warning naming the budget, so a
misconfigured MTU shows up in the logs rather than as mystery packet loss.

### WireGuard on 443/udp, end to end

```toml
# server.toml on the public host
listen_addr = "0.0.0.0:4433"            # tunnel: NOT 443, that's for WireGuard
public_listen_addr = "0.0.0.0:443"      # public TLS (TCP) — coexists fine

[[clients]]
name = "vpn-box"
token = "<openssl rand -hex 32>"

[[udp]]
name = "wireguard"
listen_addr = "0.0.0.0:443"
client = "vpn-box"
```

```bash
# on the box running WireGuard
TUYAU_SERVER=tunnel.example.com:4433 \
TUYAU_FINGERPRINT=<from the server logs> \
TUYAU_TOKEN_FILE=./tuyau-token.hex \
tuyau client --udp-ingress wireguard=127.0.0.1:51820
```

The WireGuard client then points at `Endpoint = tunnel.example.com:443` with
`MTU = 1240`. TCP/443 and UDP/443 are separate sockets, so the public TLS
listener keeps serving hostnames on the same port.

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
├── tuyau-protocol/   wire frames + length-delimited CBOR codec, plus the
│                     binary encapsulation for UDP over QUIC datagrams
├── tuyau-server/     QUIC listener + public TLS/UDP listeners + routing table
├── tuyau-client/     QUIC dialer + listener adapter (axum, lib-first)
└── tuyau-cli/        binary `tuyau` with `server` and `client` subcommands
sdk/
└── ts/               TypeScript client SDK (Bun) — serve a local handler
                      through the tunnel without the Rust CLI
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option.
