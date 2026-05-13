# Tuyau

A minimal QUIC tunnel: a server listens on a UDP port for QUIC connections from authenticated clients, each presenting a pre-shared 32-byte token. The server pins its self-signed certificate via SHA-256 fingerprint copied into the client config. No public HTTP listener, no hostname routing, no data plane — just the bottom layer.

**Status:** pre-alpha. See `.claude/plan.md` for the milestone-by-milestone build plan.

Dual-licensed under MIT or Apache-2.0 at your option.
