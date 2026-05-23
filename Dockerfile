# Multi-stage build for the `tuyau` binary (both `server` and `client`
# subcommands live in one binary).

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin tuyau

FROM debian:bookworm-slim
# ca-certificates: rustls-acme validates the ACME directory's TLS chain
# against the system trust store when the `[acme]` block is enabled.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --shell /usr/sbin/nologin tuyau
COPY --from=build /src/target/release/tuyau /usr/local/bin/tuyau
USER tuyau
ENTRYPOINT ["tuyau"]
