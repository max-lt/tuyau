//! Embed a tuyau tunnel in **passthrough** mode and serve it with axum.
//!
//! Unlike the `axum` example (terminated mode, where the tuyau-server decrypts
//! and hands us plaintext), here the server only peeks the SNI and forwards the
//! raw TLS bytes. This application is the TLS endpoint: it terminates TLS with
//! its own certificate, over the tunnel. The server never sees plaintext.
//!
//! The only difference from the terminated one-liner is `tls_listener(acceptor)`
//! instead of `listener()` — the SDK's `TlsTunnelListener` does the TLS
//! handshake on each tunnel stream and still implements `axum::serve::Listener`.
//!
//! Run (server hostname must be `tls_mode = "passthrough"`):
//!     cargo run -p tuyau-client --example passthrough --features tls,axum
//!
//! Expected env:
//!   TUYAU_SERVER=host:4433
//!   TUYAU_FINGERPRINT=<64 hex>
//!   TUYAU_TOKEN=<64 hex>
//!   TUYAU_CERT=/path/fullchain.pem   (default /tmp/fullchain1.pem)
//!   TUYAU_KEY=/path/privkey.pem      (default /tmp/privkey1.pem)

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::{Router, routing::get};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tuyau_client::{ClientConfig, TunnelClient};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let acceptor = build_acceptor()?;

    let cfg = ClientConfig {
        server_addr: env::var("TUYAU_SERVER").context("TUYAU_SERVER")?,
        server_cert_fingerprint_sha256: hex_32(&env::var("TUYAU_FINGERPRINT")?)?,
        token: hex_32(&env::var("TUYAU_TOKEN")?)?,
        client_name: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "embedded-passthrough".into()),
        ingress: vec![], // we serve directly, not forwarding to a local port
    };

    let tunnel = TunnelClient::connect(cfg).await?;
    tracing::info!("tunnel connected (passthrough); terminating TLS in-app");

    // The one-line difference from terminated mode: `tls_listener` instead of
    // `listener`. Everything below is plain axum.
    let listener = tunnel.tls_listener(acceptor);
    let shutdown = listener.closed();

    let app = Router::new()
        .route(
            "/",
            get(|| async { "Hello from tuyau PASSTHROUGH + Rust SDK 🦀\n" }),
        )
        .route("/health", get(|| async { "ok" }));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

fn build_acceptor() -> Result<TlsAcceptor> {
    let cert_path = env::var("TUYAU_CERT").unwrap_or_else(|_| "/tmp/fullchain1.pem".into());
    let key_path = env::var("TUYAU_KEY").unwrap_or_else(|_| "/tmp/privkey1.pem".into());

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(
        File::open(&cert_path).context(cert_path)?,
    ))
    .collect::<std::result::Result<_, _>>()?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(&key_path).context(key_path)?,
    ))?
    .ok_or_else(|| anyhow!("no private key in TUYAU_KEY"))?;

    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("invalid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("expected 32 bytes (64 hex chars), got {}", bytes.len()))
}
