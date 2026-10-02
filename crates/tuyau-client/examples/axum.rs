//! Embed a tuyau tunnel directly into an axum application.
//!
//! Demonstrates the lib-first API: instead of running the `tuyau` CLI as a
//! sidecar and forwarding to a local port, the application *is* the tunnel
//! endpoint. One axum::serve call serves the router over the tunnel.
//!
//! Run (after a `tuyau server` is reachable and a token is configured):
//!     cargo run -p tuyau-client --example axum --features axum
//!
//! Expected env:
//!   TUYAU_SERVER=host:4433
//!   TUYAU_FINGERPRINT=<64 hex>
//!   TUYAU_TOKEN=<64 hex>

use std::env;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::response::Html;
use axum::{Router, routing::get};
use tuyau_client::{ClientConfig, TunnelClient};

/// Path to the HTML page, re-read on every request so edits show up on a plain
/// browser refresh — no rebuild. Override with `TUYAU_PAGE`.
const DEFAULT_PAGE: &str = "crates/tuyau-client/examples/page.html";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cfg = ClientConfig {
        server_addr: env::var("TUYAU_SERVER").context("TUYAU_SERVER")?,
        server_cert_fingerprint_sha256: hex_32(&env::var("TUYAU_FINGERPRINT")?)?,
        token: hex_32(&env::var("TUYAU_TOKEN")?)?,
        client_name: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "embedded-axum".into()),
        // No [[ingress]] — we are not forwarding; we serve directly.
        ingress: vec![],
    };

    let tunnel = TunnelClient::connect(cfg).await?;
    tracing::info!("tunnel connected, axum serving");

    let listener = tunnel.listener();
    let shutdown = listener.closed();

    let page_path = Arc::new(env::var("TUYAU_PAGE").unwrap_or_else(|_| DEFAULT_PAGE.into()));

    let app = Router::new()
        .route(
            "/",
            get({
                let page_path = Arc::clone(&page_path);
                move || {
                    let page_path = Arc::clone(&page_path);
                    async move {
                        match tokio::fs::read_to_string(page_path.as_str()).await {
                            Ok(html) => Html(html),
                            Err(e) => Html(format!("<h1>page load error</h1><pre>{e}</pre>")),
                        }
                    }
                }
            }),
        )
        .route("/health", get(|| async { "ok" }));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

fn hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("expected 32 bytes (64 hex chars), got {}", bytes.len()))
}
