//! `dynamic` feature: the injected-`RoutingBackend` path (`start_with`).
//!
//! The admit *dispatch* and the shared `start_inner` machinery are already
//! covered end-to-end by the static-mode integration tests; here we exercise
//! the delta — that an embedder can implement `RoutingBackend`, inject it via
//! `start_with`, and that dynamic mode relaxes the static-only `clients`
//! requirement.
#![cfg(feature = "dynamic")]

use std::sync::Arc;

use tempfile::TempDir;
use tuyau_server::{Balance, ClientGrant, RoutingBackend, ServerConfig, TlsMode, TunnelServer};

/// A minimal embedder-style backend: admits one token, granting one passthrough
/// hostname. Stands in for a managed control plane querying its own store.
struct OneToken {
    token: [u8; 32],
    host: String,
}

#[async_trait::async_trait]
impl RoutingBackend for OneToken {
    async fn admit(&self, token: &[u8; 32]) -> Option<ClientGrant> {
        (token == &self.token).then(|| ClientGrant {
            client_name: "dyn".into(),
            balance: Balance::RoundRobin,
            hostnames: vec![(self.host.clone(), TlsMode::Passthrough)],
        })
    }
}

/// Dynamic config: `clients` / `hostnames` are owned by the backend, so they are
/// left empty here (which static mode would reject).
fn dyn_cfg(dir: &TempDir) -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
    }
}

#[tokio::test]
async fn start_with_injected_backend_starts_and_binds() {
    let dir = TempDir::new().unwrap();
    let backend = Arc::new(OneToken {
        token: [7u8; 32],
        host: "x.example".into(),
    });
    let server = TunnelServer::start_with(backend, dyn_cfg(&dir))
        .await
        .expect("start_with succeeds");

    assert!(server.local_addr().is_ok(), "QUIC tunnel listener bound");
    assert!(
        server.public_local_addr().is_some(),
        "public listener bound"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn dynamic_mode_allows_empty_clients() {
    // Static `start()` rejects an empty `clients` list (ConfigError::NoClients);
    // dynamic `start_with()` must not — the backend owns identity.
    let dir = TempDir::new().unwrap();
    let cfg = dyn_cfg(&dir);
    assert!(
        cfg.validate().is_err(),
        "static validation rejects no clients"
    );

    let backend = Arc::new(OneToken {
        token: [0u8; 32],
        host: "y.example".into(),
    });
    let server = TunnelServer::start_with(backend, dyn_cfg(&dir))
        .await
        .expect("dynamic start tolerates empty clients");
    server.shutdown().await;
}
