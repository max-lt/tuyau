//! `dynamic` feature: the injected-`RoutingBackend` path (`start_with`).
//!
//! The admit *dispatch* and the shared `start_inner` machinery are already
//! covered end-to-end by the static-mode integration tests; here we exercise
//! the delta — that an embedder can implement `RoutingBackend`, inject it via
//! `start_with`, and that dynamic mode relaxes the static-only `clients`
//! requirement.
#![cfg(feature = "dynamic")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tempfile::TempDir;
use tokio_util::codec::{FramedRead, FramedWrite};

use tuyau_protocol::{ALPN, FrameCodec, Hello, HelloResponse};
use tuyau_server::{
    Balance, ClientGrant, ControlEvent, RoutingBackend, ServerConfig, TlsMode, TunnelServer,
};

/// A minimal embedder-style backend: admits one token, granting one passthrough
/// hostname. Stands in for a managed control plane querying its own store.
struct OneToken {
    token: [u8; 32],
    host: String,
}

#[tuyau_server::async_trait]
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
        max_public_connections: None,
        error_502_file: None,
        upstreams: vec![],
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

// ---------------------------------------------------------------------------
// Raw QUIC tunnel client + backends for the cross-client / admit-timeout tests.
// ---------------------------------------------------------------------------

/// Backend mapping two tokens to two *different* client identities that both
/// claim the same hostname — exercises the one-client-per-host invariant.
struct TwoTenants;

#[tuyau_server::async_trait]
impl RoutingBackend for TwoTenants {
    async fn admit(&self, token: &[u8; 32]) -> Option<ClientGrant> {
        let client_name = match token[0] {
            0xAA => "alice",
            0xBB => "bob",
            _ => return None,
        };
        Some(ClientGrant {
            client_name: client_name.into(),
            balance: Balance::RoundRobin,
            hostnames: vec![("shop.example".into(), TlsMode::Terminated)],
        })
    }
}

/// Backend whose admit never returns within ADMIT_TIMEOUT.
struct HangingBackend;

#[tuyau_server::async_trait]
impl RoutingBackend for HangingBackend {
    async fn admit(&self, _token: &[u8; 32]) -> Option<ClientGrant> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        None
    }
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn client_endpoint() -> Endpoint {
    let mut rustls = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    rustls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(rustls).unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(QuinnClientConfig::new(Arc::new(quic)));
    endpoint
}

/// Connect a raw tunnel, perform the Hello handshake, return the connection and
/// the server's response.
async fn connect_and_hello(
    addr: SocketAddr,
    endpoint: &Endpoint,
    token: [u8; 32],
) -> (quinn::Connection, HelloResponse) {
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (send, recv) = connection.open_bi().await.unwrap();
    let mut writer = FramedWrite::new(send, FrameCodec::<Hello>::new());
    let mut reader = FramedRead::new(recv, FrameCodec::<HelloResponse>::new());
    writer
        .send(Hello {
            token,
            client_name: "raw".into(),
        })
        .await
        .unwrap();
    let response = reader.next().await.unwrap().unwrap();
    (connection, response)
}

#[tokio::test]
async fn cross_client_host_reassign_evicts_incumbent() {
    // The one-client-per-host invariant: when a host owned by `alice` is granted
    // to `bob`, bob takes it over and alice's tunnel is evicted — never mixed
    // (which would cross-route alice's tunnel into bob's traffic).
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start_with(Arc::new(TwoTenants), dyn_cfg(&dir))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let endpoint = client_endpoint();

    let (conn_a, resp_a) = connect_and_hello(addr, &endpoint, [0xAA; 32]).await;
    assert!(matches!(resp_a, HelloResponse::Welcome), "alice admitted");

    let (conn_b, resp_b) = connect_and_hello(addr, &endpoint, [0xBB; 32]).await;
    assert!(matches!(resp_b, HelloResponse::Welcome), "bob admitted");

    // Bob's grant for the same host must have evicted alice's tunnel.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn_a.closed()).await;
    assert!(
        closed.is_ok(),
        "incumbent (alice) was not evicted when the host was reassigned to bob"
    );

    drop(conn_b);
    endpoint.close(0u32.into(), b"done");
    server.shutdown().await;
}

#[tokio::test]
async fn admit_timeout_rejects_instead_of_hanging() {
    // A hung backend must not stall the handshake forever: the server bounds
    // admit by ADMIT_TIMEOUT and rejects.
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start_with(Arc::new(HangingBackend), dyn_cfg(&dir))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let endpoint = client_endpoint();

    let (_conn, resp) = tokio::time::timeout(
        Duration::from_secs(15),
        connect_and_hello(addr, &endpoint, [0x11; 32]),
    )
    .await
    .expect("server did not hang on a stuck backend");
    match resp {
        HelloResponse::Reject { reason } => {
            assert!(
                reason.contains("timeout"),
                "expected timeout reject, got {reason:?}"
            )
        }
        other => panic!("expected Reject, got {other:?}"),
    }

    endpoint.close(0u32.into(), b"done");
    server.shutdown().await;
}

#[tokio::test]
async fn observe_reports_tunnel_up_and_down() {
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start_with(
        Arc::new(OneToken {
            token: [7u8; 32],
            host: "x.example".into(),
        }),
        dyn_cfg(&dir),
    )
    .await
    .unwrap();
    let mut events = server.subscribe();
    let addr = server.local_addr().unwrap();
    let endpoint = client_endpoint();

    let (conn, resp) = connect_and_hello(addr, &endpoint, [7u8; 32]).await;
    assert!(matches!(resp, HelloResponse::Welcome));

    // TunnelUp event + snapshot.
    let up = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("event within 5s")
        .expect("event channel open");
    match up {
        ControlEvent::TunnelUp {
            client_name,
            hostnames,
            ..
        } => {
            assert_eq!(client_name, "dyn");
            assert_eq!(hostnames, vec!["x.example".to_string()]);
        }
        other => panic!("expected TunnelUp, got {other:?}"),
    }
    let snap = server.tunnels();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].client_name, "dyn");
    assert_eq!(snap[0].hostnames, vec!["x.example".to_string()]);

    // Dropping the tunnel emits TunnelDown and clears the registry.
    drop(conn);
    let down = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("event within 5s")
        .expect("event channel open");
    assert!(
        matches!(down, ControlEvent::TunnelDown { ref client_name, .. } if client_name == "dyn"),
        "expected TunnelDown for dyn, got {down:?}"
    );
    assert!(
        server.tunnels().is_empty(),
        "tunnel removed from the registry on down"
    );

    endpoint.close(0u32.into(), b"done");
    server.shutdown().await;
}

#[tokio::test]
async fn kick_revokes_a_connected_client() {
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start_with(
        Arc::new(OneToken {
            token: [7u8; 32],
            host: "x.example".into(),
        }),
        dyn_cfg(&dir),
    )
    .await
    .unwrap();
    let mut events = server.subscribe();
    let addr = server.local_addr().unwrap();
    let endpoint = client_endpoint();

    let (conn, resp) = connect_and_hello(addr, &endpoint, [7u8; 32]).await;
    assert!(matches!(resp, HelloResponse::Welcome));
    // Consume the TunnelUp.
    let _ = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.tunnels().len(), 1);

    // Revoke: closes the tunnel now and reports one connection closed.
    assert_eq!(server.kick("dyn"), 1, "one connection revoked");

    // The client's connection is closed and a TunnelDown surfaces.
    assert!(
        tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .is_ok(),
        "revoked connection was closed"
    );
    let down = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(down, ControlEvent::TunnelDown { ref client_name, .. } if client_name == "dyn"),
        "expected TunnelDown for dyn, got {down:?}"
    );
    assert!(server.tunnels().is_empty(), "registry cleared after revoke");

    // Kicking an unknown client is a no-op.
    assert_eq!(server.kick("nobody"), 0);

    endpoint.close(0u32.into(), b"done");
    server.shutdown().await;
}
