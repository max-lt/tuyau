//! M5b end-to-end tests: public TLS client → tuyau-server's public listener →
//! routed → tunnel client receives a `DataStreamHeader` + raw bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use tuyau_client::{ClientConfig, TunnelClient};
use tuyau_server::{ClientEntry, HostnameEntry, ServerConfig, TlsMode, TunnelServer};

const TOKEN: [u8; 32] = [0x42; 32];

async fn spin_up_with_public(hostnames: Vec<HostnameEntry>) -> (TunnelServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: TOKEN,
        }],
        hostnames,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    (server, dir)
}

async fn connect_tunnel(server: &TunnelServer) -> TunnelClient {
    let cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{}", server.local_addr().unwrap().port()),
        server_cert_fingerprint_sha256: server.cert_fingerprint(),
        token: TOKEN,
        client_name: "service-a".into(),
    };
    TunnelClient::connect(cfg).await.unwrap()
}

// Public-side TLS client: accepts any cert (the server's public cert is
// self-signed and not pinned — pinning is the tunnel cert, not this one).
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

async fn public_tls(
    addr: SocketAddr,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let tcp = TcpStream::connect(addr).await?;
    let config = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| std::io::Error::other(format!("invalid SNI: {e}")))?;
    connector.connect(server_name, tcp).await
}

#[tokio::test]
async fn public_tls_dispatches_bytes_through_tunnel() {
    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel_client = connect_tunnel(&server).await;

    let public_addr = server.public_local_addr().expect("public listener bound");
    let mut public_stream = public_tls(public_addr, "alpha.example.com")
        .await
        .expect("public TLS handshake");

    let mut tunnel_stream = tokio::time::timeout(Duration::from_secs(5), tunnel_client.accept_bi())
        .await
        .expect("accept_bi must resolve within 5s")
        .expect("accept_bi must return Ok");

    assert_eq!(tunnel_stream.header.hostname, "alpha.example.com");
    assert_eq!(tunnel_stream.header.mode, TlsMode::Terminated);
    assert!(
        tunnel_stream.header.peer_addr.contains("127.0.0.1"),
        "peer_addr should be loopback, got {:?}",
        tunnel_stream.header.peer_addr
    );

    // Public → tunnel
    public_stream.write_all(b"hello tunnel").await.unwrap();
    let mut buf = [0u8; 32];
    let n = tunnel_stream.recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello tunnel");

    // Tunnel → public (signal EOF on the tunnel side so read_to_end terminates)
    tunnel_stream.send.write_all(b"hello world").await.unwrap();
    let _ = tunnel_stream.send.finish();

    let mut received = Vec::new();
    public_stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"hello world");

    drop(public_stream);
    tunnel_client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn public_tls_with_unknown_sni_is_dropped() {
    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel_client = connect_tunnel(&server).await;

    let public_addr = server.public_local_addr().unwrap();
    let result = public_tls(public_addr, "ghost.example.com").await;
    assert!(
        result.is_err(),
        "TLS handshake should fail for unknown SNI, got Ok"
    );

    // No stream should have been dispatched on the tunnel.
    let accept = tokio::time::timeout(Duration::from_millis(500), tunnel_client.accept_bi()).await;
    assert!(
        accept.is_err(),
        "no tunnel stream should have been dispatched for an unknown SNI"
    );

    tunnel_client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn public_tls_to_passthrough_is_dropped_in_m5b() {
    // Passthrough wiring is M5f; for now the server logs and drops the
    // connection without completing the TLS handshake.
    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "secure.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Passthrough,
    }])
    .await;

    let tunnel_client = connect_tunnel(&server).await;

    let public_addr = server.public_local_addr().unwrap();
    let result = public_tls(public_addr, "secure.example.com").await;
    assert!(
        result.is_err(),
        "passthrough hostnames must not complete TLS handshake in M5b"
    );

    let accept = tokio::time::timeout(Duration::from_millis(500), tunnel_client.accept_bi()).await;
    assert!(
        accept.is_err(),
        "passthrough drop must not dispatch on the tunnel"
    );

    tunnel_client.shutdown().await;
    server.shutdown().await;
}
