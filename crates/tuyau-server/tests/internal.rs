//! Upstreams with `internal_listener`: the public listener reaches an
//! `InternalListener` of the embedding program, with no socket between them.
#![cfg(feature = "axum")]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::get;
use axum::serve::ListenerExt;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use tuyau_server::{
    ClientGrant, ConfigError, RoutingBackend, ServerConfig, ServerError, TlsMode, TunnelServer,
    UpstreamEntry,
};

struct NoClients;

#[tuyau_server::async_trait]
impl RoutingBackend for NoClients {
    async fn admit(&self, _token: &[u8; 32]) -> Option<ClientGrant> {
        None
    }
}

fn config(dir: &tempfile::TempDir, tls_mode: TlsMode) -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![UpstreamEntry {
            host: "admin.example.com".into(),
            local_addr: None,
            local_socket: None,
            internal_listener: Some("admin".into()),
            tls_mode,
            tls_cert_file: None,
            tls_key_file: None,
            issuer: None,
        }],
        max_public_connections: None,
        error_502_file: None,
        client_ca_file: None,
        issuers: vec![],
    }
}

async fn start(dir: &tempfile::TempDir, tls_mode: TlsMode) -> (TunnelServer, SocketAddr) {
    let server = TunnelServer::start_with(Arc::new(NoClients), config(dir, tls_mode))
        .await
        .unwrap();
    let public = server.public_local_addr().unwrap();
    (server, public)
}

fn tls_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    TlsConnector::from(Arc::new(tls))
}

/// A GET of `/` over h2, from a TCP connection whose local address it returns.
async fn get_root(public: SocketAddr) -> (u16, String, SocketAddr) {
    let tcp = TcpStream::connect(public).await.unwrap();
    let local = tcp.local_addr().unwrap();
    let name = rustls::pki_types::ServerName::try_from("admin.example.com").unwrap();
    let tls = tls_connector().connect(name, tcp).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);

    let request = Request::get("https://admin.example.com/")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap(), local)
}

#[tokio::test]
async fn test_an_axum_app_on_an_internal_listener_sees_the_public_client() {
    let dir = tempfile::TempDir::new().unwrap();
    let (server, public) = start(&dir, TlsMode::Terminated).await;
    let listener = server.internal_listener("admin").unwrap();
    let app = Router::new().route(
        "/",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    tokio::spawn(async move {
        let app = app.into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener.tap_io(|_| ()), app).await.unwrap();
    });

    let (status, body, client) = get_root(public).await;

    assert_eq!(status, 200);
    assert_eq!(body, client.to_string());

    server.shutdown().await;
}

#[tokio::test]
async fn test_a_name_without_a_listener_gets_a_502() {
    let dir = tempfile::TempDir::new().unwrap();
    let (server, public) = start(&dir, TlsMode::Terminated).await;

    let (status, _, _) = get_root(public).await;

    assert_eq!(status, 502);

    server.shutdown().await;
}

#[tokio::test]
async fn test_a_passthrough_listener_gets_the_raw_client_hello() {
    let dir = tempfile::TempDir::new().unwrap();
    let (server, public) = start(&dir, TlsMode::Passthrough).await;
    let mut listener = server.internal_listener("admin").unwrap();

    // The handshake waits for an answer that never comes; the bytes are enough
    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(public).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("admin.example.com").unwrap();
        let _ = tls_connector().connect(name, tcp).await;
    });
    let mut connection = listener.accept().await.unwrap();
    let mut record_type = [0u8; 1];
    connection.read_exact(&mut record_type).await.unwrap();

    assert_eq!(record_type[0], 0x16, "a TLS handshake record");
    assert_eq!(connection.hostname(), "admin.example.com");
    assert_eq!(connection.tls_mode(), TlsMode::Passthrough);

    client.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_a_static_server_refuses_an_internal_listener() {
    let dir = tempfile::TempDir::new().unwrap();

    let started = TunnelServer::start(config(&dir, TlsMode::Terminated)).await;

    assert!(matches!(
        started,
        Err(ServerError::Config(ConfigError::InternalListenerStatic(_)))
    ));
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
