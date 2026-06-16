//! End-to-end: a TLS client reaches a **cleartext, non-HTTP** backend through
//! the terminated public listener in `tls_offload` mode. Proves the offload
//! path: tuyau owns the certificate and terminates TLS (ALPN-less, like a
//! database client), then byte-pipes the *plaintext* straight to a backend that
//! never speaks TLS and never speaks HTTP — one generic path, no protocol code.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use tuyau_server::{ServerConfig, TlsMode, TunnelServer, UpstreamEntry};

/// Minimal cleartext TCP echo backend — stands in for any non-HTTP, non-TLS
/// service (Postgres, Redis, a line protocol you invented). It reads bytes and
/// writes them straight back; it never performs a TLS handshake.
async fn spawn_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// rustls client verifier that accepts any cert — the server serves a dev
/// self-signed cert here, and the test isn't about cert validation.
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

#[tokio::test]
async fn tls_offload_pipes_plaintext_to_cleartext_backend() {
    let backend = spawn_echo_backend().await;

    let dir = tempfile::TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![UpstreamEntry {
            host: "db.example.com".into(),
            local_addr: Some(backend),
            local_socket: None,
            tls_mode: TlsMode::TlsOffload,
        }],
        max_public_connections: None,
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    // DB-style TLS client: trust anything, and offer NO ALPN (databases don't).
    // The server advertises h2/http1.1, but an empty client offer negotiates
    // nothing, so the offload path byte-pipes instead of bridging HTTP.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
        .with_no_client_auth();
    assert!(tls.alpn_protocols.is_empty(), "client offers no ALPN");
    let connector = TlsConnector::from(Arc::new(tls));

    let tcp = TcpStream::connect(public).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("db.example.com").unwrap();
    let mut tls_stream = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(
        tls_stream.get_ref().1.alpn_protocol(),
        None,
        "no ALPN negotiated — offload, not the h2 bridge"
    );

    // The TLS session now tunnels a raw byte stream to the cleartext backend.
    // Send an opaque (non-HTTP) frame and expect it echoed verbatim.
    let payload = b"\x00\x01\x02not-http-just-bytes\xff";
    tls_stream.write_all(payload).await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf, payload,
        "backend echoed the raw bytes through the offload"
    );

    server.shutdown().await;
}
