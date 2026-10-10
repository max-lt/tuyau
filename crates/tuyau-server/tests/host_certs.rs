//! End-to-end: the public listener presents the cert that an upstream entry
//! sets for its hostname, and the server-wide cert for the other hostnames.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use tuyau_server::{ServerConfig, TlsMode, TunnelServer, UpstreamEntry};

/// rustls client verifier that accepts any cert: the test reads the cert the
/// server presents, it does not validate it.
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

/// The leaf cert the server presents for `sni`.
async fn presented_cert(public: std::net::SocketAddr, sni: &str) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));

    let tcp = TcpStream::connect(public).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let stream = connector.connect(server_name, tcp).await.unwrap();

    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

fn upstream(
    host: &str,
    backend: std::net::SocketAddr,
    cert: Option<(&std::path::Path, &std::path::Path)>,
) -> UpstreamEntry {
    UpstreamEntry {
        host: host.into(),
        local_addr: Some(backend),
        local_socket: None,
        tls_mode: TlsMode::TlsOffload,
        tls_cert_file: cert.map(|(cert, _)| cert.to_path_buf()),
        tls_key_file: cert.map(|(_, key)| key.to_path_buf()),
    }
}

#[tokio::test]
async fn a_hostname_with_its_own_cert_presents_it_and_the_others_get_the_default() {
    // The handshake ends before any byte reaches the backend
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();

    let dir = tempfile::TempDir::new().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let own = rcgen::CertificateParams::new(vec!["own.example.com".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_file = dir.path().join("own.crt");
    let key_file = dir.path().join("own.key");
    std::fs::write(&cert_file, own.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();

    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![
            upstream(
                "own.example.com",
                backend_addr,
                Some((&cert_file, &key_file)),
            ),
            upstream("plain.example.com", backend_addr, None),
        ],
        max_public_connections: None,
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    let own_presented = presented_cert(public, "own.example.com").await;
    let plain_presented = presented_cert(public, "plain.example.com").await;

    assert_eq!(own_presented, own.der().to_vec());
    assert_ne!(
        plain_presented, own_presented,
        "the default cert, not the entry's"
    );

    server.shutdown().await;
}
