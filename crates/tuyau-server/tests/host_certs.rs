//! End-to-end: the public listener presents the cert that an upstream entry
//! sets for its hostname, and the server-wide cert for the other hostnames.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    tls_mode: TlsMode,
    cert: Option<(&std::path::Path, &std::path::Path)>,
) -> UpstreamEntry {
    UpstreamEntry {
        host: host.into(),
        local_addr: Some(backend),
        local_socket: None,
        tls_mode,
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
                TlsMode::TlsOffload,
                Some((&cert_file, &key_file)),
            ),
            upstream("plain.example.com", backend_addr, TlsMode::TlsOffload, None),
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

/// Writes a self-signed cert for `host` into `dir`; gives the cert, its DER and
/// the key file.
fn write_cert(
    dir: &std::path::Path,
    name: &str,
    host: &str,
) -> (std::path::PathBuf, Vec<u8>, std::path::PathBuf) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_file = dir.join(format!("{name}.crt"));
    let key_file = dir.join(format!("{name}.key"));
    std::fs::write(&cert_file, cert.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();

    (cert_file, cert.der().to_vec(), key_file)
}

/// A TLS backend that echoes one line: the end of a passthrough route.
async fn spawn_tls_echo(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> std::net::SocketAddr {
    use rustls::pki_types::pem::PemObject;

    let chain = rustls::pki_types::CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_file).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = [0u8; 64];
                let n = tls.read(&mut buf).await.unwrap();
                tls.write_all(&buf[..n]).await.unwrap();
                tls.flush().await.unwrap();
            });
        }
    });

    addr
}

#[tokio::test]
async fn the_catch_all_passes_unknown_hosts_through_and_a_wildcard_serves_its_cert() {
    let dir = tempfile::TempDir::new().unwrap();
    let (backend_cert, backend_der, backend_key) =
        write_cert(dir.path(), "backend", "backend.test");
    let (wild_cert, wild_der, wild_key) = write_cert(dir.path(), "wild", "*.wild.test");

    let tls_backend = spawn_tls_echo(&backend_cert, &backend_key).await;
    let plain_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();

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
            upstream("*", tls_backend, TlsMode::Passthrough, None),
            upstream(
                "*.wild.test",
                plain_backend.local_addr().unwrap(),
                TlsMode::TlsOffload,
                Some((&wild_cert, &wild_key)),
            ),
        ],
        max_public_connections: None,
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    assert_eq!(presented_cert(public, "a.wild.test").await, wild_der);

    // A host that no entry names reaches the TLS backend untouched
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let tcp = TcpStream::connect(public).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("custom.example.net").unwrap();
    let mut stream = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .unwrap();

    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0].to_vec(),
        backend_der
    );

    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    server.shutdown().await;
}
