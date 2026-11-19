//! A config reload on a running server: new routes, a config that does not
//! load, and a renewed cert file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use tuyau_server::{IssuerEntry, IssuerKind, ServerConfig, TlsMode, TunnelServer, UpstreamEntry};

/// rustls client verifier that accepts any cert: the tests read the cert the
/// server presents, they do not validate it.
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

fn connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(tls))
}

/// The leaf cert the server presents for `sni`, and whether "ping" comes back.
async fn probe(public: std::net::SocketAddr, sni: &str) -> Option<(Vec<u8>, bool)> {
    let tcp = TcpStream::connect(public).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut stream = connector().connect(name, tcp).await.ok()?;
    let cert = stream.get_ref().1.peer_certificates()?[0].to_vec();

    stream.write_all(b"ping").await.ok()?;
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await;

    Some((cert, matches!(read, Ok(Ok(_))) && &buf == b"ping"))
}

/// A cleartext backend that echoes what it reads, for `tls_offload` routes.
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok(n) = tcp.read(&mut buf).await {
                    if n == 0 || tcp.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// Writes a self-signed cert for `host` to `name.crt` and `name.key` in `dir`;
/// gives the two files and the cert.
fn write_cert(dir: &Path, name: &str, host: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_file = dir.join(format!("{name}.crt"));
    let key_file = dir.join(format!("{name}.key"));
    std::fs::write(&cert_file, cert.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();

    (cert_file, key_file, cert.der().to_vec())
}

fn upstream(host: &str, backend: std::net::SocketAddr) -> UpstreamEntry {
    UpstreamEntry {
        host: host.into(),
        local_addr: Some(backend),
        local_socket: None,
        internal_listener: None,
        tls_mode: TlsMode::TlsOffload,
        tls_cert_file: None,
        tls_key_file: None,
        issuer: None,
    }
}

fn config(dir: &Path, upstreams: Vec<UpstreamEntry>, issuers: Vec<IssuerEntry>) -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams,
        max_public_connections: None,
        error_502_file: None,
        client_ca_file: None,
        issuers,
    }
}

#[tokio::test]
async fn a_reload_serves_a_new_route_on_the_same_listener() {
    let dir = tempfile::TempDir::new().unwrap();
    let echo = spawn_echo().await;
    let server = TunnelServer::start(config(dir.path(), vec![upstream("a.test", echo)], vec![]))
        .await
        .unwrap();
    let public = server.public_local_addr().unwrap();

    assert!(probe(public, "a.test").await.unwrap().1);
    assert!(probe(public, "b.test").await.is_none(), "no route yet");

    let both = vec![upstream("a.test", echo), upstream("b.test", echo)];
    server.reload(config(dir.path(), both, vec![])).unwrap();

    assert!(probe(public, "a.test").await.unwrap().1);
    assert!(probe(public, "b.test").await.unwrap().1);

    server.shutdown().await;
}

#[tokio::test]
async fn a_config_that_does_not_load_changes_nothing() {
    let dir = tempfile::TempDir::new().unwrap();
    let echo = spawn_echo().await;
    let server = TunnelServer::start(config(dir.path(), vec![upstream("a.test", echo)], vec![]))
        .await
        .unwrap();
    let public = server.public_local_addr().unwrap();

    let mut broken = upstream("b.test", echo);
    broken.tls_cert_file = Some("/nonexistent/b.crt".into());
    broken.tls_key_file = Some("/nonexistent/b.key".into());
    let bad = config(dir.path(), vec![broken], vec![]);

    assert!(TunnelServer::check(&bad).is_err());
    assert!(server.reload(bad).is_err());
    assert!(
        probe(public, "a.test").await.unwrap().1,
        "the old route stays"
    );
    assert!(probe(public, "b.test").await.is_none());

    server.shutdown().await;
}

#[tokio::test]
async fn a_renewed_cert_file_is_served_after_a_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let echo = spawn_echo().await;
    let (cert_file, key_file, first) = write_cert(dir.path(), "origin", "a.test");
    let issuers = vec![IssuerEntry {
        name: "origin".into(),
        default: true,
        kind: IssuerKind::Imported {
            cert_file,
            key_file,
        },
    }];
    let routes = || vec![upstream("a.test", echo)];

    let server = TunnelServer::start(config(dir.path(), routes(), issuers.clone()))
        .await
        .unwrap();
    let public = server.public_local_addr().unwrap();

    assert_eq!(probe(public, "a.test").await.unwrap().0, first);

    // Same entry, new file contents
    let (_, _, renewed) = write_cert(dir.path(), "origin", "a.test");
    server
        .reload(config(dir.path(), routes(), issuers))
        .unwrap();

    assert_eq!(probe(public, "a.test").await.unwrap().0, renewed);

    server.shutdown().await;
}
