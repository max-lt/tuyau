//! End-to-end TLS of the public listener: the cert an entry sets, wildcard and
//! catch-all routes, and the client certs it accepts.

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
        client_ca_file: None,
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
        client_ca_file: None,
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

/// Whether "ping" sent to `sni` with `client_cert` comes back.
async fn echoes(
    public: std::net::SocketAddr,
    sni: &str,
    client_cert: Option<(rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
) -> bool {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)));
    let tls = match client_cert {
        Some((cert, key)) => {
            let key = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
            builder.with_client_auth_cert(vec![cert], key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };

    let tcp = TcpStream::connect(public).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let Ok(mut stream) = TlsConnector::from(Arc::new(tls)).connect(name, tcp).await else {
        return false;
    };

    if stream.write_all(b"ping").await.is_err() || stream.flush().await.is_err() {
        return false;
    }

    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await;

    matches!(read, Ok(Ok(_))) && &buf == b"ping"
}

#[tokio::test]
async fn a_terminated_host_accepts_only_client_certs_signed_by_the_client_ca() {
    let dir = tempfile::TempDir::new().unwrap();

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_file = dir.path().join("origin-pull-ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();

    let proxy_key = rcgen::KeyPair::generate().unwrap();
    let proxy = rcgen::CertificateParams::new(vec!["proxy.test".to_string()])
        .unwrap()
        .signed_by(&proxy_key, &ca, &ca_key)
        .unwrap();

    let stranger_key = rcgen::KeyPair::generate().unwrap();
    let stranger = rcgen::CertificateParams::new(vec!["stranger.test".to_string()])
        .unwrap()
        .self_signed(&stranger_key)
        .unwrap();

    let (backend_cert, _, backend_key) = write_cert(dir.path(), "backend", "backend.test");
    let tls_backend = spawn_tls_echo(&backend_cert, &backend_key).await;

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
            upstream("app.test", spawn_echo().await, TlsMode::TlsOffload, None),
            upstream("pass.test", tls_backend, TlsMode::Passthrough, None),
        ],
        max_public_connections: None,
        error_502_file: None,
        client_ca_file: Some(ca_file),
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    assert!(echoes(public, "app.test", Some((proxy.der().clone(), &proxy_key))).await);
    assert!(!echoes(public, "app.test", None).await, "no client cert");
    assert!(
        !echoes(
            public,
            "app.test",
            Some((stranger.der().clone(), &stranger_key))
        )
        .await,
        "a cert of another CA"
    );

    // The backend of a passthrough host does its own handshake
    assert!(echoes(public, "pass.test", None).await);

    server.shutdown().await;
}

#[tokio::test]
async fn a_client_ca_file_without_a_cert_stops_the_start() {
    let dir = tempfile::TempDir::new().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();

    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![upstream(
            "app.test",
            spawn_echo().await,
            TlsMode::TlsOffload,
            None,
        )],
        max_public_connections: None,
        error_502_file: None,
        client_ca_file: Some(empty),
    };

    assert!(TunnelServer::start(cfg).await.is_err());
}

/// An h1 backend that answers "<x-real-ip>|<cf-connecting-ip or ->", and
/// echoes the bytes of an upgraded connection.
async fn spawn_address_backend() -> std::net::SocketAddr {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    |mut req: hyper::Request<hyper::body::Incoming>| async move {
                        let header = |name: &str| {
                            req.headers()
                                .get(name)
                                .map_or("-".to_string(), |v| v.to_str().unwrap().to_string())
                        };
                        let body =
                            format!("{}|{}", header("x-real-ip"), header("cf-connecting-ip"));

                        if req.headers().contains_key(hyper::header::UPGRADE) {
                            let upgrade = hyper::upgrade::on(&mut req);
                            tokio::spawn(async move {
                                let mut io = TokioIo::new(upgrade.await.unwrap());
                                let mut buf = [0u8; 64];
                                let n = io.read(&mut buf).await.unwrap();
                                io.write_all(&buf[..n]).await.unwrap();
                            });

                            return Ok::<_, hyper::Error>(
                                hyper::Response::builder()
                                    .status(101)
                                    .header("connection", "Upgrade")
                                    .header("upgrade", "websocket")
                                    .header("x-backend-saw", body)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }

                        Ok(hyper::Response::new(Full::new(Bytes::from(body))))
                    },
                );

                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .with_upgrades()
                    .await
                    .ok();
            });
        }
    });

    addr
}

fn client_tls(
    alpn: &[u8],
    cert: Option<(rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)));
    let mut tls = match cert {
        Some((cert, key)) => {
            let key = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
            builder.with_client_auth_cert(vec![cert], key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![alpn.to_vec()];

    TlsConnector::from(Arc::new(tls))
}

/// GET / on `sni` over ALPN `alpn` with `headers`; gives what the backend saw.
async fn backend_saw(
    public: std::net::SocketAddr,
    sni: &str,
    alpn: &[u8],
    cert: Option<(rustls::pki_types::CertificateDer<'static>, &rcgen::KeyPair)>,
    headers: &[(&str, &str)],
) -> String {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let tcp = TcpStream::connect(public).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let tls = client_tls(alpn, cert).connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);

    let mut req = hyper::Request::builder().uri(format!("https://{sni}/"));
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    if alpn == b"http/1.1" {
        req = req.header("host", sni);
    }
    let req = req.body(Empty::<Bytes>::new()).unwrap();

    let resp = if alpn == b"h2" {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(conn);
        sender.send_request(req).await.unwrap()
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        sender.send_request(req).await.unwrap()
    };

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

/// A client CA, and a client cert it signs.
fn origin_pull_ca(
    dir: &std::path::Path,
) -> (std::path::PathBuf, rcgen::Certificate, rcgen::KeyPair) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();

    let proxy_key = rcgen::KeyPair::generate().unwrap();
    let proxy = rcgen::CertificateParams::new(vec!["proxy.test".to_string()])
        .unwrap()
        .signed_by(&proxy_key, &ca, &ca_key)
        .unwrap();

    (ca_file, proxy, proxy_key)
}

async fn start_terminated(
    dir: &std::path::Path,
    backend: std::net::SocketAddr,
    client_ca_file: Option<std::path::PathBuf>,
) -> TunnelServer {
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![upstream("app.test", backend, TlsMode::Terminated, None)],
        max_public_connections: None,
        error_502_file: None,
        client_ca_file,
    };

    TunnelServer::start(cfg).await.unwrap()
}

const FORGED: [(&str, &str); 2] = [
    ("x-real-ip", "198.51.100.9"),
    ("cf-connecting-ip", "203.0.113.7"),
];

#[tokio::test]
async fn without_a_client_ca_the_backend_gets_the_peer_and_no_forged_address() {
    let dir = tempfile::TempDir::new().unwrap();
    let server = start_terminated(dir.path(), spawn_address_backend().await, None).await;
    let public = server.public_local_addr().unwrap();

    for alpn in [b"http/1.1".as_slice(), b"h2"] {
        assert_eq!(
            backend_saw(public, "app.test", alpn, None, &FORGED).await,
            "127.0.0.1|-"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn behind_the_client_ca_the_backend_gets_cf_connecting_ip() {
    let dir = tempfile::TempDir::new().unwrap();
    let (ca_file, proxy, proxy_key) = origin_pull_ca(dir.path());
    let server = start_terminated(dir.path(), spawn_address_backend().await, Some(ca_file)).await;
    let public = server.public_local_addr().unwrap();

    for alpn in [b"http/1.1".as_slice(), b"h2"] {
        let cert = || Some((proxy.der().clone(), &proxy_key));

        assert_eq!(
            backend_saw(public, "app.test", alpn, cert(), &FORGED).await,
            "203.0.113.7|203.0.113.7"
        );
        assert_eq!(
            backend_saw(
                public,
                "app.test",
                alpn,
                cert(),
                &[("cf-connecting-ip", "nope")]
            )
            .await,
            "127.0.0.1|-"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn an_h1_websocket_upgrade_reaches_the_backend_with_the_client_address() {
    let dir = tempfile::TempDir::new().unwrap();
    let server = start_terminated(dir.path(), spawn_address_backend().await, None).await;
    let public = server.public_local_addr().unwrap();

    let tcp = TcpStream::connect(public).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("app.test").unwrap();
    let mut tls = client_tls(b"http/1.1", None)
        .connect(name, tcp)
        .await
        .unwrap();

    tls.write_all(
        b"GET /ws HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          X-Real-IP: 198.51.100.9\r\n\r\n",
    )
    .await
    .unwrap();

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();

    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(head.contains("x-backend-saw: 127.0.0.1|-"), "{head}");

    tls.write_all(b"frame").await.unwrap();
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"frame");

    server.shutdown().await;
}
