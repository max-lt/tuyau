//! End-to-end: a browser-style HTTP/2 client reaches a plain HTTP/1.1 backend
//! through the terminated public listener. Proves the h2→h1 bridge: tuyau
//! terminates h2 (ALPN), and the backend only ever speaks h1.

use std::sync::Arc;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::ext::Protocol;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use tuyau_server::{ServerConfig, TlsMode, TunnelServer, UpstreamEntry};

/// Minimal HTTP/1.1 backend: replies `200` with a fixed body, echoing the
/// negotiated-down protocol so the test can assert it saw h1, not h2.
async fn spawn_h1_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let body = format!("hello from backend: {} {}", req.method(), req.uri().path());
                    Ok::<_, hyper::Error>(Response::new(body))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

/// Minimal HTTP/1.1 WebSocket backend: answers the `Upgrade: websocket`
/// handshake with `101` (a fixed, unchecked accept), then echoes bytes. The
/// bridge synthesizes a constant Sec-WebSocket-Key and never verifies the
/// accept, so a hand-rolled 101 is enough.
async fn spawn_ws_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Read the request head up to the blank line.
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                if !head.contains("upgrade: websocket") {
                    let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
                let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: dummy\r\n\r\n";
                if stream.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // Echo the WebSocket payload bytes back.
                let mut io = [0u8; 1024];
                loop {
                    match stream.read(&mut io).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&io[..n]).await.is_err() {
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
async fn h2_browser_reaches_h1_backend() {
    let backend = spawn_h1_backend().await;

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
            host: "front.example.com".into(),
            local_addr: Some(backend),
            local_socket: None,
            tls_mode: TlsMode::Terminated,
        }],
        max_public_connections: None,
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    // Browser-style TLS client: trust anything, offer ALPN h2.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));

    let tcp = TcpStream::connect(public).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("front.example.com").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(
        tls_stream.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "server must negotiate h2"
    );

    // Speak HTTP/2 to tuyau.
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        TokioIo::new(tls_stream),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("https://front.example.com/hello")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert_eq!(
        text, "hello from backend: GET /hello",
        "backend saw the request as h1 GET, proxied from the h2 client"
    );

    server.shutdown().await;
}

/// Start a terminated public listener whose only route is a local upstream to
/// `backend`. Returns the running server and its public address.
async fn start_terminated_to(backend: std::net::SocketAddr) -> (TunnelServer, std::net::SocketAddr) {
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
            host: "front.example.com".into(),
            local_addr: Some(backend),
            local_socket: None,
            tls_mode: TlsMode::Terminated,
        }],
        max_public_connections: None,
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();
    (server, public)
}

/// Open an h2 connection (trusting any cert) to `public` and return the sender.
async fn h2_sender(
    public: std::net::SocketAddr,
) -> hyper::client::conn::http2::SendRequest<Empty<Bytes>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let tcp = TcpStream::connect(public).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("front.example.com").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

#[tokio::test]
async fn websocket_over_h2_bridges_to_h1_upgrade() {
    let backend = spawn_ws_backend().await;
    let (server, public) = start_terminated_to(backend).await;
    let mut sender = h2_sender(public).await;

    // Let the server's SETTINGS (advertising RFC 8441 Extended CONNECT) arrive.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Browser-style WebSocket-over-h2: CONNECT with the `:protocol` pseudo-header.
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri("https://front.example.com/ws")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.extensions_mut().insert(Protocol::from_static("websocket"));

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200, "RFC 8441 success is 200, not 101");

    // The h2 stream is now a raw byte tunnel bridged to the backend's h1 WS.
    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let mut io = TokioIo::new(upgraded);
    io.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping", "backend echoed the websocket payload");

    server.shutdown().await;
}
