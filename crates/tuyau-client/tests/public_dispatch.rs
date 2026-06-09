//! End-to-end data-plane tests:
//! - M5b: public TLS → server listener → routed → tunnel client receives a
//!   `DataStreamHeader` + raw bytes (via the raw `accept_bi` surface).
//! - M5c: full HTTP request through `serve()` → ingress → local service →
//!   response back out.
//! - M5d: `TunnelListener` / `TunnelConnection` (no quinn leak) and the
//!   `axum::serve` adapter (behind the `axum` feature).

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
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
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
    connect_tunnel_with(server, vec![]).await
}

async fn connect_tunnel_with(
    server: &TunnelServer,
    ingress: Vec<tuyau_client::IngressRule>,
) -> TunnelClient {
    let cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{}", server.local_addr().unwrap().port()),
        server_cert_fingerprint_sha256: server.cert_fingerprint(),
        token: TOKEN,
        client_name: "service-a".into(),
        ingress,
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

/// Spawn a TLS-terminating HTTP/1.1 server on loopback with a fresh
/// self-signed cert for the given hostname. tuyau-server NEVER has this cert
/// — that's the whole point of the passthrough test below.
async fn spawn_local_tls_http(hostname: String, body: Arc<Vec<u8>>) -> SocketAddr {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::ServerConfig as RustlsServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![hostname.clone()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname.as_str());
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let tls_config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                let mut req = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match tls.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            req.extend_from_slice(&tmp[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len(),
                );
                let _ = tls.write_all(header.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn public_tls_passthrough_forwards_raw_tls() {
    // The tuyau-server runs a passthrough route for "secure.example.com" and
    // has NO cert covering that hostname. A local rustls server holds the
    // matching cert privately. If tuyau-server were terminating, the TLS
    // handshake to the public client would fail (no SAN match). The fact
    // that the public client receives a response signed by the LOCAL server's
    // cert proves the bytes flowed through opaquely.
    let body = Arc::new(b"from-passthrough".to_vec());
    let local_addr =
        spawn_local_tls_http("secure.example.com".to_string(), Arc::clone(&body)).await;

    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "secure.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Passthrough,
    }])
    .await;

    let tunnel = connect_tunnel_with(
        &server,
        vec![tuyau_client::IngressRule {
            host: "secure.example.com".into(),
            local_addr: local_addr.to_string(),
        }],
    )
    .await;
    let tunnel = Arc::new(tunnel);
    let serve_client = Arc::clone(&tunnel);
    let serve_handle = tokio::spawn(async move { serve_client.serve().await });

    let public_addr = server.public_local_addr().unwrap();
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        http_get(public_addr, "secure.example.com"),
    )
    .await
    .expect("passthrough response within 5s");

    assert!(
        resp.starts_with(b"HTTP/1.1 200 OK"),
        "non-200 on passthrough: {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(http_body(&resp), body.as_slice());

    serve_handle.abort();
    server.shutdown().await;
}

/// Minimal HTTP/1.1 server that replies with a fixed body and closes. Reads
/// the request until the header terminator so split TCP segments don't break
/// the test. Body is `Arc<Vec<u8>>` so callers can share large bodies cheaply
/// across many connections.
async fn spawn_local_http(body: Arc<Vec<u8>>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            req.extend_from_slice(&tmp[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len(),
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn end_to_end_http_request_through_tunnel() {
    let local_addr = spawn_local_http(Arc::new(b"tuyau works".to_vec())).await;

    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel_with(
        &server,
        vec![tuyau_client::IngressRule {
            host: "alpha.example.com".into(),
            local_addr: local_addr.to_string(),
        }],
    )
    .await;
    let tunnel = Arc::new(tunnel);
    let serve_client = Arc::clone(&tunnel);
    let serve_handle = tokio::spawn(async move { serve_client.serve().await });

    let public_addr = server.public_local_addr().unwrap();
    let mut public = public_tls(public_addr, "alpha.example.com")
        .await
        .expect("public TLS handshake");

    public
        .write_all(b"GET / HTTP/1.1\r\nHost: alpha.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), public.read_to_end(&mut raw))
        .await
        .expect("response should arrive within 5s")
        .unwrap();
    let resp = String::from_utf8_lossy(&raw);

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "expected 200, got: {resp:?}"
    );
    assert!(
        resp.contains("tuyau works"),
        "body missing in response: {resp:?}"
    );

    serve_handle.abort();
    drop(public);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// M5d: TunnelListener / TunnelConnection (no quinn leak)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tunnel_listener_yields_connection_with_metadata() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel(&server).await;
    let listener = tunnel.listener();

    let public_addr = server.public_local_addr().unwrap();
    let mut public_stream = public_tls(public_addr, "alpha.example.com")
        .await
        .expect("public TLS handshake");

    let (mut conn, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept must resolve within 5s")
        .expect("accept must return Ok");

    assert_eq!(conn.hostname(), "alpha.example.com");
    assert_eq!(conn.tls_mode(), TlsMode::Terminated);
    assert!(
        peer.ip().is_loopback(),
        "peer should be loopback, got {peer}"
    );

    // Bytes both directions through the no-quinn-leak wrapper.
    public_stream.write_all(b"hello listener").await.unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello listener");

    conn.write_all(b"world").await.unwrap();
    conn.shutdown().await.unwrap();

    let mut received = Vec::new();
    public_stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"world");

    drop(public_stream);
    tunnel.shutdown().await;
    server.shutdown().await;
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_serves_through_tunnel_listener() {
    use axum::Router;
    use axum::routing::get;

    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel(&server).await;
    let listener = tunnel.listener();
    let shutdown_signal = listener.closed();

    let app = Router::new().route("/", get(|| async { "hello from axum-over-tuyau" }));
    let serve_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await;
    });

    let public_addr = server.public_local_addr().unwrap();
    let mut public = public_tls(public_addr, "alpha.example.com")
        .await
        .expect("public TLS handshake");

    public
        .write_all(b"GET / HTTP/1.1\r\nHost: alpha.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), public.read_to_end(&mut raw))
        .await
        .expect("axum response within 5s")
        .unwrap();
    let resp = String::from_utf8_lossy(&raw);

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "expected 200, got: {resp:?}"
    );
    assert!(
        resp.contains("hello from axum-over-tuyau"),
        "body missing in response: {resp:?}"
    );

    serve_handle.abort();
    drop(public);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Multi-request / concurrent / large-payload coverage
// ---------------------------------------------------------------------------

/// Send one full HTTP/1.1 GET via TLS and return the raw response bytes.
async fn http_get(public_addr: SocketAddr, sni: &str) -> Vec<u8> {
    let mut public = public_tls(public_addr, sni).await.expect("TLS handshake");
    let req = format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    public.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    public.read_to_end(&mut buf).await.unwrap();
    buf
}

/// Strip the HTTP/1.1 header block and return only the body bytes.
fn http_body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(resp)
}

#[tokio::test]
async fn serve_handles_multiple_sequential_requests() {
    let local_addr = spawn_local_http(Arc::new(b"req-ok".to_vec())).await;
    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel_with(
        &server,
        vec![tuyau_client::IngressRule {
            host: "alpha.example.com".into(),
            local_addr: local_addr.to_string(),
        }],
    )
    .await;
    let tunnel = Arc::new(tunnel);
    let serve_client = Arc::clone(&tunnel);
    let serve_handle = tokio::spawn(async move { serve_client.serve().await });

    let public_addr = server.public_local_addr().unwrap();
    for i in 0..3 {
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            http_get(public_addr, "alpha.example.com"),
        )
        .await
        .unwrap_or_else(|_| panic!("request {i} timed out"));
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK"),
            "request {i} non-200: {:?}",
            String::from_utf8_lossy(&resp)
        );
        assert_eq!(http_body(&resp), b"req-ok", "request {i} body mismatch");
    }

    serve_handle.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn serve_handles_concurrent_public_connections() {
    let local_addr = spawn_local_http(Arc::new(b"concurrent".to_vec())).await;
    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel_with(
        &server,
        vec![tuyau_client::IngressRule {
            host: "alpha.example.com".into(),
            local_addr: local_addr.to_string(),
        }],
    )
    .await;
    let tunnel = Arc::new(tunnel);
    let serve_client = Arc::clone(&tunnel);
    let serve_handle = tokio::spawn(async move { serve_client.serve().await });

    let public_addr = server.public_local_addr().unwrap();
    let a = tokio::spawn(http_get(public_addr, "alpha.example.com"));
    let b = tokio::spawn(http_get(public_addr, "alpha.example.com"));

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(5), async {
        (a.await.unwrap(), b.await.unwrap())
    })
    .await
    .expect("concurrent responses within 5s");

    for (label, resp) in [("a", &ra), ("b", &rb)] {
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK"),
            "{label} non-200: {:?}",
            String::from_utf8_lossy(resp)
        );
        assert_eq!(http_body(resp), b"concurrent", "{label} body");
    }

    serve_handle.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn multi_client_routing_keeps_hostnames_isolated() {
    // Two distinct clients, each owning a different hostname. Public requests
    // for each hostname must reach only the owning client's local service.
    const TOKEN_A: [u8; 32] = [0xA0; 32];
    const TOKEN_B: [u8; 32] = [0xB0; 32];

    let local_a = spawn_local_http(Arc::new(b"from-alpha".to_vec())).await;
    let local_b = spawn_local_http(Arc::new(b"from-beta".to_vec())).await;

    let dir = TempDir::new().unwrap();
    let server_cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        clients: vec![
            ClientEntry {
                name: "alpha-srv".into(),
                token: TOKEN_A,
            },
            ClientEntry {
                name: "beta-srv".into(),
                token: TOKEN_B,
            },
        ],
        hostnames: vec![
            HostnameEntry {
                host: "alpha.example.com".into(),
                client: "alpha-srv".into(),
                tls_mode: TlsMode::Terminated,
            },
            HostnameEntry {
                host: "beta.example.com".into(),
                client: "beta-srv".into(),
                tls_mode: TlsMode::Terminated,
            },
        ],
    };
    let server = TunnelServer::start(server_cfg).await.unwrap();

    let make_client = |token: [u8; 32], host: &str, local: SocketAddr| {
        let cfg = ClientConfig {
            server_addr: format!("127.0.0.1:{}", server.local_addr().unwrap().port()),
            server_cert_fingerprint_sha256: server.cert_fingerprint(),
            token,
            client_name: host.into(),
            ingress: vec![tuyau_client::IngressRule {
                host: host.into(),
                local_addr: local.to_string(),
            }],
        };
        async move { TunnelClient::connect(cfg).await.unwrap() }
    };

    let tunnel_a = Arc::new(make_client(TOKEN_A, "alpha.example.com", local_a).await);
    let tunnel_b = Arc::new(make_client(TOKEN_B, "beta.example.com", local_b).await);

    let a = Arc::clone(&tunnel_a);
    let h_a = tokio::spawn(async move { a.serve().await });
    let b = Arc::clone(&tunnel_b);
    let h_b = tokio::spawn(async move { b.serve().await });

    let public_addr = server.public_local_addr().unwrap();

    let resp_a = tokio::time::timeout(
        Duration::from_secs(5),
        http_get(public_addr, "alpha.example.com"),
    )
    .await
    .expect("alpha response within 5s");
    let resp_b = tokio::time::timeout(
        Duration::from_secs(5),
        http_get(public_addr, "beta.example.com"),
    )
    .await
    .expect("beta response within 5s");

    assert_eq!(
        http_body(&resp_a),
        b"from-alpha",
        "alpha must reach alpha-srv's local service, not beta's"
    );
    assert_eq!(
        http_body(&resp_b),
        b"from-beta",
        "beta must reach beta-srv's local service, not alpha's"
    );

    h_a.abort();
    h_b.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn large_payload_roundtrips_through_tunnel() {
    // ~1 MiB body, deterministic pattern so we can compare exactly.
    let body: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = Arc::new(body);
    let local_addr = spawn_local_http(Arc::clone(&expected)).await;

    let (server, _dir) = spin_up_with_public(vec![HostnameEntry {
        host: "alpha.example.com".into(),
        client: "service-a".into(),
        tls_mode: TlsMode::Terminated,
    }])
    .await;

    let tunnel = connect_tunnel_with(
        &server,
        vec![tuyau_client::IngressRule {
            host: "alpha.example.com".into(),
            local_addr: local_addr.to_string(),
        }],
    )
    .await;
    let tunnel = Arc::new(tunnel);
    let serve_client = Arc::clone(&tunnel);
    let serve_handle = tokio::spawn(async move { serve_client.serve().await });

    let public_addr = server.public_local_addr().unwrap();
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        http_get(public_addr, "alpha.example.com"),
    )
    .await
    .expect("large response within 10s");

    assert!(
        resp.starts_with(b"HTTP/1.1 200 OK"),
        "non-200 on large payload"
    );
    let body = http_body(&resp);
    assert_eq!(body.len(), expected.len(), "body length mismatch");
    assert_eq!(body, expected.as_slice(), "body content mismatch");

    serve_handle.abort();
    server.shutdown().await;
}
