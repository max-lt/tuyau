//! Public-listener resource limits: the concurrency cap sheds excess
//! connections instead of growing tasks/memory without bound.

use std::time::Duration;

use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use tuyau_server::{ServerConfig, TlsMode, TunnelServer, UpstreamEntry};

#[tokio::test]
async fn public_connection_cap_sheds_excess() {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        // A route must exist for the config to validate; the upstream is never
        // dialed here (the test connections never send a ClientHello).
        upstreams: vec![UpstreamEntry {
            host: "front.example.com".into(),
            local_addr: Some("127.0.0.1:9".parse().unwrap()),
            local_socket: None,
            tls_mode: TlsMode::Passthrough,
        }],
        max_public_connections: Some(1),
        error_502_file: None,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.public_local_addr().unwrap();

    // First connection: connect but send no ClientHello. The handler accepts it,
    // takes the only permit, and blocks reading the ClientHello — holding it.
    let mut c1 = TcpStream::connect(public).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Second connection: no permit free → the server sheds it (drops the
    // stream), so the client sees a prompt EOF.
    let mut c2 = TcpStream::connect(public).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut buf))
        .await
        .expect("a shed connection should close promptly")
        .expect("read");
    assert_eq!(n, 0, "second connection should be shed (EOF)");

    // The first is still alive (not shed): a read just blocks — no data, no close.
    let mut b1 = [0u8; 1];
    let still_open = tokio::time::timeout(Duration::from_millis(300), c1.read(&mut b1)).await;
    assert!(still_open.is_err(), "first connection should still be open");

    server.shutdown().await;
}
