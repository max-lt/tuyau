//! End-to-end smoke test: spin up TunnelServer + TunnelClient in-process and
//! verify a successful handshake plus the M5a routing-table lifecycle.

use std::time::Duration;

use tempfile::TempDir;

use tuyau_client::{ClientConfig, TunnelClient};
use tuyau_server::{ClientEntry, HostnameEntry, ServerConfig, TlsMode, TunnelServer};

const TOKEN: [u8; 32] = [0x42; 32];

#[tokio::test]
async fn end_to_end_handshake() {
    let dir = TempDir::new().unwrap();

    let server_cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: None,
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: TOKEN,
        }],
        hostnames: vec![HostnameEntry {
            host: "alpha.example.com".into(),
            client: "service-a".into(),
            tls_mode: TlsMode::Terminated,
        }],
    };

    let server = TunnelServer::start(server_cfg).await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    let fingerprint = server.cert_fingerprint();

    assert!(
        server.active_hostnames().is_empty(),
        "routing table should be empty before any client connects"
    );

    let client_cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{server_port}"),
        server_cert_fingerprint_sha256: fingerprint,
        token: TOKEN,
        client_name: "service-a".into(),
    };

    let client = TunnelClient::connect(client_cfg)
        .await
        .expect("client should connect after a valid handshake");

    assert_eq!(
        server.active_hostnames(),
        vec!["alpha.example.com".to_string()],
        "routing table should be populated while the client is connected"
    );

    client.shutdown().await;

    // Server's cleanup runs asynchronously after observing conn.closed().
    for _ in 0..50 {
        if server.active_hostnames().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        server.active_hostnames().is_empty(),
        "routing table should clear after the client disconnects"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn example_configs_parse() {
    let server_toml = include_str!("../../../examples/server.toml");
    ServerConfig::from_toml_str(server_toml).expect("examples/server.toml must parse");

    let client_toml = include_str!("../../../examples/client.toml");
    ClientConfig::from_toml_str(client_toml).expect("examples/client.toml must parse");
}
