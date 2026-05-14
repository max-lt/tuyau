//! End-to-end smoke test: spin up TunnelServer + TunnelClient in-process and
//! verify a successful handshake. This is the MVP success criterion.

use tempfile::TempDir;

use tuyau_client::{ClientConfig, TunnelClient};
use tuyau_server::{ClientEntry, ServerConfig, TunnelServer};

const TOKEN: [u8; 32] = [0x42; 32];

#[tokio::test]
async fn end_to_end_handshake() {
    let dir = TempDir::new().unwrap();

    let server_cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: TOKEN,
        }],
    };

    let server = TunnelServer::start(server_cfg).await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    let fingerprint = server.cert_fingerprint();

    let client_cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{server_port}"),
        server_cert_fingerprint_sha256: fingerprint,
        token: TOKEN,
        client_name: "service-a".into(),
    };

    let client = TunnelClient::connect(client_cfg)
        .await
        .expect("client should connect after a valid handshake");

    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn example_configs_parse() {
    let server_toml = include_str!("../../../examples/server.toml");
    ServerConfig::from_toml_str(server_toml).expect("examples/server.toml must parse");

    let client_toml = include_str!("../../../examples/client.toml");
    ClientConfig::from_toml_str(client_toml).expect("examples/client.toml must parse");
}
