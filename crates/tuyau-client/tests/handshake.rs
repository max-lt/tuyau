use std::time::Duration;

use tempfile::TempDir;

use tuyau_client::{ClientConfig, ClientError, TunnelClient};
use tuyau_server::{ClientEntry, HostnameEntry, ServerConfig, TlsMode, TunnelServer};

const VALID_TOKEN: [u8; 32] = [0x42; 32];
const WRONG_TOKEN: [u8; 32] = [0x99; 32];

async fn spin_up_server() -> (TunnelServer, TempDir) {
    spin_up_server_with(vec![]).await
}

async fn spin_up_server_with(hostnames: Vec<HostnameEntry>) -> (TunnelServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: None,
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        acme: None,
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: VALID_TOKEN,
        }],
        hostnames,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    (server, dir)
}

fn host_entry(host: &str, tls_mode: TlsMode) -> HostnameEntry {
    HostnameEntry {
        host: host.into(),
        client: "service-a".into(),
        tls_mode,
    }
}

async fn wait_active_hostnames(server: &TunnelServer, expected: Vec<String>) {
    let target = expected.clone();
    for _ in 0..50 {
        if server.active_hostnames() == target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "timed out: expected active_hostnames={:?}, got {:?}",
        expected,
        server.active_hostnames()
    );
}

fn client_config_for(
    server: &TunnelServer,
    token: [u8; 32],
    fingerprint: [u8; 32],
) -> ClientConfig {
    let port = server.local_addr().unwrap().port();
    ClientConfig {
        server_addr: format!("127.0.0.1:{port}"),
        server_cert_fingerprint_sha256: fingerprint,
        token,
        client_name: "alice".into(),
        ingress: vec![],
    }
}

#[tokio::test]
async fn connects_with_valid_token() {
    let (server, _dir) = spin_up_server().await;
    let cfg = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());

    let client = TunnelClient::connect(cfg).await.unwrap();
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn rejected_on_wrong_token() {
    let (server, _dir) = spin_up_server().await;
    let cfg = client_config_for(&server, WRONG_TOKEN, server.cert_fingerprint());

    let err = TunnelClient::connect(cfg).await.unwrap_err();
    match err {
        ClientError::Rejected(reason) => {
            assert!(reason.contains("invalid"), "got reason {reason:?}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn fails_on_wrong_fingerprint() {
    let (server, _dir) = spin_up_server().await;
    let bogus_fingerprint = [0xAB; 32];
    let cfg = client_config_for(&server, VALID_TOKEN, bogus_fingerprint);

    let err = TunnelClient::connect(cfg).await.unwrap_err();
    // The TLS handshake should fail before we ever exchange a Hello frame.
    assert!(
        !matches!(err, ClientError::Rejected(_)),
        "fingerprint mismatch should not surface as a Rejected response, got {err:?}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn fails_on_unreachable_server() {
    // Bind a UDP socket on an ephemeral port, drop it, and try to connect to its
    // address. The port is almost certainly free immediately after the drop, so
    // connect attempts go nowhere.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    drop(sock);

    let cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{}", addr.port()),
        server_cert_fingerprint_sha256: [0u8; 32],
        token: VALID_TOKEN,
        client_name: "alice".into(),
        ingress: vec![],
    };

    let err = TunnelClient::connect(cfg).await.unwrap_err();

    match err {
        ClientError::ConnectTimeout
        | ClientError::QuicConnection(_)
        | ClientError::QuicConnect(_) => {}
        other => panic!("expected connection failure, got {other:?}"),
    }
}

#[tokio::test]
async fn populates_active_hostnames_on_connect() {
    let (server, _dir) = spin_up_server_with(vec![
        host_entry("alpha.example.com", TlsMode::Terminated),
        host_entry("beta.example.com", TlsMode::Passthrough),
    ])
    .await;
    assert!(server.active_hostnames().is_empty());

    let cfg = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());
    let client = TunnelClient::connect(cfg).await.unwrap();

    // install happens before Welcome, so by the time connect() resolves the
    // server-side routing table is already populated. No polling needed here.
    assert_eq!(
        server.active_hostnames(),
        vec![
            "alpha.example.com".to_string(),
            "beta.example.com".to_string()
        ]
    );

    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn clears_active_hostnames_on_disconnect() {
    let (server, _dir) =
        spin_up_server_with(vec![host_entry("alpha.example.com", TlsMode::Terminated)]).await;
    let cfg = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());

    let client = TunnelClient::connect(cfg).await.unwrap();
    assert_eq!(
        server.active_hostnames(),
        vec!["alpha.example.com".to_string()]
    );

    client.shutdown().await;
    // The server's handler observes conn.closed() then removes the routes; this
    // is asynchronous from the client's perspective, so we poll briefly.
    wait_active_hostnames(&server, vec![]).await;

    server.shutdown().await;
}

#[tokio::test]
async fn last_write_wins_kicks_previous_connection() {
    let (server, _dir) =
        spin_up_server_with(vec![host_entry("alpha.example.com", TlsMode::Terminated)]).await;

    let cfg_a = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());
    let client_a = TunnelClient::connect(cfg_a).await.unwrap();
    assert_eq!(
        server.active_hostnames(),
        vec!["alpha.example.com".to_string()]
    );

    let cfg_b = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());
    let client_b = TunnelClient::connect(cfg_b).await.unwrap();

    // Connection A must close shortly after B's install kicks it.
    tokio::time::timeout(Duration::from_secs(2), client_a.wait_closed())
        .await
        .expect("connection A should have been kicked within 2s");

    // Routes remain populated, now owned by B.
    assert_eq!(
        server.active_hostnames(),
        vec!["alpha.example.com".to_string()]
    );

    client_b.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn client_without_assigned_hostnames_does_not_affect_table() {
    // Server has a client entry but no [[hostnames]] pointing at it.
    let (server, _dir) = spin_up_server_with(vec![]).await;
    let cfg = client_config_for(&server, VALID_TOKEN, server.cert_fingerprint());

    let client = TunnelClient::connect(cfg).await.unwrap();
    assert!(server.active_hostnames().is_empty());

    client.shutdown().await;
    server.shutdown().await;
}
