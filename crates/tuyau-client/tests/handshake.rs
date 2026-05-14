use tempfile::TempDir;

use tuyau_client::{ClientConfig, ClientError, TunnelClient};
use tuyau_server::{ClientEntry, ServerConfig, TunnelServer};

const VALID_TOKEN: [u8; 32] = [0x42; 32];
const WRONG_TOKEN: [u8; 32] = [0x99; 32];

async fn spin_up_server() -> (TunnelServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: VALID_TOKEN,
        }],
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    (server, dir)
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
    };

    let err = TunnelClient::connect(cfg).await.unwrap_err();

    match err {
        ClientError::ConnectTimeout
        | ClientError::QuicConnection(_)
        | ClientError::QuicConnect(_) => {}
        other => panic!("expected connection failure, got {other:?}"),
    }
}
