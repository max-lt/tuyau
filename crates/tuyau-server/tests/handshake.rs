use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tempfile::TempDir;
use tokio_util::codec::{FramedRead, FramedWrite};

use tuyau_protocol::{ALPN, FrameCodec, Hello, HelloResponse};
use tuyau_server::{ClientEntry, ServerConfig, TunnelServer};

const VALID_TOKEN: [u8; 32] = [0x42; 32];
const WRONG_TOKEN: [u8; 32] = [0x99; 32];

async fn spin_up_server() -> (TunnelServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let config = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: VALID_TOKEN,
        }],
        hostnames: vec![],
    };
    let server = TunnelServer::start(config).await.unwrap();
    (server, dir)
}

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

fn make_client_endpoint(alpn: &[u8]) -> Endpoint {
    let mut rustls = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    rustls.alpn_protocols = vec![alpn.to_vec()];

    let quic_crypto = QuicClientConfig::try_from(rustls).unwrap();
    let client_config = QuinnClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

#[tokio::test]
async fn welcome_on_valid_token() {
    let (server, _dir) = spin_up_server().await;
    let server_addr = server.local_addr().unwrap();
    let endpoint = make_client_endpoint(ALPN);
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let (send, recv) = connection.open_bi().await.unwrap();
    let mut writer = FramedWrite::new(send, FrameCodec::<Hello>::new());
    let mut reader = FramedRead::new(recv, FrameCodec::<HelloResponse>::new());

    writer
        .send(Hello {
            token: VALID_TOKEN,
            client_name: "alice".into(),
        })
        .await
        .unwrap();

    let response = reader.next().await.unwrap().unwrap();
    assert_eq!(response, HelloResponse::Welcome);

    connection.close(0u32.into(), b"test done");
    drop(connection);
    endpoint.close(0u32.into(), b"test done");
    server.shutdown().await;
}

#[tokio::test]
async fn reject_on_wrong_token() {
    let (server, _dir) = spin_up_server().await;
    let server_addr = server.local_addr().unwrap();
    let endpoint = make_client_endpoint(ALPN);
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let (send, recv) = connection.open_bi().await.unwrap();
    let mut writer = FramedWrite::new(send, FrameCodec::<Hello>::new());
    let mut reader = FramedRead::new(recv, FrameCodec::<HelloResponse>::new());

    writer
        .send(Hello {
            token: WRONG_TOKEN,
            client_name: "evil".into(),
        })
        .await
        .unwrap();

    let response = reader.next().await.unwrap().unwrap();
    match response {
        HelloResponse::Reject { reason } => assert!(reason.contains("invalid"), "got {reason:?}"),
        other => panic!("expected Reject, got {other:?}"),
    }

    connection.close(0u32.into(), b"test done");
    drop(connection);
    endpoint.close(0u32.into(), b"test done");
    server.shutdown().await;
}

#[tokio::test]
async fn reject_on_malformed_bytes() {
    let (server, _dir) = spin_up_server().await;
    let server_addr = server.local_addr().unwrap();
    let endpoint = make_client_endpoint(ALPN);
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let (mut send, recv) = connection.open_bi().await.unwrap();
    // 4-byte BE length prefix = 3, then 3 bytes that don't decode as a Hello.
    send.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    let _ = send.finish();

    let mut reader = FramedRead::new(recv, FrameCodec::<HelloResponse>::new());
    let response = reader.next().await.unwrap().unwrap();
    match response {
        HelloResponse::Reject { reason } => assert!(reason.contains("protocol"), "got {reason:?}"),
        other => panic!("expected Reject, got {other:?}"),
    }

    connection.close(0u32.into(), b"test done");
    drop(connection);
    endpoint.close(0u32.into(), b"test done");
    server.shutdown().await;
}

#[tokio::test]
async fn server_closes_silent_client() {
    let (server, _dir) = spin_up_server().await;
    let server_addr = server.local_addr().unwrap();
    let endpoint = make_client_endpoint(ALPN);
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Don't open a bidi stream; the server's accept_bi will time out after 5s.
    let result = tokio::time::timeout(Duration::from_secs(10), connection.closed()).await;
    assert!(
        result.is_ok(),
        "server did not close silent connection in time"
    );

    drop(connection);
    endpoint.close(0u32.into(), b"test done");
    server.shutdown().await;
}

#[tokio::test]
async fn fingerprint_stable_across_restarts() {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "a".into(),
            token: VALID_TOKEN,
        }],
        hostnames: vec![],
    };

    let server1 = TunnelServer::start(cfg.clone()).await.unwrap();
    let fp1 = server1.cert_fingerprint();
    server1.shutdown().await;

    let server2 = TunnelServer::start(cfg).await.unwrap();
    let fp2 = server2.cert_fingerprint();
    server2.shutdown().await;

    assert_eq!(fp1, fp2);
}

#[tokio::test]
async fn wrong_alpn_rejected() {
    let (server, _dir) = spin_up_server().await;
    let server_addr = server.local_addr().unwrap();

    let endpoint = make_client_endpoint(b"bogus");
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(server_addr, "localhost").unwrap(),
    )
    .await;

    let connect_result = result.expect("connection should resolve quickly");
    assert!(
        connect_result.is_err(),
        "expected connection failure due to ALPN mismatch, got {connect_result:?}"
    );

    endpoint.close(0u32.into(), b"test done");
    server.shutdown().await;
}
