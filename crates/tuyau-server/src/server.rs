use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig as RustlsServerConfig;
use subtle::ConstantTimeEq;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use tuyau_protocol::{ALPN, FrameCodec, Hello, HelloResponse};

use crate::cert::{self, CertMaterial};
use crate::config::{ClientEntry, ServerConfig};
use crate::error::ServerError;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const MAX_IDLE: Duration = Duration::from_secs(60);

pub struct TunnelServer {
    endpoint: Endpoint,
    fingerprint: [u8; 32],
    cancel: CancellationToken,
    accept_handle: JoinHandle<()>,
}

impl TunnelServer {
    pub async fn start(config: ServerConfig) -> Result<Self, ServerError> {
        config.validate()?;

        let cert_dir = resolve_cert_dir(&config.tunnel_cert_dir);
        let material = cert::load_or_generate(&cert_dir)?;

        tracing::info!(
            fingerprint = %hex::encode(material.fingerprint),
            listen_addr = %config.listen_addr,
            clients = config.clients.len(),
            cert_dir = %cert_dir.display(),
            "starting tuyau-server"
        );

        let rustls_config = build_rustls_config(&material)?;
        let quinn_config = build_quinn_config(rustls_config)?;

        let endpoint = Endpoint::server(quinn_config, config.listen_addr)?;
        let fingerprint = material.fingerprint;

        let cancel = CancellationToken::new();
        let config = Arc::new(config);
        let endpoint_clone = endpoint.clone();
        let cancel_clone = cancel.clone();

        let accept_handle = tokio::spawn(async move {
            accept_loop(endpoint_clone, config, cancel_clone).await;
        });

        Ok(Self {
            endpoint,
            fingerprint,
            cancel,
            accept_handle,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn cert_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"server shutdown");
        let _ = self.accept_handle.await;
        self.endpoint.wait_idle().await;
    }
}

fn resolve_cert_dir(configured: &Option<PathBuf>) -> PathBuf {
    configured.clone().unwrap_or_else(|| PathBuf::from("."))
}

fn build_rustls_config(material: &CertMaterial) -> Result<RustlsServerConfig, ServerError> {
    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(ServerError::Tls)?
    .with_no_client_auth()
    .with_single_cert(
        vec![material.cert_der.clone()],
        material.key_der.clone_key(),
    )?;
    config.alpn_protocols = vec![ALPN.to_vec()];

    Ok(config)
}

fn build_quinn_config(rustls_config: RustlsServerConfig) -> Result<QuinnServerConfig, ServerError> {
    let quic_crypto = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        MAX_IDLE.try_into().expect("MAX_IDLE fits in a QUIC VarInt"),
    ));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

async fn accept_loop(endpoint: Endpoint, config: Arc<ServerConfig>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("accept loop cancelled");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    tracing::debug!("endpoint closed");
                    break;
                };
                let config = Arc::clone(&config);
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(incoming, config, cancel).await {
                        tracing::warn!(error = %e, "connection handler error");
                    }
                });
            }
        }
    }
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    config: Arc<ServerConfig>,
    cancel: CancellationToken,
) -> Result<(), ServerError> {
    let connection = incoming.await?;
    let peer = connection.remote_address();
    tracing::debug!(peer = %peer, "incoming connection accepted");

    let streams = tokio::time::timeout(HELLO_TIMEOUT, connection.accept_bi()).await;

    let (send, recv) = match streams {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer, error = %e, "accept_bi failed");
            return Ok(());
        }
        Err(_) => {
            tracing::warn!(peer = %peer, "timed out waiting for client stream");
            connection.close(1u32.into(), b"hello timeout");
            return Ok(());
        }
    };

    let mut reader = FramedRead::new(recv, FrameCodec::<Hello>::new());
    let mut writer = FramedWrite::new(send, FrameCodec::<HelloResponse>::new());

    let hello_result = tokio::time::timeout(HELLO_TIMEOUT, reader.next()).await;

    let response: Option<HelloResponse> = match hello_result {
        Ok(Some(Ok(hello))) => match match_token(&hello.token, &config.clients) {
            Some(name) => {
                tracing::info!(
                    peer = %peer,
                    name = %name,
                    client_name = %hello.client_name,
                    "client connected"
                );
                Some(HelloResponse::Welcome)
            }
            None => {
                tracing::warn!(
                    peer = %peer,
                    client_name = %hello.client_name,
                    "client rejected: invalid token"
                );
                Some(HelloResponse::Reject {
                    reason: "invalid token".into(),
                })
            }
        },
        Ok(Some(Err(e))) => {
            tracing::warn!(peer = %peer, error = %e, "hello decode failed");
            Some(HelloResponse::Reject {
                reason: "protocol error".into(),
            })
        }
        Ok(None) => {
            tracing::warn!(peer = %peer, "stream closed before hello");
            None
        }
        Err(_) => {
            tracing::warn!(peer = %peer, "timed out waiting for hello frame");
            Some(HelloResponse::Reject {
                reason: "protocol error".into(),
            })
        }
    };

    let Some(response) = response else {
        return Ok(());
    };

    let send_result = writer.send(response).await;
    if let Err(e) = send_result {
        tracing::warn!(peer = %peer, error = %e, "failed to send response");
        return Ok(());
    }

    // Cleanly close the send stream so the peer reads it as EOF (not a reset).
    let mut send = writer.into_inner();
    let _ = send.finish();

    // Hold the connection open until the peer closes it or we cancel. Safety-net
    // via the QUIC idle timeout (max_idle_timeout) if the peer abandons silently.
    tokio::select! {
        _ = cancel.cancelled() => {
            connection.close(0u32.into(), b"server shutdown");
        }
        _ = connection.closed() => {
            tracing::debug!(peer = %peer, "connection closed by peer");
        }
    }

    Ok(())
}

fn match_token(token: &[u8; 32], clients: &[ClientEntry]) -> Option<String> {
    let mut matched: Option<&str> = None;
    for c in clients {
        if token.ct_eq(&c.token).into() {
            matched = Some(&c.name);
        }
    }
    matched.map(str::to_owned)
}
