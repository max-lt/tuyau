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
use crate::config::{ClientEntry, ServerConfig, TlsMode};
use crate::error::ServerError;
use crate::public;
use crate::routes::RoutingTable;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const MAX_IDLE: Duration = Duration::from_secs(60);

pub struct TunnelServer {
    endpoint: Endpoint,
    fingerprint: [u8; 32],
    routes: RoutingTable,
    public_addr: Option<SocketAddr>,
    cancel: CancellationToken,
    accept_handle: JoinHandle<()>,
    public_handle: Option<JoinHandle<()>>,
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
            hostnames = config.hostnames.len(),
            cert_dir = %cert_dir.display(),
            "starting tuyau-server"
        );

        let rustls_config = build_rustls_config(&material)?;
        let quinn_config = build_quinn_config(rustls_config)?;

        let endpoint = Endpoint::server(quinn_config, config.listen_addr)?;
        let fingerprint = material.fingerprint;

        let cancel = CancellationToken::new();
        let routes = RoutingTable::new();

        // Optional public listener — only spawned if configured. Generates a
        // fresh multi-SAN self-signed cert per startup over the configured
        // terminated hostnames. M5e will replace this with ACME-issued certs.
        let (public_addr, public_handle) = match config.public_listen_addr {
            Some(addr) => {
                let terminated_hostnames: Vec<String> = config
                    .hostnames
                    .iter()
                    .filter(|h| h.tls_mode == TlsMode::Terminated)
                    .map(|h| h.host.clone())
                    .collect();
                let public_cert = cert::generate_public_cert(&terminated_hostnames, &cert_dir)?;
                let handle = public::start(addr, public_cert, routes.clone(), cancel.clone())
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, listen_addr = %addr, "public listener bind failed");
                        e
                    })?;
                tracing::info!(
                    listen_addr = %handle.local_addr,
                    hostnames = terminated_hostnames.len(),
                    "public TLS listener active"
                );
                (Some(handle.local_addr), Some(handle.join))
            }
            None => (None, None),
        };

        let config = Arc::new(config);
        let endpoint_clone = endpoint.clone();
        let routes_clone = routes.clone();
        let cancel_clone = cancel.clone();

        let accept_handle = tokio::spawn(async move {
            accept_loop(endpoint_clone, config, routes_clone, cancel_clone).await;
        });

        Ok(Self {
            endpoint,
            fingerprint,
            routes,
            public_addr,
            cancel,
            accept_handle,
            public_handle,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Address the public TLS listener is bound to, or `None` if the server
    /// was configured without a `public_listen_addr`.
    pub fn public_local_addr(&self) -> Option<SocketAddr> {
        self.public_addr
    }

    pub fn cert_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Sorted snapshot of currently active hostnames (a hostname is "active"
    /// while its owning client tunnel is connected).
    pub fn active_hostnames(&self) -> Vec<String> {
        self.routes.active_hostnames()
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"server shutdown");
        let _ = self.accept_handle.await;
        if let Some(h) = self.public_handle {
            let _ = h.await;
        }
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

async fn accept_loop(
    endpoint: Endpoint,
    config: Arc<ServerConfig>,
    routes: RoutingTable,
    cancel: CancellationToken,
) {
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
                let routes = routes.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(incoming, config, routes, cancel).await {
                        tracing::warn!(error = %e, "connection handler error");
                    }
                });
            }
        }
    }
}

/// Outcome of the handshake; determines whether routes were installed and
/// therefore whether cleanup is needed after the connection ends.
enum Outcome {
    Welcome,
    Reject,
    NoResponse,
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    config: Arc<ServerConfig>,
    routes: RoutingTable,
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

    let outcome = match hello_result {
        Ok(Some(Ok(hello))) => match match_token(&hello.token, &config.clients) {
            Some(matched_name) => {
                let assigned: Vec<(String, TlsMode)> = config
                    .hostnames
                    .iter()
                    .filter(|h| h.client == matched_name)
                    .map(|h| (h.host.clone(), h.tls_mode))
                    .collect();

                let host_list: Vec<&str> = assigned.iter().map(|(h, _)| h.as_str()).collect();

                if let Some(prev) = routes.install(assigned.clone(), &matched_name, &connection) {
                    tracing::info!(
                        name = %matched_name,
                        "kicking previous connection (last-write-wins)"
                    );
                    prev.close(0u32.into(), b"replaced by new connection");
                }

                tracing::info!(
                    peer = %peer,
                    name = %matched_name,
                    client_name = %hello.client_name,
                    hosts = ?host_list,
                    "client connected"
                );

                match writer.send(HelloResponse::Welcome).await {
                    Ok(()) => Outcome::Welcome,
                    Err(e) => {
                        tracing::warn!(peer = %peer, error = %e, "failed to send welcome");
                        routes.remove_conn(connection.stable_id());
                        return Ok(());
                    }
                }
            }
            None => {
                tracing::warn!(
                    peer = %peer,
                    client_name = %hello.client_name,
                    "client rejected: invalid token"
                );
                let _ = writer
                    .send(HelloResponse::Reject {
                        reason: "invalid token".into(),
                    })
                    .await;
                Outcome::Reject
            }
        },
        Ok(Some(Err(e))) => {
            tracing::warn!(peer = %peer, error = %e, "hello decode failed");
            let _ = writer
                .send(HelloResponse::Reject {
                    reason: "protocol error".into(),
                })
                .await;
            Outcome::Reject
        }
        Ok(None) => {
            tracing::warn!(peer = %peer, "stream closed before hello");
            Outcome::NoResponse
        }
        Err(_) => {
            tracing::warn!(peer = %peer, "timed out waiting for hello frame");
            let _ = writer
                .send(HelloResponse::Reject {
                    reason: "protocol error".into(),
                })
                .await;
            Outcome::Reject
        }
    };

    if matches!(outcome, Outcome::NoResponse) {
        return Ok(());
    }

    // Cleanly close the send stream so the peer reads it as EOF (not a reset).
    let mut send = writer.into_inner();
    let _ = send.finish();

    // Hold the connection open until the peer closes it or we cancel. The QUIC
    // idle timeout (max_idle_timeout) is the safety-net if the peer abandons.
    let stable_id = connection.stable_id();
    tokio::select! {
        _ = cancel.cancelled() => {
            connection.close(0u32.into(), b"server shutdown");
        }
        _ = connection.closed() => {
            tracing::debug!(peer = %peer, "connection closed by peer");
        }
    }

    if matches!(outcome, Outcome::Welcome) {
        routes.remove_conn(stable_id);
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
