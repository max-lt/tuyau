use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use tuyau_protocol::{ALPN, FrameCodec, Hello, HelloResponse};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::backend::{RoutingBackend, StaticBackend};
use crate::cert::{self, CertMaterial};
use crate::config::{AcmeSection, ServerConfig, TlsMode};
use crate::control::{Control, TunnelInfo};
use crate::error::ServerError;
use crate::public;
use crate::routes::RoutingTable;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
// Tunnel liveness. A silently-dead tunnel (killed process, severed network) is
// detected only once MAX_IDLE elapses with no packets received, so MAX_IDLE
// bounds how long a dead round-robin member stays in rotation. KEEP_ALIVE must
// sit comfortably below the peer's MAX_IDLE (the client mirrors these values)
// so a healthy tunnel is never falsely dropped — here ~3 keep-alives fit in one
// idle window.
const KEEP_ALIVE: Duration = Duration::from_secs(7);
const MAX_IDLE: Duration = Duration::from_secs(20);
// How long to keep a rejected connection open so its reject frame can flush and
// the peer can close, before force-closing it. Bounds the resource a peer that
// never closes can pin (it must not be held until MAX_IDLE).
const REJECT_LINGER: Duration = Duration::from_secs(2);
// Upper bound on a RoutingBackend admit decision. A dynamic backend may do I/O
// (DB / control-plane lookup); without a bound a hung backend would stall the
// handler forever (keep-alives stop the idle timeout from reaping it).
const ADMIT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TunnelServer {
    endpoint: Endpoint,
    fingerprint: [u8; 32],
    routes: RoutingTable,
    // Read only via the `dynamic`-gated tunnels()/subscribe(); still populated
    // (no-op) without the feature so the accept loop can notify it.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    control: Control,
    public_addr: Option<SocketAddr>,
    cancel: CancellationToken,
    accept_handle: JoinHandle<()>,
    public_handle: Option<JoinHandle<()>>,
    acme_handle: Option<JoinHandle<()>>,
}

impl TunnelServer {
    pub async fn start(config: ServerConfig) -> Result<Self, ServerError> {
        config.validate()?;
        let backend: Arc<dyn RoutingBackend> = Arc::new(StaticBackend::new(&config));
        Self::start_inner(backend, config).await
    }

    /// Start with a caller-provided [`RoutingBackend`] instead of the static
    /// config-file one. Available with the `dynamic` feature. The backend owns
    /// identity + routing decisions, so `config.clients` and `config.hostnames`
    /// are ignored — everything else (listen addrs, certs, ACME) still applies.
    #[cfg(feature = "dynamic")]
    pub async fn start_with(
        backend: Arc<dyn RoutingBackend>,
        config: ServerConfig,
    ) -> Result<Self, ServerError> {
        config.validate_dynamic()?;
        Self::start_inner(backend, config).await
    }

    async fn start_inner(
        backend: Arc<dyn RoutingBackend>,
        config: ServerConfig,
    ) -> Result<Self, ServerError> {
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

        // Optional public listener — only spawned if configured. The cert
        // resolver is either a static self-signed multi-SAN cert (dev mode)
        // or rustls-acme's resolver (ACME mode, real LE certs via
        // TLS-ALPN-01).
        let (public_addr, public_handle, acme_handle) = match config.public_listen_addr {
            Some(addr) => {
                let terminated_hostnames: Vec<String> = config
                    .hostnames
                    .iter()
                    .filter(|h| h.tls_mode == TlsMode::Terminated)
                    .map(|h| h.host.clone())
                    .collect();

                let (resolver, acme_handle) = build_cert_resolver(
                    &config.acme,
                    &config.tls_cert_file,
                    &config.tls_key_file,
                    &terminated_hostnames,
                    &cert_dir,
                    cancel.clone(),
                )?;
                let acme_active = acme_handle.is_some();

                let handle = public::start(
                    addr,
                    resolver,
                    acme_active,
                    routes.clone(),
                    cancel.clone(),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, listen_addr = %addr, "public listener bind failed");
                    e
                })?;
                tracing::info!(
                    listen_addr = %handle.local_addr,
                    terminated_hostnames = terminated_hostnames.len(),
                    acme = acme_active,
                    "public TLS listener active"
                );
                (Some(handle.local_addr), Some(handle.join), acme_handle)
            }
            None => (None, None, None),
        };

        let control = Control::new();
        let endpoint_clone = endpoint.clone();
        let routes_clone = routes.clone();
        let control_clone = control.clone();
        let cancel_clone = cancel.clone();

        let accept_handle = tokio::spawn(async move {
            accept_loop(
                endpoint_clone,
                backend,
                routes_clone,
                control_clone,
                cancel_clone,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            fingerprint,
            routes,
            control,
            public_addr,
            cancel,
            accept_handle,
            public_handle,
            acme_handle,
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

    /// Snapshot of currently connected tunnels (metadata only). Behind the
    /// `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn tunnels(&self) -> Vec<TunnelInfo> {
        self.control.tunnels()
    }

    /// Subscribe to the live tunnel-event stream (metadata only). Behind the
    /// `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::control::ControlEvent> {
        self.control.subscribe()
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"server shutdown");
        let _ = self.accept_handle.await;
        if let Some(h) = self.public_handle {
            let _ = h.await;
        }
        if let Some(h) = self.acme_handle {
            let _ = h.await;
        }
        self.endpoint.wait_idle().await;
    }
}

/// Cert resolver plus the ACME renewal task handle when ACME is active.
type ResolverBundle = (Arc<dyn ResolvesServerCert>, Option<JoinHandle<()>>);

/// Build the cert resolver the public listener should use: rustls-acme's
/// dynamic resolver if `[acme]` is configured (with a background renewal
/// task), or a static resolver over a fresh self-signed multi-SAN cert
/// otherwise.
fn build_cert_resolver(
    acme: &Option<AcmeSection>,
    tls_cert_file: &Option<std::path::PathBuf>,
    tls_key_file: &Option<std::path::PathBuf>,
    terminated_hostnames: &[String],
    cert_dir: &std::path::Path,
    cancel: CancellationToken,
) -> Result<ResolverBundle, ServerError> {
    if let Some(acme_cfg) = acme {
        if terminated_hostnames.is_empty() {
            tracing::warn!(
                "[acme] configured but no terminated hostnames — falling back to a placeholder self-signed cert (passthrough-only deployment?)"
            );
        } else {
            let (resolver, handle) = build_acme_resolver(acme_cfg, terminated_hostnames, cancel)?;
            return Ok((resolver, Some(handle)));
        }
    }
    // Static cert (e.g. obtained out-of-band via DNS-01). Takes precedence over
    // the self-signed fallback when both cert and key paths are configured.
    if let (Some(cert_file), Some(key_file)) = (tls_cert_file, tls_key_file) {
        let (chain, key) = cert::load_chain(cert_file, key_file)?;
        tracing::info!(
            cert = %cert_file.display(),
            chain_len = chain.len(),
            "serving static TLS cert on public listener"
        );
        return Ok((build_static_chain_resolver(chain, key)?, None));
    }
    let public_cert = cert::generate_public_cert(terminated_hostnames, cert_dir)?;
    Ok((build_static_resolver(public_cert)?, None))
}

fn build_static_chain_resolver(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<dyn ResolvesServerCert>, ServerError> {
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&key).map_err(ServerError::Tls)?;
    let certified = CertifiedKey::new(chain, signing_key);
    Ok(Arc::new(StaticResolver(Arc::new(certified))))
}

fn build_static_resolver(
    material: CertMaterial,
) -> Result<Arc<dyn ResolvesServerCert>, ServerError> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&material.key_der)
        .map_err(ServerError::Tls)?;
    let certified = CertifiedKey::new(vec![material.cert_der], signing_key);
    Ok(Arc::new(StaticResolver(Arc::new(certified))))
}

fn build_acme_resolver(
    cfg: &AcmeSection,
    hostnames: &[String],
    cancel: CancellationToken,
) -> Result<(Arc<dyn ResolvesServerCert>, JoinHandle<()>), ServerError> {
    use futures_util::StreamExt;
    use rustls_acme::{AcmeConfig, caches::DirCache};

    let mut state = AcmeConfig::new(hostnames.to_vec())
        .contact_push(&cfg.contact)
        .cache(DirCache::new(cfg.cache_dir.clone()))
        .directory_lets_encrypt(cfg.production)
        .state();
    let resolver = state.resolver();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::debug!("acme renewal loop cancelled");
                    break;
                }
                event = state.next() => {
                    match event {
                        Some(Ok(ok)) => tracing::info!("acme: {:?}", ok),
                        Some(Err(err)) => tracing::warn!(error = ?err, "acme error"),
                        None => {
                            tracing::debug!("acme state stream ended");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok((resolver, handle))
}

/// Always returns the same `CertifiedKey` — used for the dev-mode multi-SAN
/// self-signed cert. ACME mode uses rustls-acme's dynamic resolver instead.
#[derive(Debug)]
struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
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
    backend: Arc<dyn RoutingBackend>,
    routes: RoutingTable,
    control: Control,
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
                let backend = Arc::clone(&backend);
                let routes = routes.clone();
                let control = control.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(incoming, backend, routes, control, cancel).await
                    {
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
    backend: Arc<dyn RoutingBackend>,
    routes: RoutingTable,
    control: Control,
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
        Ok(Some(Ok(hello))) => {
            match tokio::time::timeout(ADMIT_TIMEOUT, backend.admit(&hello.token)).await {
                Ok(Some(grant)) => {
                    // The backend may have taken time (dynamic backends do I/O). If
                    // the peer went away while we waited, drop instead of installing
                    // a dead tunnel — and so a late grant can't displace a newer
                    // connection that already took the host (the install drain is
                    // order-blind).
                    if connection.close_reason().is_some() {
                        tracing::debug!(peer = %peer, "connection closed during admit; dropping");
                        return Ok(());
                    }

                    let host_list: Vec<&str> =
                        grant.hostnames.iter().map(|(h, _)| h.as_str()).collect();

                    for prev in routes.install(
                        grant.hostnames.clone(),
                        &grant.client_name,
                        grant.balance,
                        &connection,
                    ) {
                        tracing::info!(name = %grant.client_name, "kicking previous connection");
                        prev.close(0u32.into(), b"replaced by new connection");
                    }

                    tracing::info!(
                        peer = %peer,
                        name = %grant.client_name,
                        client_name = %hello.client_name,
                        hosts = ?host_list,
                        "client connected"
                    );

                    match writer.send(HelloResponse::Welcome).await {
                        Ok(()) => {
                            control.register(
                                connection.stable_id(),
                                TunnelInfo {
                                    client_name: grant.client_name.clone(),
                                    peer,
                                    hostnames: grant
                                        .hostnames
                                        .iter()
                                        .map(|(h, _)| h.clone())
                                        .collect(),
                                },
                            );
                            Outcome::Welcome
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer, error = %e, "failed to send welcome");
                            routes.remove_conn(connection.stable_id());
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {
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
                Err(_) => {
                    tracing::warn!(peer = %peer, "backend admit timed out; rejecting");
                    let _ = writer
                        .send(HelloResponse::Reject {
                            reason: "authorization timeout".into(),
                        })
                        .await;
                    Outcome::Reject
                }
            }
        }
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

    // Stream closed before a hello arrived — nothing was sent; just drop.
    if matches!(outcome, Outcome::NoResponse) {
        return Ok(());
    }

    // Cleanly close the send stream so the peer reads it as EOF (not a reset).
    let mut send = writer.into_inner();
    let _ = send.finish();

    // A reject was sent. Wait for the peer to read it and close, but only up to
    // REJECT_LINGER, then force-close. Parking a rejected (i.e. unauthenticated)
    // connection until the QUIC idle timeout lets a peer that never closes pin
    // server resources without a token; the linger still lets the reject frame
    // flush to a well-behaved peer.
    if matches!(outcome, Outcome::Reject) {
        let _ = tokio::time::timeout(REJECT_LINGER, connection.closed()).await;
        connection.close(1u32.into(), b"rejected");
        return Ok(());
    }

    // Authenticated tunnel (Outcome::Welcome): hold the connection open until the
    // peer closes it or we cancel. The QUIC idle timeout is the safety-net if
    // the peer abandons it.
    let stable_id = connection.stable_id();
    tokio::select! {
        _ = cancel.cancelled() => {
            connection.close(0u32.into(), b"server shutdown");
        }
        _ = connection.closed() => {
            tracing::debug!(peer = %peer, "connection closed by peer");
        }
    }

    routes.remove_conn(stable_id);
    control.unregister(stable_id);
    Ok(())
}
