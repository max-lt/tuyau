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

use crate::backend::{RoutingBackend, StaticBackend};
use crate::cert::{self, CertMaterial};
use crate::config::ServerConfig;
#[cfg(feature = "dynamic")]
use crate::config::{IssuerEntry, TerminatedHost};
use crate::control::{Control, TunnelInfo};
use crate::error::ServerError;
use crate::host_certs::HostCerts;
#[cfg(feature = "dynamic")]
use crate::issuers::HostIssuer;
use crate::issuers::Issuers;
use crate::public;
use crate::routes::RoutingTable;
#[cfg(feature = "dynamic")]
use std::collections::HashMap;

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
    // The cert issuers of the public listener. Their ACME tasks are tied to
    // `cancel`, so shutdown stops them without an explicit await.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    issuers: Option<Arc<Issuers>>,
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
        let routes = RoutingTable::from_config(&config.hostnames, &config.upstreams);

        // Optional public listener, only spawned if configured. A host with a
        // cert file serves it; the others take the cert of their issuer.
        let (public_addr, public_handle, issuers) = match config.public_listen_addr {
            Some(addr) => {
                let host_certs = HostCerts::load(&config)?;
                let issuers = Arc::new(Issuers::new(&config, cancel.clone())?);
                let terminated = routes.terminated_hosts();
                issuers.plan_acme(&terminated);

                let resolver = host_certs.resolver(issuers.clone());
                let client_cert = match &config.client_ca_file {
                    Some(path) => public::ClientCert::SignedBy(Arc::new(cert::load_roots(path)?)),
                    None => public::ClientCert::Any,
                };

                let max_conns = config
                    .max_public_connections
                    .unwrap_or(public::DEFAULT_MAX_PUBLIC_CONNECTIONS);
                // A deployment can brand the 502 page (e.g. add a dashboard
                // link); fall back to the built-in if unset or unreadable.
                let error_502: Arc<str> = match &config.error_502_file {
                    Some(path) => match std::fs::read_to_string(path) {
                        Ok(html) => Arc::from(html),
                        Err(e) => {
                            tracing::warn!(error = %e, path = %path.display(), "error_502_file unreadable, using built-in");
                            Arc::from(public::DEFAULT_502_HTML)
                        }
                    },
                    None => Arc::from(public::DEFAULT_502_HTML),
                };
                let tls = public::PublicTls::new(resolver, client_cert)?;
                let handle = public::start(
                    addr,
                    tls,
                    routes.clone(),
                    max_conns,
                    error_502,
                    cancel.clone(),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, listen_addr = %addr, "public listener bind failed");
                    e
                })?;
                tracing::info!(
                    listen_addr = %handle.local_addr,
                    terminated_hostnames = terminated.len(),
                    "public TLS listener active"
                );
                (Some(handle.local_addr), Some(handle.join), Some(issuers))
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
            issuers,
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

    /// Liveness for a process watchdog: `false` if an accept loop has stopped
    /// (panicked or exited), which would silently stop serving new connections
    /// while the process stays up. A supervisor (e.g. systemd via sd_notify)
    /// should withhold its watchdog ping on `false` and let the process restart.
    /// Cheap and non-blocking (no locks) — safe to call on a tight timer.
    pub fn healthy(&self) -> bool {
        if self.accept_handle.is_finished() {
            return false;
        }
        !self
            .public_handle
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
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

    /// Revoke a client: close all of its connected tunnels now. Returns the
    /// number of connections closed. Each closed tunnel surfaces a `TunnelDown`
    /// event once its handler observes the close. This only terminates *current*
    /// tunnels — to prevent reconnection the [`RoutingBackend`] must also stop
    /// admitting the client. Behind the `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn kick(&self, client_name: &str) -> usize {
        let conns = self.routes.kick(client_name);
        let n = conns.len();
        for c in conns {
            c.close(0u32.into(), b"revoked");
        }
        n
    }

    /// Update the set of hostnames the server terminates TLS for — the config
    /// set ∪ the backend's provisioned terminated hostnames. The public listener
    /// decides "terminate this SNI?" from it, independently of any live tunnel,
    /// so a provisioned terminated hostname's cert / ACME challenge is served
    /// even before its agent connects. Behind the `dynamic` feature.
    ///
    /// A host that names an issuer takes its certs from it, else from the
    /// default issuer. An ACME name serves a valid cert once its order completes.
    #[cfg(feature = "dynamic")]
    pub fn set_terminated_domains(&self, hosts: Vec<TerminatedHost>) {
        let issuers = hosts
            .iter()
            .filter_map(|h| Some((h.host.clone(), h.issuer.clone()?)))
            .collect();
        self.routes
            .set_terminated(hosts.into_iter().map(|h| h.host).collect());

        if let Some(cert_issuers) = &self.issuers {
            cert_issuers.set_dynamic_hosts(issuers);
            cert_issuers.plan_acme(&self.routes.terminated_hosts());
        }
    }

    /// The issuer of a terminated hostname and how it got it; `None` takes a
    /// self-signed cert. Behind the `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn host_issuer(&self, host: &str) -> Option<HostIssuer> {
        self.issuers.as_ref()?.host_issuer(host)
    }

    /// The names that each issuer covers by itself, as an operator reads them
    /// (e.g. `.home.lan`, `*.example.com`). Behind the `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn issuer_coverage(&self) -> HashMap<String, Vec<String>> {
        self.issuers
            .as_ref()
            .map(|issuers| issuers.coverage())
            .unwrap_or_default()
    }

    /// Replace the cert issuers. An issuer whose entry did not change keeps its
    /// certs and orders. On an error (a file that does not load, two defaults)
    /// nothing changes. Behind the `dynamic` feature.
    #[cfg(feature = "dynamic")]
    pub fn set_issuers(&self, entries: Vec<IssuerEntry>) -> Result<(), ServerError> {
        let Some(issuers) = &self.issuers else {
            return Ok(());
        };

        issuers.set_issuers(entries)?;
        issuers.plan_acme(&self.routes.terminated_hosts());

        Ok(())
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"server shutdown");
        let _ = self.accept_handle.await;
        if let Some(h) = self.public_handle {
            let _ = h.await;
        }
        // ACME tasks are tied to `cancel` (already cancelled above) — they self-
        // terminate; nothing to await.
        drop(self.issuers);
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
