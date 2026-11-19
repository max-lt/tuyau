//! Tuyau server: QUIC listener, cert handling, token validation.

mod backend;
mod cert;
mod config;
mod control;
mod coverage;
mod error;
mod h2proxy;
mod host_certs;
mod internal;
mod issuers;
mod local_pool;
mod meter;
mod on_demand;
mod public;
mod routes;
mod server;
mod sni;

pub use config::{
    AcmeSection, Balance, ClientEntry, HostnameEntry, IssuerEntry, IssuerKind, ServerConfig,
    TerminatedHost, TlsMode, UpstreamEntry,
};
pub use error::{CertError, ConfigError, ServerError};
pub use issuers::{HostIssuer, IssuerChoice};
pub use server::TunnelServer;

/// Dynamic routing seam: implement [`RoutingBackend`] and inject it via
/// [`TunnelServer::start_with`] to drive identity + routing from outside the
/// core (e.g. a managed control plane). Behind the `dynamic` feature.
///
/// [`RoutingBackend`] is an `async` trait; implement it with the re-exported
/// attribute macro so embedders don't need their own `async-trait` dependency:
///
/// ```ignore
/// #[tuyau_server::async_trait]
/// impl tuyau_server::RoutingBackend for MyBackend {
///     async fn admit(&self, token: &[u8; 32]) -> Option<tuyau_server::ClientGrant> { /* ... */ }
/// }
/// ```
#[cfg(feature = "dynamic")]
pub use async_trait::async_trait;
#[cfg(feature = "dynamic")]
pub use backend::{ClientGrant, RoutingBackend};

/// Live, metadata-only observability of connected tunnels, surfaced by
/// [`TunnelServer::tunnels`] (snapshot) and [`TunnelServer::subscribe`] (event
/// stream). Behind the `dynamic` feature.
#[cfg(feature = "dynamic")]
pub use control::{ControlEvent, TunnelInfo};

/// The in-memory listeners of the upstreams with `internal_listener`, taken by
/// [`TunnelServer::internal_listener`]. Behind the `dynamic` feature.
#[cfg(feature = "dynamic")]
pub use internal::{InternalConnection, InternalListener};
