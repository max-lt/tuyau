//! Tuyau server: QUIC listener, cert handling, token validation.

mod backend;
mod cert;
mod config;
mod error;
mod public;
mod routes;
mod server;
mod sni;

pub use config::{Balance, ClientEntry, HostnameEntry, ServerConfig, TlsMode};
pub use error::{CertError, ConfigError, ServerError};
pub use server::TunnelServer;

/// Dynamic routing seam: implement [`RoutingBackend`] and inject it via
/// [`TunnelServer::start_with`] to drive identity + routing from outside the
/// core (e.g. a managed control plane). Behind the `dynamic` feature.
#[cfg(feature = "dynamic")]
pub use backend::{ClientGrant, RoutingBackend};
