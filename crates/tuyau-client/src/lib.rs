//! Tuyau client: QUIC dialer with pinned-fingerprint cert verification.

mod client;
mod config;
mod error;
mod verifier;

pub use client::{TunnelClient, TunnelStream};
pub use config::ClientConfig;
pub use error::{ClientError, ConfigError};
