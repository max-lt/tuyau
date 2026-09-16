use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cbor error: {0}")]
    Cbor(String),

    #[error("oversized frame: {len} bytes (max {max})")]
    OversizedFrame { len: usize, max: usize },

    #[error("truncated udp datagram: {len} bytes")]
    TruncatedDatagram { len: usize },

    #[error("unknown udp datagram version: {0}")]
    UnknownDatagramVersion(u8),

    #[error("invalid udp route name: {0}")]
    InvalidUdpRoute(String),
}

impl ProtocolError {
    pub(crate) fn cbor<E: core::fmt::Display>(e: E) -> Self {
        Self::Cbor(e.to_string())
    }
}
