use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cbor error: {0}")]
    Cbor(String),

    #[error("oversized frame: {len} bytes (max {max})")]
    OversizedFrame { len: usize, max: usize },
}

impl ProtocolError {
    pub(crate) fn cbor<E: core::fmt::Display>(e: E) -> Self {
        Self::Cbor(e.to_string())
    }
}
