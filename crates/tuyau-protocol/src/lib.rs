//! Tuyau wire protocol: handshake frames + length-delimited CBOR codec.

mod codec;
mod error;
mod frame;

pub use codec::FrameCodec;
pub use error::ProtocolError;
pub use frame::{Hello, HelloResponse};

/// QUIC ALPN advertised by both sides of a Tuyau handshake.
pub const ALPN: &[u8] = b"tuyau/0";

/// Maximum encoded payload size (excluding the 4-byte length prefix).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
