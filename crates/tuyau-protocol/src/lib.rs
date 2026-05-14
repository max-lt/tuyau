//! Tuyau wire protocol: handshake frames + length-delimited CBOR codec.

mod codec;
mod error;
mod frame;

pub use codec::FrameCodec;
pub use error::ProtocolError;
pub use frame::{DataStreamHeader, Hello, HelloResponse, TlsMode};

/// QUIC ALPN advertised by both sides of a Tuyau handshake.
///
/// Bumped from `tuyau/0` to `tuyau/1` in M5b, when `DataStreamHeader` was
/// introduced for server-initiated data streams.
pub const ALPN: &[u8] = b"tuyau/1";

/// Maximum encoded payload size (excluding the 4-byte length prefix).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
