use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{MAX_FRAME_SIZE, error::ProtocolError};

const LEN_PREFIX_SIZE: usize = 4;

#[derive(Debug, Default)]
pub struct FrameCodec<F>(PhantomData<fn() -> F>);

impl<F> FrameCodec<F> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<F> Encoder<F> for FrameCodec<F>
where
    F: Serialize,
{
    type Error = ProtocolError;

    fn encode(&mut self, item: F, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut payload = Vec::new();
        ciborium::into_writer(&item, &mut payload).map_err(ProtocolError::cbor)?;

        if payload.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::OversizedFrame {
                len: payload.len(),
                max: MAX_FRAME_SIZE,
            });
        }

        dst.reserve(LEN_PREFIX_SIZE + payload.len());
        dst.put_u32(payload.len() as u32);
        dst.put_slice(&payload);
        Ok(())
    }
}

impl<F> Decoder for FrameCodec<F>
where
    F: DeserializeOwned,
{
    type Item = F;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < LEN_PREFIX_SIZE {
            return Ok(None);
        }

        let mut len_bytes = [0u8; LEN_PREFIX_SIZE];
        len_bytes.copy_from_slice(&src[..LEN_PREFIX_SIZE]);
        let frame_len = u32::from_be_bytes(len_bytes) as usize;

        if frame_len > MAX_FRAME_SIZE {
            return Err(ProtocolError::OversizedFrame {
                len: frame_len,
                max: MAX_FRAME_SIZE,
            });
        }

        if src.len() < LEN_PREFIX_SIZE + frame_len {
            src.reserve(LEN_PREFIX_SIZE + frame_len - src.len());
            return Ok(None);
        }

        src.advance(LEN_PREFIX_SIZE);
        let payload = src.split_to(frame_len);
        let item: F = ciborium::from_reader(payload.as_ref()).map_err(ProtocolError::cbor)?;
        Ok(Some(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{DataStreamHeader, Hello, HelloResponse, TlsMode};

    fn sample_hello() -> Hello {
        Hello {
            token: [7u8; 32],
            client_name: "alice".into(),
        }
    }

    #[test]
    fn hello_roundtrip() {
        let mut codec = FrameCodec::<Hello>::new();
        let mut buf = BytesMut::new();
        codec.encode(sample_hello(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, sample_hello());
        assert!(buf.is_empty());
    }

    #[test]
    fn welcome_roundtrip() {
        let mut codec = FrameCodec::<HelloResponse>::new();
        let mut buf = BytesMut::new();
        codec.encode(HelloResponse::Welcome, &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, HelloResponse::Welcome);
    }

    #[test]
    fn reject_roundtrip() {
        let mut codec = FrameCodec::<HelloResponse>::new();
        let mut buf = BytesMut::new();
        let reject = HelloResponse::Reject {
            reason: "invalid token".into(),
        };
        codec.encode(reject.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, reject);
    }

    #[test]
    fn split_reads_decode_byte_by_byte() {
        let mut encoder = FrameCodec::<Hello>::new();
        let mut decoder = FrameCodec::<Hello>::new();
        let mut wire = BytesMut::new();
        encoder.encode(sample_hello(), &mut wire).unwrap();
        let bytes: Vec<u8> = wire.to_vec();

        let mut incoming = BytesMut::new();
        for (i, b) in bytes.iter().enumerate() {
            incoming.extend_from_slice(&[*b]);
            let res = decoder.decode(&mut incoming).unwrap();

            if i + 1 < bytes.len() {
                assert!(res.is_none(), "decoded too early at byte {i}");
            } else {
                assert_eq!(res, Some(sample_hello()));
            }
        }

        assert!(incoming.is_empty());
    }

    #[test]
    fn decode_oversized_length_prefix_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u32((MAX_FRAME_SIZE as u32) + 1);
        let mut decoder = FrameCodec::<Hello>::new();
        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::OversizedFrame { .. }));
    }

    #[test]
    fn data_stream_header_roundtrip_terminated() {
        let header = DataStreamHeader {
            hostname: "alpha.example.com".into(),
            peer_addr: "10.0.0.1:54321".into(),
            mode: TlsMode::Terminated,
        };
        let mut codec = FrameCodec::<DataStreamHeader>::new();
        let mut buf = BytesMut::new();
        codec.encode(header.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn data_stream_header_roundtrip_passthrough() {
        let header = DataStreamHeader {
            hostname: "secure.example.com".into(),
            peer_addr: "2001:db8::1:443".into(),
            mode: TlsMode::Passthrough,
        };
        let mut codec = FrameCodec::<DataStreamHeader>::new();
        let mut buf = BytesMut::new();
        codec.encode(header.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn encode_oversized_payload_rejected() {
        let huge = Hello {
            token: [0u8; 32],
            client_name: "x".repeat(MAX_FRAME_SIZE + 100),
        };
        let mut codec = FrameCodec::<Hello>::new();
        let mut buf = BytesMut::new();
        let err = codec.encode(huge, &mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::OversizedFrame { .. }));
    }
}
