use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    #[serde(with = "token_serde")]
    pub token: [u8; 32],
    pub client_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloResponse {
    Welcome,
    Reject { reason: String },
}

/// TLS handling for a given hostname.
///
/// - `Terminated`: the tuyau-server holds a cert for the hostname, terminates
///   incoming TLS, and forwards the *plaintext* bytes over the tunnel.
/// - `Passthrough`: the tuyau-server only peeks the SNI for routing and
///   forwards the raw TLS bytes (including ClientHello) over the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Terminated,
    Passthrough,
}

/// First frame on each server-initiated data stream: tells the tunnel client
/// which logical hostname this stream serves, the public peer's address (for
/// logging / `X-Forwarded-For`), and which TLS mode the server applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataStreamHeader {
    pub hostname: String,
    pub peer_addr: String,
    pub mode: TlsMode,
}

// Encode token as a CBOR byte string (major type 2) rather than an array
// of 32 unsigned integers. Decoding accepts either form for robustness.
mod token_serde {
    use core::fmt;
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
    };

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = [u8; 32];

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("32 bytes")
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; 32]>::try_from(v).map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 32];

                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }

                Ok(out)
            }
        }

        de.deserialize_bytes(V)
    }
}
