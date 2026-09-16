//! UDP-over-QUIC encapsulation.
//!
//! Unlike the control/handshake path, UDP forwarding does **not** use CBOR
//! frames. Datagrams ride QUIC DATAGRAM frames (unreliable, unordered — the
//! right shape for UDP; a stream would add head-of-line blocking and reordering
//! that hurt WireGuard), so every byte of header is paid on every packet and
//! competes with the path MTU. The encapsulation is therefore a fixed, tiny
//! binary header:
//!
//! ```text
//! 0        1                        9        10          10+n
//! +--------+------------------------+--------+-----------+-----------+
//! | ver(1) |    session id (8, BE)  | len(1) | route (n) |  payload  |
//! +--------+------------------------+--------+-----------+-----------+
//! ```
//!
//! The route name is repeated on **every** datagram rather than negotiated
//! once. That costs a few bytes but buys statelessness: a datagram is
//! self-describing, so it survives loss, reordering, and either side having
//! expired its session state — the receiver can always rebuild the session from
//! a single packet. Session ids are minted by the server (which owns the public
//! socket) and are scoped to one tunnel connection.

use crate::error::ProtocolError;

/// Wire version of the UDP encapsulation. Bump only for an incompatible
/// header change; receivers reject anything else rather than guess.
pub const UDP_DATAGRAM_VERSION: u8 = 1;

/// Longest route name accepted on the wire (the length field is one byte, but
/// route names are config identifiers — keep them short so the header stays
/// small). Server config validation enforces the same bound.
pub const MAX_UDP_ROUTE_LEN: usize = 64;

/// Fixed part of the header: version + session id + route length.
const FIXED_HEADER_LEN: usize = 1 + 8 + 1;

/// One encapsulated UDP packet: which session it belongs to, which route it
/// arrived on, and the original datagram payload.
///
/// Borrows its payload so the hot path can forward straight out of the receive
/// buffer without copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Session id, minted by the server and unique within one tunnel.
    pub session_id: u64,
    /// Name of the configured UDP route this packet belongs to.
    pub route: &'a str,
    /// The original UDP payload (may legitimately be empty).
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Bytes of encapsulation overhead for `route` — what a payload loses out
    /// of the QUIC datagram budget. Callers size their MTU checks with this.
    #[must_use]
    pub fn header_len(route: &str) -> usize {
        FIXED_HEADER_LEN + route.len()
    }

    /// Largest UDP payload that still fits in a QUIC datagram of
    /// `max_datagram_size` bytes on `route`. `0` when the route name alone
    /// already exceeds the budget (a degenerate path MTU).
    #[must_use]
    pub fn max_payload(max_datagram_size: usize, route: &str) -> usize {
        max_datagram_size.saturating_sub(Self::header_len(route))
    }

    /// Serialize into a fresh buffer. Fails only on a route name that can't be
    /// expressed on the wire — the caller checks the MTU separately, since the
    /// budget depends on the connection, not the datagram.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let route = self.route.as_bytes();
        if route.is_empty() || route.len() > MAX_UDP_ROUTE_LEN {
            return Err(ProtocolError::InvalidUdpRoute(self.route.to_string()));
        }

        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + route.len() + self.payload.len());
        out.push(UDP_DATAGRAM_VERSION);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        // Cast is bounded by the MAX_UDP_ROUTE_LEN check above.
        out.push(route.len() as u8);
        out.extend_from_slice(route);
        out.extend_from_slice(self.payload);
        Ok(out)
    }

    /// Parse an encapsulated datagram out of `buf`, borrowing from it.
    ///
    /// Every field is bounds-checked against the buffer: this parses attacker-
    /// influenced bytes (anything a peer can put on the tunnel), so it must
    /// never panic or over-read — it only ever returns an error.
    pub fn decode(buf: &'a [u8]) -> Result<Self, ProtocolError> {
        if buf.len() < FIXED_HEADER_LEN {
            return Err(ProtocolError::TruncatedDatagram { len: buf.len() });
        }
        if buf[0] != UDP_DATAGRAM_VERSION {
            return Err(ProtocolError::UnknownDatagramVersion(buf[0]));
        }

        let mut id = [0u8; 8];
        id.copy_from_slice(&buf[1..9]);
        let session_id = u64::from_be_bytes(id);

        let route_len = buf[9] as usize;
        if route_len == 0 || route_len > MAX_UDP_ROUTE_LEN {
            return Err(ProtocolError::InvalidUdpRoute(format!(
                "length {route_len}"
            )));
        }
        let route_end = FIXED_HEADER_LEN + route_len;
        if buf.len() < route_end {
            return Err(ProtocolError::TruncatedDatagram { len: buf.len() });
        }
        let route = core::str::from_utf8(&buf[FIXED_HEADER_LEN..route_end])
            .map_err(|_| ProtocolError::InvalidUdpRoute("not valid UTF-8".into()))?;

        Ok(Self {
            session_id,
            route,
            payload: &buf[route_end..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dg = UdpDatagram {
            session_id: 0x0102_0304_0506_0708,
            route: "wireguard",
            payload: &[1, 2, 3, 4, 5],
        };
        let wire = dg.encode().unwrap();
        assert_eq!(wire.len(), UdpDatagram::header_len("wireguard") + 5);
        assert_eq!(UdpDatagram::decode(&wire).unwrap(), dg);
    }

    #[test]
    fn empty_payload_roundtrips() {
        // A zero-length UDP datagram is legal and must survive encapsulation.
        let dg = UdpDatagram {
            session_id: 7,
            route: "wg",
            payload: &[],
        };
        let wire = dg.encode().unwrap();
        let back = UdpDatagram::decode(&wire).unwrap();
        assert_eq!(back, dg);
        assert!(back.payload.is_empty());
    }

    #[test]
    fn header_len_and_max_payload_agree() {
        let overhead = UdpDatagram::header_len("wg");
        assert_eq!(overhead, 12);
        assert_eq!(UdpDatagram::max_payload(1200, "wg"), 1200 - overhead);
        // A path MTU smaller than the header saturates to zero instead of
        // underflowing.
        assert_eq!(UdpDatagram::max_payload(4, "wg"), 0);
    }

    #[test]
    fn decode_rejects_truncated_buffers() {
        let wire = UdpDatagram {
            session_id: 1,
            route: "wg",
            payload: &[9, 9, 9],
        }
        .encode()
        .unwrap();

        // Every prefix shorter than the full header must be rejected, never
        // panic — these are bytes an attacker controls.
        for cut in 0..UdpDatagram::header_len("wg") {
            assert!(
                matches!(
                    UdpDatagram::decode(&wire[..cut]),
                    Err(ProtocolError::TruncatedDatagram { .. })
                ),
                "prefix of {cut} bytes should be rejected"
            );
        }
        // The full header (with no payload) is valid.
        assert!(UdpDatagram::decode(&wire[..UdpDatagram::header_len("wg")]).is_ok());
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut wire = UdpDatagram {
            session_id: 1,
            route: "wg",
            payload: &[],
        }
        .encode()
        .unwrap();
        wire[0] = 0xff;
        assert!(matches!(
            UdpDatagram::decode(&wire),
            Err(ProtocolError::UnknownDatagramVersion(0xff))
        ));
    }

    #[test]
    fn decode_rejects_zero_length_route() {
        let mut wire = UdpDatagram {
            session_id: 1,
            route: "wg",
            payload: &[],
        }
        .encode()
        .unwrap();
        wire[9] = 0;
        assert!(matches!(
            UdpDatagram::decode(&wire),
            Err(ProtocolError::InvalidUdpRoute(_))
        ));
    }

    #[test]
    fn decode_rejects_route_len_past_the_buffer() {
        let mut wire = UdpDatagram {
            session_id: 1,
            route: "wg",
            payload: &[],
        }
        .encode()
        .unwrap();
        wire[9] = MAX_UDP_ROUTE_LEN as u8; // claims 64 bytes that aren't there
        assert!(matches!(
            UdpDatagram::decode(&wire),
            Err(ProtocolError::TruncatedDatagram { .. })
        ));
    }

    #[test]
    fn decode_rejects_non_utf8_route() {
        let mut wire = UdpDatagram {
            session_id: 1,
            route: "wg",
            payload: &[],
        }
        .encode()
        .unwrap();
        wire[10] = 0xff; // invalid UTF-8 lead byte
        assert!(matches!(
            UdpDatagram::decode(&wire),
            Err(ProtocolError::InvalidUdpRoute(_))
        ));
    }

    #[test]
    fn encode_rejects_unrepresentable_routes() {
        let long = "r".repeat(MAX_UDP_ROUTE_LEN + 1);
        for route in ["", long.as_str()] {
            let dg = UdpDatagram {
                session_id: 1,
                route,
                payload: &[],
            };
            assert!(matches!(
                dg.encode(),
                Err(ProtocolError::InvalidUdpRoute(_))
            ));
        }
    }

    #[test]
    fn max_length_route_roundtrips() {
        let route = "r".repeat(MAX_UDP_ROUTE_LEN);
        let dg = UdpDatagram {
            session_id: u64::MAX,
            route: &route,
            payload: &[42],
        };
        let wire = dg.encode().unwrap();
        assert_eq!(UdpDatagram::decode(&wire).unwrap(), dg);
    }
}
