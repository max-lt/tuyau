//! Best-effort SNI extraction from raw TLS ClientHello bytes.
//!
//! Used by the public listener to route on hostname BEFORE deciding whether to
//! terminate TLS (route is `terminated`) or forward the bytes opaquely (route
//! is `passthrough`). Returning `None` on any parse failure is fine — the
//! caller treats a missing SNI as "no route" and drops the connection.
//!
//! Scope: a single ClientHello message inside a single TLS record. SNI lives
//! in extension type 0x0000 with name_type 0x00 (host_name). TLS 1.3 PSK /
//! session-resumption tricks and ClientHello-fragmented-across-records are
//! not handled here; both are extremely rare in browser-like clients and we
//! deliberately keep the parser small enough to audit at a glance.

/// Maximum SNI host_name length we accept. A DNS name is at most 253 bytes;
/// anything longer isn't a real hostname, so we reject it rather than route on
/// (or allocate) a pathological string from a hostile ClientHello.
const MAX_SNI_LEN: usize = 253;

/// Returns the SNI host_name if the bytes look like a valid ClientHello with
/// an SNI extension; `None` otherwise. Never panics on arbitrary input — every
/// read is bounds-checked and every advance is `checked_add`.
pub(crate) fn parse_sni(buf: &[u8]) -> Option<String> {
    let mut p = 0usize;

    // Record header: type (1) | version (2) | length (2)
    if read_u8(buf, &mut p)? != 0x16 {
        return None; // not a Handshake record
    }
    p += 2; // skip legacy_record_version
    let _rec_len = read_u16(buf, &mut p)? as usize;

    // Handshake header: msg_type (1) | length (3)
    if read_u8(buf, &mut p)? != 0x01 {
        return None; // not ClientHello
    }
    let _hs_len = read_u24(buf, &mut p)? as usize;

    // ClientHello body
    p = p.checked_add(2)?; // client_version
    p = p.checked_add(32)?; // random
    if p > buf.len() {
        return None;
    }

    let session_id_len = read_u8(buf, &mut p)? as usize;
    p = p.checked_add(session_id_len)?;

    let cs_len = read_u16(buf, &mut p)? as usize;
    p = p.checked_add(cs_len)?;

    let cm_len = read_u8(buf, &mut p)? as usize;
    p = p.checked_add(cm_len)?;

    let ext_total = read_u16(buf, &mut p)? as usize;
    let ext_end = p.checked_add(ext_total)?;
    if ext_end > buf.len() {
        return None;
    }

    while p < ext_end {
        let ext_type = read_u16(buf, &mut p)?;
        let ext_data_len = read_u16(buf, &mut p)? as usize;
        let ext_end_inner = p.checked_add(ext_data_len)?;
        if ext_end_inner > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            // server_name extension: list_length (2) | ServerName entries
            let mut q = p;
            let _list_len = read_u16(buf, &mut q)?;
            while q < ext_end_inner {
                let name_type = read_u8(buf, &mut q)?;
                let name_len = read_u16(buf, &mut q)? as usize;
                let name_end = q.checked_add(name_len)?;
                if name_end > ext_end_inner {
                    return None;
                }
                if name_type == 0x00 {
                    // host_name — reject implausibly long names (not a hostname).
                    if name_len > MAX_SNI_LEN {
                        return None;
                    }
                    return std::str::from_utf8(&buf[q..name_end])
                        .ok()
                        .map(String::from);
                }
                q = name_end;
            }
        }

        p = ext_end_inner;
    }

    None
}

fn read_u8(buf: &[u8], p: &mut usize) -> Option<u8> {
    let v = *buf.get(*p)?;
    *p += 1;
    Some(v)
}

fn read_u16(buf: &[u8], p: &mut usize) -> Option<u16> {
    if *p + 2 > buf.len() {
        return None;
    }
    let v = u16::from_be_bytes([buf[*p], buf[*p + 1]]);
    *p += 2;
    Some(v)
}

fn read_u24(buf: &[u8], p: &mut usize) -> Option<u32> {
    if *p + 3 > buf.len() {
        return None;
    }
    let v = ((buf[*p] as u32) << 16) | ((buf[*p + 1] as u32) << 8) | (buf[*p + 2] as u32);
    *p += 3;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello carrying a single SNI extension. Pads
    /// random bytes to the right shape; cipher_suites, compression_methods
    /// kept tiny.
    fn craft_client_hello_with_sni(host: &str) -> Vec<u8> {
        // ServerName entry: name_type(1) | name_length(2) | name
        let mut server_name = Vec::new();
        server_name.push(0x00);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host.as_bytes());

        // server_name_list: list_length(2) | entries
        let mut sni_list = Vec::new();
        sni_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(&server_name);

        // Extension: type(2)=0x0000 | length(2) | sni_list
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni_list);

        // Extensions block: length(2) | extensions
        let mut exts = Vec::new();
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        // ClientHello body: version(2) | random(32) | session_id_len(1) | ...
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_length
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites_len
        body.extend_from_slice(&[0x00, 0x35]); // one cipher
        body.push(0x01); // compression_methods_length
        body.push(0x00); // null compression
        body.extend_from_slice(&exts);

        // Handshake: type(1)=0x01 | length(3) | body
        let mut hs = Vec::new();
        hs.push(0x01);
        let body_len = body.len() as u32;
        hs.extend_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&body);

        // Record: type(1)=0x16 | version(2) | length(2) | handshake
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy 1.0
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_simple_sni() {
        let bytes = craft_client_hello_with_sni("alpha.example.com");
        assert_eq!(parse_sni(&bytes).as_deref(), Some("alpha.example.com"));
    }

    #[test]
    fn returns_none_on_wrong_record_type() {
        let mut bytes = craft_client_hello_with_sni("alpha.example.com");
        bytes[0] = 0x17; // ApplicationData instead of Handshake
        assert_eq!(parse_sni(&bytes), None);
    }

    #[test]
    fn returns_none_on_truncated_buffer() {
        let bytes = craft_client_hello_with_sni("alpha.example.com");
        let truncated = &bytes[..bytes.len() / 2];
        assert_eq!(parse_sni(truncated), None);
    }

    #[test]
    fn returns_none_on_empty_buffer() {
        assert_eq!(parse_sni(&[]), None);
    }

    /// Tiny deterministic PRNG (no rng dependency) for fuzz-style inputs.
    fn lcg(state: &mut u64) -> u8 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*state >> 33) as u8
    }

    #[test]
    fn never_panics_on_truncations() {
        let full = craft_client_hello_with_sni("alpha.example.com");
        for len in 0..=full.len() {
            let _ = parse_sni(&full[..len]); // must not panic at any prefix
        }
    }

    #[test]
    fn never_panics_on_single_byte_mutations() {
        let base = craft_client_hello_with_sni("alpha.example.com");
        for i in 0..base.len() {
            for b in [0x00u8, 0x01, 0x16, 0x7f, 0xff] {
                let mut m = base.clone();
                m[i] = b;
                let _ = parse_sni(&m);
            }
        }
    }

    #[test]
    fn never_panics_on_random_and_semi_valid_buffers() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for len in [0usize, 1, 2, 5, 9, 16, 64, 256, 1024, 16384] {
            for _ in 0..100 {
                // Fully random bytes.
                let buf: Vec<u8> = (0..len).map(|_| lcg(&mut state)).collect();
                let _ = parse_sni(&buf);

                // A valid-looking record/handshake header over a random body —
                // exercises the length-field paths with hostile lengths.
                let mut framed = vec![0x16, 0x03, 0x01];
                framed.extend_from_slice(&(len.min(0xffff) as u16).to_be_bytes());
                framed.push(0x01);
                framed.extend((0..len).map(|_| lcg(&mut state)));
                let _ = parse_sni(&framed);
            }
        }
    }

    #[test]
    fn rejects_overlong_sni() {
        let bytes = craft_client_hello_with_sni(&"a".repeat(300));
        assert_eq!(parse_sni(&bytes), None);
    }

    #[test]
    fn returns_none_when_no_sni_extension_present() {
        // Same shape but drop the extensions block (empty extensions).
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x35]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&0u16.to_be_bytes()); // extensions_length = 0
        let mut hs = Vec::new();
        hs.push(0x01);
        let body_len = body.len() as u32;
        hs.extend_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&body);
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0301u16.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(parse_sni(&rec), None);
    }
}
