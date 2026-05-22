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

/// Returns the SNI host_name if the bytes look like a valid ClientHello with
/// an SNI extension; `None` otherwise.
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
                    // host_name
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
