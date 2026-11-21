//! Bounded, read-only TLS ClientHello inspector for the M0.1 feasibility spike.
//! It is NOT a TLS stack, QUIC packet decrypter, JA3/JA4 implementation, or
//! evidence of browser impersonation. Do not log SNI, random or session IDs.
const MAX_HELLO: usize = 65_536;
const MAX_RECORD: usize = 16_384 + 2_048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloSummary {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions_in_wire_order: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub sni_present: bool,
    pub quic_transport_parameters_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    Invalid(&'static str),
    TooLarge,
}

impl ClientHelloSummary {
    /// GREASE extension IDs are informative, not a complete browser fingerprint.
    pub fn has_grease_extension(&self) -> bool {
        self.extensions_in_wire_order.iter().any(|&id| is_grease(id))
    }

    /// BoringSSL supports an old and a new application_settings (ALPS)
    /// codepoint. Do not mistake lack of one for lack of ALPS altogether.
    pub fn has_alps(&self) -> bool {
        self.extensions_in_wire_order
            .iter()
            .any(|&id| id == 17_513 || id == 17_613)
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::TooLarge)?;
        let part = self.data.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u24(&mut self) -> Result<usize, ParseError> {
        let x = self.take(3)?;
        Ok((usize::from(x[0]) << 16) | (usize::from(x[1]) << 8) | usize::from(x[2]))
    }
}

fn read_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u16()?);
    if n != r.remaining() || n == 0 {
        return Err(ParseError::Invalid("ALPN vector length"));
    }
    let mut names = Vec::new();
    while r.remaining() != 0 {
        let len = usize::from(r.u8()?);
        if len == 0 {
            return Err(ParseError::Invalid("empty ALPN identifier"));
        }
        names.push(r.take(len)?.to_vec());
    }
    Ok(names)
}

fn read_versions(data: &[u8]) -> Result<Vec<u16>, ParseError> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u8()?);
    if n == 0 || n % 2 != 0 || n != r.remaining() {
        return Err(ParseError::Invalid("supported_versions length"));
    }
    let mut versions = Vec::new();
    while r.remaining() != 0 {
        versions.push(r.u16()?);
    }
    Ok(versions)
}

fn read_groups(data: &[u8]) -> Result<Vec<u16>, ParseError> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u16()?);
    if n == 0 || n % 2 != 0 || n != r.remaining() {
        return Err(ParseError::Invalid("supported_groups length"));
    }
    let mut groups = Vec::new();
    while r.remaining() != 0 {
        groups.push(r.u16()?);
    }
    Ok(groups)
}

fn validate_sni(data: &[u8]) -> Result<bool, ParseError> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u16()?);
    if n != r.remaining() || n == 0 {
        return Err(ParseError::Invalid("SNI vector length"));
    }
    let mut found = false;
    while r.remaining() != 0 {
        let typ = r.u8()?;
        let len = usize::from(r.u16()?);
        if len == 0 {
            return Err(ParseError::Invalid("empty server name"));
        }
        r.take(len)?;
        found |= typ == 0;
    }
    Ok(found)
}

/// Parse an unencrypted TLS handshake message, such as rustls::quic::write_hs
/// produces *before* QUIC packet encryption. Accepts exactly one ClientHello.
pub fn parse_handshake(raw: &[u8]) -> Result<ClientHelloSummary, ParseError> {
    if raw.len() > MAX_HELLO {
        return Err(ParseError::TooLarge);
    }
    let mut h = Reader::new(raw);
    if h.u8()? != 1 {
        return Err(ParseError::Invalid("expected ClientHello handshake type"));
    }
    let len = h.u24()?;
    if len != h.remaining() {
        return Err(ParseError::Invalid("handshake length mismatch"));
    }
    let legacy_version = h.u16()?;
    h.take(32)?; // client random (never retain or log)
    let session_id_len = usize::from(h.u8()?);
    if session_id_len > 32 {
        return Err(ParseError::Invalid("session id too large"));
    }
    h.take(session_id_len)?; // never retain or log

    let cipher_len = usize::from(h.u16()?);
    if cipher_len == 0 || cipher_len % 2 != 0 {
        return Err(ParseError::Invalid("cipher suite vector"));
    }
    let mut suites = Reader::new(h.take(cipher_len)?);
    let mut cipher_suites = Vec::new();
    while suites.remaining() > 0 {
        cipher_suites.push(suites.u16()?);
    }
    let compression_len = usize::from(h.u8()?);
    let compression = h.take(compression_len)?;
    if compression != [0] {
        return Err(ParseError::Invalid("TLS compression methods"));
    }
    let extensions_len = usize::from(h.u16()?);
    if extensions_len != h.remaining() {
        return Err(ParseError::Invalid("extensions length mismatch"));
    }
    let mut exts = Reader::new(h.take(extensions_len)?);
    let mut extension_types = Vec::new();
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut sni_present = false;
    let mut quic_transport_parameters_present = false;
    while exts.remaining() != 0 {
        let typ = exts.u16()?;
        let length = usize::from(exts.u16()?);
        let value = exts.take(length)?;
        if extension_types.contains(&typ) {
            return Err(ParseError::Invalid("duplicate TLS extension"));
        }
        extension_types.push(typ);
        match typ {
            0 => sni_present = validate_sni(value)?,
            16 => alpn = read_alpn(value)?,
            10 => supported_groups = read_groups(value)?,
            43 => supported_versions = read_versions(value)?,
            57 => quic_transport_parameters_present = true,
            _ => {}
        }
    }
    Ok(ClientHelloSummary {
        legacy_version,
        cipher_suites,
        extensions_in_wire_order: extension_types,
        alpn,
        supported_versions,
        supported_groups,
        sni_present,
        quic_transport_parameters_present,
    })
}

/// Reassemble the initial plaintext TLS handshake record(s), with explicit
/// bounds. A QUIC CRYPTO payload is *not* a TLS record: use parse_handshake.
pub fn parse_tls_records(wire: &[u8]) -> Result<ClientHelloSummary, ParseError> {
    let mut records = Reader::new(wire);
    let mut message = Vec::new();
    while records.remaining() != 0 {
        if records.u8()? != 22 {
            return Err(ParseError::Invalid("expected TLS handshake record"));
        }
        let version = records.u16()?;
        if version != 0x0301 && version != 0x0303 {
            return Err(ParseError::Invalid("TLS legacy record version"));
        }
        let len = usize::from(records.u16()?);
        if len == 0 || len > MAX_RECORD {
            return Err(ParseError::Invalid("TLS record length"));
        }
        let data = records.take(len)?;
        if message.len().saturating_add(data.len()) > MAX_HELLO {
            return Err(ParseError::TooLarge);
        }
        message.extend_from_slice(data);
        if message.len() >= 4 {
            let mut prefix = Reader::new(&message);
            if prefix.u8()? != 1 {
                return Err(ParseError::Invalid("expected ClientHello"));
            }
            let total = 4 + prefix.u24()?;
            if total > MAX_HELLO {
                return Err(ParseError::TooLarge);
            }
            if message.len() >= total {
                return parse_handshake(&message[..total]);
            }
        }
    }
    Err(ParseError::Truncated)
}

/// TLS GREASE code points (RFC 8701); fingerprints should report their
/// presence, but a code point alone never proves browser compatibility.
pub fn is_grease(value: u16) -> bool {
    let byte = (value & 0xff) as u8;
    (value >> 8) as u8 == byte && (byte & 0x0f) == 0x0a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_hello() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.push(0); // session id length
        body.extend([0, 2, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend([1, 0]); // null compression
        let mut exts = vec![0, 16, 0, 5, 0, 3, 2, b'h', b'2']; // ALPN
        exts.extend([0, 43, 0, 3, 2, 3, 4]); // supported TLS 1.3
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let len = body.len();
        let mut hello = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        hello.extend(body);
        hello
    }

    fn tls_record(body: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend((body.len() as u16).to_be_bytes());
        record.extend(body);
        record
    }

    #[test]
    fn parser_accepts_framed_clienthello_and_recovers_record_fragments() {
        let bytes = minimal_hello();
        let parsed = parse_handshake(&bytes).unwrap();
        assert_eq!(parsed.alpn, vec![b"h2".to_vec()]);
        assert_eq!(parsed.cipher_suites, vec![0x1301]);
        assert_eq!(parsed.supported_versions, vec![0x0304]);
        assert_eq!(parsed.extensions_in_wire_order, vec![16, 43]);
        let mut fragments = tls_record(&bytes[..12]);
        fragments.extend(tls_record(&bytes[12..]));
        assert_eq!(parse_tls_records(&fragments).unwrap(), parsed);
    }

    #[test]
    fn parser_fails_closed_on_truncation_wrong_length_and_wrong_type() {
        let hello = minimal_hello();
        assert!(parse_handshake(&hello[..hello.len() - 1]).is_err());
        let mut corrupt = hello.clone();
        corrupt[3] = corrupt[3].wrapping_add(1);
        assert!(parse_handshake(&corrupt).is_err());
        let mut incorrect_type = hello;
        incorrect_type[0] = 2;
        assert!(parse_handshake(&incorrect_type).is_err());
        assert_eq!(
            parse_tls_records(&[22, 3, 1, 0, 10, 1]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn parser_rejects_duplicate_extension_and_broken_alpn() {
        let mut hello = minimal_hello();
        let ext = hello[hello.len() - 7..].to_vec();
        hello.extend(&ext);
        let body_len = hello.len() - 4;
        hello[1] = (body_len >> 16) as u8;
        hello[2] = (body_len >> 8) as u8;
        hello[3] = body_len as u8;
        let extensions_offset = 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let ext_len = u16::from_be_bytes([hello[extensions_offset], hello[extensions_offset + 1]]);
        hello[extensions_offset..extensions_offset + 2]
            .copy_from_slice(&(ext_len + 7).to_be_bytes());
        assert_eq!(
            parse_handshake(&hello),
            Err(ParseError::Invalid("duplicate TLS extension"))
        );
    }

    #[test]
    fn grease_is_classified_without_claiming_impersonation() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x2a2a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a0b));
    }

    // Append a synthetic extension and update both TLS length prefixes.
    fn append_extension(hello: &mut Vec<u8>, id: u16, value: &[u8]) {
        let extensions_offset = 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let old_len = u16::from_be_bytes([
            hello[extensions_offset],
            hello[extensions_offset + 1],
        ]);
        hello.extend(id.to_be_bytes());
        hello.extend((value.len() as u16).to_be_bytes());
        hello.extend(value);
        hello[extensions_offset..extensions_offset + 2]
            .copy_from_slice(&(old_len + 4 + value.len() as u16).to_be_bytes());
        let body_len = hello.len() - 4;
        hello[1] = (body_len >> 16) as u8;
        hello[2] = (body_len >> 8) as u8;
        hello[3] = body_len as u8;
    }

    #[test]
    fn supported_groups_are_observed_and_invalid_vectors_fail_closed() {
        let mut valid = minimal_hello();
        append_extension(&mut valid, 10, &[0, 4, 0, 29, 0, 23]);
        assert_eq!(
            parse_handshake(&valid).unwrap().supported_groups,
            vec![29, 23]
        );
        let mut invalid = minimal_hello();
        append_extension(&mut invalid, 10, &[0, 3, 0, 29, 23]);
        assert_eq!(
            parse_handshake(&invalid),
            Err(ParseError::Invalid("supported_groups length"))
        );
    }

    #[test]
    fn alps_old_and_new_codepoints_are_detected() {
        assert!(!parse_handshake(&minimal_hello()).unwrap().has_alps());
        for codepoint in [17_513, 17_613] {
            let mut h = minimal_hello();
            append_extension(&mut h, codepoint, &[0, 0]);
            assert!(
                parse_handshake(&h).unwrap().has_alps(),
                "ALPS codepoint {codepoint}"
            );
        }
    }

    #[test]
    fn record_parser_rejects_overlarge_record() {
        assert_eq!(
            parse_tls_records(&[22, 3, 1, 0xff, 0xff]),
            Err(ParseError::Invalid("TLS record length"))
        );
    }
}
