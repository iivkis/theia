//! Observe the TLS ClientHello built by the exact rustls version used in M0.1.
//!
//! These are the plaintext first flights from the TLS engine:
//!   * TCP: actual rustls TLS records emitted by ClientConnection::write_tls.
//!   * QUIC: actual rustls QUIC CRYPTO bytes emitted by quic::ClientConnection::write_hs.
//! The latter is NOT a decrypted capture of Quinn's QUIC Initial packets.
//!
//! Neither path claims Chrome/Firefox/Safari impersonation. No SNI, secrets,
//! key-share bytes, session IDs, certificates or raw ClientHello are logged.
use rustls::pki_types::ServerName;
use std::sync::Arc;

const EXT_SNI: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
const EXT_APPLICATION_SETTINGS: u16 = 0x4469; // ALPS, 17513

#[derive(Debug, PartialEq, Eq)]
struct ClientHelloFeatures {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extension_ids_in_order: Vec<u16>,
    supported_groups: Vec<u16>,
    supported_versions: Vec<u16>,
    alpn: Vec<String>,
}

impl ClientHelloFeatures {
    fn has_grease_extension(&self) -> bool {
        // RFC 8701 GREASE: 0x0a0a, 0x1a1a, ..., 0xfafa.
        self.extension_ids_in_order.iter().any(|&id| {
            (id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff)
        })
    }

    fn has_alps(&self) -> bool {
        self.extension_ids_in_order.contains(&EXT_APPLICATION_SETTINGS)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(n).ok_or("length overflow")?;
        let result = self.input.get(self.offset..end).ok_or("truncated input")?;
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let two = self.take(2)?;
        Ok(u16::from_be_bytes([two[0], two[1]]))
    }

    fn vec_u8(&mut self) -> Result<&'a [u8], &'static str> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    fn vec_u16(&mut self) -> Result<&'a [u8], &'static str> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    fn empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

fn decode_u16s(bytes: &[u8]) -> Result<Vec<u16>, &'static str> {
    if bytes.len() % 2 != 0 {
        return Err("odd length for u16 vector");
    }
    Ok(bytes.chunks_exact(2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .collect())
}

/// Parse exactly one complete TLS ClientHello handshake message, without
/// accepting malformed/truncated or trailing data. Does not inspect the SNI.
fn parse_client_hello(handshake: &[u8]) -> Result<ClientHelloFeatures, &'static str> {
    let mut h = Reader::new(handshake);
    if h.u8()? != 1 {
        return Err("not ClientHello handshake type");
    }
    let size = h.take(3)?;
    let length = ((size[0] as usize) << 16) | ((size[1] as usize) << 8) | size[2] as usize;
    let body = h.take(length)?;
    if !h.empty() {
        return Err("trailing handshake data");
    }

    let mut c = Reader::new(body);
    let legacy_version = c.u16()?;
    c.take(32)?; // random: never log
    c.vec_u8()?; // session ID: never log
    let cipher_suites = decode_u16s(c.vec_u16()?)?;
    if cipher_suites.is_empty() {
        return Err("no cipher suites");
    }
    c.vec_u8()?; // legacy compression list
    let extensions = c.vec_u16()?;
    if !c.empty() {
        return Err("trailing ClientHello fields");
    }

    let mut ext = Reader::new(extensions);
    let mut ids = Vec::new();
    let mut alpn = Vec::new();
    let mut versions = Vec::new();
    let mut groups = Vec::new();
    while !ext.empty() {
        let id = ext.u16()?;
        let bytes = ext.vec_u16()?;
        if ids.contains(&id) {
            return Err("duplicate extension type");
        }
        ids.push(id);
        match id {
            EXT_ALPN => {
                let mut payload = Reader::new(bytes);
                let list = payload.vec_u16()?;
                if !payload.empty() {
                    return Err("ALPN extension has trailing bytes");
                }
                let mut names = Reader::new(list);
                while !names.empty() {
                    let name = names.vec_u8()?;
                    let text = std::str::from_utf8(name).map_err(|_| "non-UTF8 ALPN")?;
                    alpn.push(text.to_owned());
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut payload = Reader::new(bytes);
                let list = payload.vec_u8()?;
                if !payload.empty() {
                    return Err("versions extension trailing bytes");
                }
                versions = decode_u16s(list)?;
            }
            EXT_SUPPORTED_GROUPS => {
                let mut payload = Reader::new(bytes);
                let list = payload.vec_u16()?;
                if !payload.empty() {
                    return Err("groups extension trailing bytes");
                }
                groups = decode_u16s(list)?;
            }
            _ => {}
        }
    }
    Ok(ClientHelloFeatures {
        legacy_version,
        cipher_suites,
        extension_ids_in_order: ids,
        supported_groups: groups,
        supported_versions: versions,
        alpn,
    })
}

fn parse_tls_records(records: &[u8]) -> Result<ClientHelloFeatures, &'static str> {
    // TLS 1.3 ClientHello may span multiple plaintext TLS records.
    let mut cursor = Reader::new(records);
    let mut handshake = Vec::new();
    while !cursor.empty() {
        let typ = cursor.u8()?;
        cursor.take(2)?; // TLS record legacy version
        let len = cursor.u16()? as usize;
        let payload = cursor.take(len)?;
        if typ != 22 {
            return Err("unexpected pre-handshake TLS record type");
        }
        handshake.extend_from_slice(payload);
    }
    parse_client_hello(&handshake)
}

fn config(alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("test certificate");
    roots.add(cert.cert.der().clone()).expect("valid trust anchor");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 supported")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

fn tcp_client_hello() -> (ClientHelloFeatures, Vec<u8>) {
    let mut client = rustls::ClientConnection::new(
        config(b"h2"),
        ServerName::try_from("localhost".to_owned()).expect("SNI"),
    ).expect("TLS client config");
    let mut first_flight = Vec::new();
    let len = client.write_tls(&mut first_flight).expect("serialize TCP TLS records");
    assert_eq!(len, first_flight.len());
    let observed = parse_tls_records(&first_flight).expect("valid TCP ClientHello");
    (observed, first_flight)
}

fn quic_client_hello() -> (ClientHelloFeatures, Vec<u8>) {
    // The sample transport parameter is valid QUIC varint-encoded
    // max_udp_payload_size=1200, but is NOT Quinn's complete parameter set.
    // Only the TLS extension ID and shape are probed in this isolated test.
    let transport_params = vec![0x03, 0x02, 0x44, 0xb0];
    let mut client = rustls::quic::ClientConnection::new(
        config(b"h3"),
        rustls::quic::Version::V1,
        ServerName::try_from("localhost".to_owned()).expect("SNI"),
        transport_params,
    ).expect("QUIC TLS config");
    let mut crypto_data = Vec::new();
    client.write_hs(&mut crypto_data);
    let observed = parse_client_hello(&crypto_data).expect("valid QUIC CRYPTO ClientHello");
    (observed, crypto_data)
}

#[test]
fn h2_rustls_client_hello_first_flight_observed() {
    let (features, _) = tcp_client_hello();
    assert_eq!(features.legacy_version, 0x0303);
    assert!(features.cipher_suites.contains(&0x1301), "TLS_AES_128_GCM_SHA256");
    assert!(features.extension_ids_in_order.contains(&EXT_SNI));
    assert!(features.extension_ids_in_order.contains(&EXT_ALPN));
    assert!(features.supported_versions.contains(&0x0304), "TLS 1.3 offered");
    assert_eq!(features.alpn, vec!["h2"]);
    assert!(!features.extension_ids_in_order.contains(&EXT_QUIC_TRANSPORT_PARAMETERS));
    // Observational, not a test of any claimed browser profile.
    eprintln!(
        "M0.1/TCP TLS1.3 rustls first flight (no secret material): {features:?}; GREASE={} ALPS={}; browser_profile_verified=false",
        features.has_grease_extension(), features.has_alps()
    );
}

#[test]
fn h3_rustls_quic_crypto_client_hello_first_flight_observed() {
    let (features, _) = quic_client_hello();
    assert_eq!(features.legacy_version, 0x0303);
    assert!(features.extension_ids_in_order.contains(&EXT_SNI));
    assert!(features.supported_versions.contains(&0x0304));
    assert_eq!(features.alpn, vec!["h3"]);
    assert!(features.extension_ids_in_order.contains(&EXT_QUIC_TRANSPORT_PARAMETERS));
    eprintln!(
        "M0.1/QUIC TLS1.3 rustls CRYPTO first flight (not decrypted UDP Initial): {features:?}; GREASE={} ALPS={}; browser_profile_verified=false",
        features.has_grease_extension(), features.has_alps()
    );
}

#[test]
fn parser_rejects_truncated_and_corrupt_first_flights() {
    let (_, tls_records) = tcp_client_hello();
    for i in 0..tls_records.len() {
        assert!(parse_tls_records(&tls_records[..i]).is_err(), "truncated TLS record at {i}");
    }
    let (_, crypto) = quic_client_hello();
    for i in 0..crypto.len() {
        assert!(parse_client_hello(&crypto[..i]).is_err(), "truncated QUIC CRYPTO at {i}");
    }
    let mut invalid = crypto.clone();
    invalid[0] = 2;
    assert!(parse_client_hello(&invalid).is_err(), "ServerHello must not be misread");
    let mut invalid = crypto;
    invalid.push(0);
    assert!(parse_client_hello(&invalid).is_err(), "trailing bytes must not be ignored");
}
