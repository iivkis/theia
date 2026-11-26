//! Proxy-level TLS analysis. No certificate substitution or packet access.
use super::strategy::Strategy;
use std::{collections::HashSet, net::SocketAddr, sync::{Arc, OnceLock}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) const RECORD_LIMIT: usize = 16 * 1024;
pub(super) const FLIGHT_LIMIT: usize = 32 * 1024 + 16 * 5;
const MAX_RECORDS: usize = 16;

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let result = data.get(..n)?;
    *data = &data[n..];
    Some(result)
}
fn byte(data: &mut &[u8]) -> Option<usize> { Some(usize::from(take(data, 1)?[0])) }
fn word(data: &mut &[u8]) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(take(data, 2)?.try_into().ok()?)))
}

pub(super) fn hello_name(mut data: &[u8]) -> Option<String> {
    if byte(&mut data)? != 1 { return None; }
    let len = take(&mut data, 3)?;
    let length = (usize::from(len[0]) << 16) | (usize::from(len[1]) << 8) | usize::from(len[2]);
    if length != data.len() || take(&mut data, 2)? != [3, 3] { return None; }
    take(&mut data, 32)?;
    let session = byte(&mut data)?;
    if session > 32 { return None; }
    take(&mut data, session)?;
    let ciphers = word(&mut data)?;
    if ciphers < 2 || ciphers % 2 != 0 { return None; }
    take(&mut data, ciphers)?;
    let compression = byte(&mut data)?;
    if compression == 0 || !take(&mut data, compression)?.contains(&0) { return None; }
    if word(&mut data)? != data.len() { return None; }
    let mut seen = HashSet::new();
    let mut name = None;
    while !data.is_empty() {
        let kind = word(&mut data)?;
        let len = word(&mut data)?;
        let mut value = take(&mut data, len)?;
        if seen.len() == 128 || !seen.insert(kind) { return None; }
        match kind {
            // Do not apply a name-specific strategy to ECH, even when the
            // public outer SNI happens to match the configured destination.
            0xfe0d => return None,
            0 => {
                if word(&mut value)? != value.len() || byte(&mut value)? != 0 { return None; }
                let len = word(&mut value)?;
                let raw = std::str::from_utf8(take(&mut value, len)?).ok()?;
                if !value.is_empty() { return None; }
                name = Some(super::super::domain_name(raw).ok()?);
            }
            _ => {}
        }
    }
    name
}

pub(super) enum Flight {
    Need(usize),
    Unsupported,
    Complete { message: Vec<u8>, consumed: usize, version: [u8; 2], name: String },
}

/// Parse up to 16 complete plaintext handshake records with bounded total
/// length. Never consume TLS application records or a second handshake.
pub(super) fn inspect(bytes: &[u8]) -> Flight {
    if bytes.len() > FLIGHT_LIMIT { return Flight::Unsupported; }
    let mut offset = 0;
    let mut message = Vec::new();
    let mut version = None;
    for _ in 0..MAX_RECORDS {
        if bytes.get(offset).is_some_and(|b| *b != 22) { return Flight::Unsupported; }
        let Some(header) = bytes.get(offset..offset+5) else { return Flight::Need(offset+5); };
        let current = [header[1], header[2]];
        if current[0] != 3 || !(1..=3).contains(&current[1])
            || version.is_some_and(|old| old != current)
        { return Flight::Unsupported; }
        version = Some(current);
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = offset + 5 + len;
        if len == 0 || len > RECORD_LIMIT || end > FLIGHT_LIMIT { return Flight::Unsupported; }
        let Some(body) = bytes.get(offset+5..end) else { return Flight::Need(end); };
        message.extend_from_slice(body);
        offset = end;
        if message.first() != Some(&1) || message.len() > 32*1024 { return Flight::Unsupported; }
        if message.len() < 4 { continue; }
        let total = 4 + (usize::from(message[1]) << 16) + (usize::from(message[2]) << 8) + usize::from(message[3]);
        if !(45..=32*1024).contains(&total) || message.len() > total { return Flight::Unsupported; }
        if message.len() == total {
            return match hello_name(&message) {
                Some(name) => Flight::Complete { message, consumed: offset, version: current, name },
                None => Flight::Unsupported,
            };
        }
    }
    Flight::Unsupported
}

/// Reframe only the plaintext ClientHello, retaining its transcript and
/// any following bytes exactly. TCP packet boundaries remain OS-managed.
pub(super) fn transform(bytes: &[u8], expected_name: &str, strategy: Strategy) -> Option<Vec<u8>> {
    let Flight::Complete { message, consumed, version, name } = inspect(bytes) else { return None; };
    if name != expected_name { return None; }
    let cut = match strategy { Strategy::Header => 4, Strategy::Middle => message.len()/2 };
    let mut output = Vec::with_capacity(bytes.len()+15);
    for part in [&message[..cut], &message[cut..]] {
        for chunk in part.chunks(RECORD_LIMIT) {
            output.push(22);
            output.extend_from_slice(&version);
            output.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            output.extend_from_slice(chunk);
        }
    }
    output.extend_from_slice(&bytes[consumed..]);
    Some(output)
}

pub(super) fn tls_config(roots: rustls::RootCertStore) -> Option<Arc<rustls::ClientConfig>> {
    if roots.is_empty() {
        return None;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Some(Arc::new(config))
}

pub(super) fn native_config() -> Option<Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            tls_config(roots)
        })
        .clone()
}

// A separate authenticated TLS probe to the exact policy-pinned address.
// Never send application data or disable hostname/certificate validation.
pub(super) async fn probe(
    name: &str,
    address: SocketAddr,
    strategy: Strategy,
    config: Arc<rustls::ClientConfig>,
) -> Option<()> {
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).ok()?;
    let mut tls = rustls::ClientConnection::new(config, server_name).ok()?;
    let mut socket = super::tcp::connect(address).await.ok()?;
    let mut first = true;
    let mut input = [0; RECORD_LIMIT];
    loop {
        while tls.wants_write() {
            let mut output = Vec::new();
            if tls.write_tls(&mut output).ok()? == 0 {
                return None;
            }
            if first {
                output = transform(&output, name, strategy)?;
                first = false;
            }
            socket.write_all(&output).await.ok()?;
        }
        if !tls.is_handshaking() {
            return (!first).then_some(());
        }
        if !tls.wants_read() {
            return None;
        }
        let count = socket.read(&mut input).await.ok()?;
        if count == 0 {
            return None;
        }
        let mut bytes = &input[..count];
        while !bytes.is_empty() {
            if tls.read_tls(&mut bytes).ok()? == 0 {
                return None;
            }
            tls.process_new_packets().ok()?;
        }
    }
}


#[cfg(test)]
pub(super) fn fixture(name: &str) -> Vec<u8> {
    let mut body = vec![3,3];
    body.extend([0;32]);
    body.extend([0,0,2,0x13,1,1,0]);
    let n = name.len();
    let mut extension = vec![0,0,0,(5+n) as u8,0,(3+n) as u8,0,0,n as u8];
    extension.extend(name.as_bytes());
    body.extend((extension.len() as u16).to_be_bytes());
    body.extend(extension);
    let mut hello = vec![1,0,0,body.len() as u8];
    hello.extend(body);
    record(&hello)
}

#[cfg(test)]
fn record(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![22,3,1];
    bytes.extend((body.len() as u16).to_be_bytes());
    bytes.extend(body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(mut bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        while !bytes.is_empty() {
            assert_eq!(&bytes[..3], &[22,3,1]);
            let n = usize::from(u16::from_be_bytes([bytes[3],bytes[4]]));
            result.extend_from_slice(&bytes[5..5+n]);
            bytes = &bytes[5+n..];
        }
        result
    }

    #[test]
    fn reassembly_and_reframing_preserve_transcript_and_tail() {
        let first = fixture("example.org");
        let mut fragmented = record(&first[5..7]);
        fragmented.extend(record(&first[7..15]));
        fragmented.extend(record(&first[15..]));
        for input in [&first, &fragmented] {
            for end in 0..input.len() {
                assert!(matches!(inspect(&input[..end]), Flight::Need(_)));
            }
            for strategy in Strategy::ALL {
                let split = transform(input, "example.org", strategy).unwrap();
                assert_eq!(payload(&split), first[5..]);
                let mut with_tail = input.clone();
                with_tail.extend([20,3,3,0,1,1]);
                let transformed = transform(&with_tail, "example.org", strategy).unwrap();
                assert_eq!(&transformed[split.len()..], &[20,3,3,0,1,1]);
            }
        }
        assert!(transform(&first, "other.org", Strategy::Header).is_none());
    }

    #[test]
    fn rejects_malformed_and_unrelated_data() {
        let original = fixture("example.org");
        for (offset, invalid) in [(0,23),(1,4),(2,0),(3,255),(5,2),(9,4)] {
            let mut bad = original.clone();
            bad[offset] = invalid;
            assert!(transform(&bad,"example.org",Strategy::Middle).is_none());
        }
        assert!(matches!(inspect(b"GET /"), Flight::Unsupported));
        assert!(matches!(inspect(&vec![0;FLIGHT_LIMIT+1]), Flight::Unsupported));
    }
}
