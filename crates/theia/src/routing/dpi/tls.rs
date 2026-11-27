//! Proxy-level TLS analysis. No certificate substitution or packet access.
use super::strategy::Strategy;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) const RECORD_LIMIT: usize = 16 * 1024;
pub(super) const FLIGHT_LIMIT: usize = 32 * 1024 + 16 * 5;
const MAX_RECORDS: usize = 16;

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let result = data.get(..n)?;
    *data = &data[n..];
    Some(result)
}
fn byte(data: &mut &[u8]) -> Option<usize> {
    Some(usize::from(take(data, 1)?[0]))
}
fn word(data: &mut &[u8]) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(
        take(data, 2)?.try_into().ok()?,
    )))
}

pub(super) fn hello_name(data: &[u8]) -> Option<String> {
    hello_metadata(data).map(|(name, _)| name)
}

pub(super) fn hello_metadata(mut data: &[u8]) -> Option<(String, bool)> {
    if byte(&mut data)? != 1 {
        return None;
    }
    let len = take(&mut data, 3)?;
    let length = (usize::from(len[0]) << 16) | (usize::from(len[1]) << 8) | usize::from(len[2]);
    if length != data.len() || take(&mut data, 2)? != [3, 3] {
        return None;
    }
    take(&mut data, 32)?;
    let session = byte(&mut data)?;
    if session > 32 {
        return None;
    }
    take(&mut data, session)?;
    let ciphers = word(&mut data)?;
    if ciphers < 2 || ciphers % 2 != 0 {
        return None;
    }
    take(&mut data, ciphers)?;
    let compression = byte(&mut data)?;
    if compression == 0 || !take(&mut data, compression)?.contains(&0) {
        return None;
    }
    if word(&mut data)? != data.len() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut name = None;
    let mut h3 = false;
    while !data.is_empty() {
        let kind = word(&mut data)?;
        let len = word(&mut data)?;
        let mut value = take(&mut data, len)?;
        if seen.len() == 128 || !seen.insert(kind) {
            return None;
        }
        match kind {
            // Do not apply a name-specific strategy to ECH, even when the
            // public outer SNI happens to match the configured destination.
            0xfe0d => return None,
            0 => {
                if word(&mut value)? != value.len() || byte(&mut value)? != 0 {
                    return None;
                }
                let len = word(&mut value)?;
                let raw = std::str::from_utf8(take(&mut value, len)?).ok()?;
                if !value.is_empty() {
                    return None;
                }
                name = Some(super::super::domain_name(raw).ok()?);
            }
            16 => {
                if word(&mut value)? != value.len() || value.is_empty() {
                    return None;
                }
                while !value.is_empty() {
                    let n = byte(&mut value)?;
                    if n == 0 {
                        return None;
                    }
                    h3 |= take(&mut value, n)? == b"h3";
                }
            }
            _ => {}
        }
    }
    Some((name?, h3))
}

pub(super) enum Flight {
    Need(usize),
    Unsupported,
    Complete {
        message: Vec<u8>,
        consumed: usize,
        version: [u8; 2],
        name: String,
    },
}

/// Parse up to 16 complete plaintext handshake records with bounded total
/// length. Never consume TLS application records or a second handshake.
pub(super) fn inspect(bytes: &[u8]) -> Flight {
    if bytes.len() > FLIGHT_LIMIT {
        return Flight::Unsupported;
    }
    let mut offset = 0;
    let mut message = Vec::new();
    let mut version = None;
    for _ in 0..MAX_RECORDS {
        if bytes.get(offset).is_some_and(|b| *b != 22) {
            return Flight::Unsupported;
        }
        let Some(header) = bytes.get(offset..offset + 5) else {
            return Flight::Need(offset + 5);
        };
        let current = [header[1], header[2]];
        if current[0] != 3
            || !(1..=3).contains(&current[1])
            || version.is_some_and(|old| old != current)
        {
            return Flight::Unsupported;
        }
        version = Some(current);
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = offset + 5 + len;
        if len == 0 || len > RECORD_LIMIT || end > FLIGHT_LIMIT {
            return Flight::Unsupported;
        }
        let Some(body) = bytes.get(offset + 5..end) else {
            return Flight::Need(end);
        };
        message.extend_from_slice(body);
        offset = end;
        if message.first() != Some(&1) || message.len() > 32 * 1024 {
            return Flight::Unsupported;
        }
        if message.len() < 4 {
            continue;
        }
        let total = 4
            + (usize::from(message[1]) << 16)
            + (usize::from(message[2]) << 8)
            + usize::from(message[3]);
        if !(45..=32 * 1024).contains(&total) || message.len() > total {
            return Flight::Unsupported;
        }
        if message.len() == total {
            return match hello_name(&message) {
                Some(name) => Flight::Complete {
                    message,
                    consumed: offset,
                    version: current,
                    name,
                },
                None => Flight::Unsupported,
            };
        }
    }
    Flight::Unsupported
}

/// Reframe only the plaintext ClientHello, retaining its transcript and
/// any following bytes exactly. TCP packet boundaries remain OS-managed.
pub(super) fn transform(bytes: &[u8], expected_name: &str, strategy: Strategy) -> Option<Vec<u8>> {
    let Flight::Complete {
        message,
        consumed,
        version,
        name,
    } = inspect(bytes)
    else {
        return None;
    };
    if name != expected_name {
        return None;
    }
    let middle = message.len() / 2;
    let cuts: &[usize] = match strategy {
        Strategy::Header => &[4],
        Strategy::Middle => &[middle],
        Strategy::Balanced => &[message.len() / 4, middle, message.len() * 3 / 4],
    };
    let mut output = Vec::with_capacity(bytes.len() + 30);
    let mut start = 0;
    for end in cuts.iter().copied().chain(std::iter::once(message.len())) {
        let part = &message[start..end];
        start = end;
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

/// Strict structural observation of a complete plaintext ServerHello.
/// This is not certificate or Finished authentication: the application owns TLS.
/// Permit a valid HelloRetryRequest, and preserve any coalesced later handshake.
pub(super) fn server_hello(mut message: &[u8]) -> bool {
    if byte(&mut message) != Some(2) {
        return false;
    }
    let Some(length) = take(&mut message, 3) else {
        return false;
    };
    let length =
        (usize::from(length[0]) << 16) | (usize::from(length[1]) << 8) | usize::from(length[2]);
    let Some(mut body) = take(&mut message, length) else {
        return false;
    };
    if take(&mut body, 2) != Some(&[3, 3][..]) || take(&mut body, 32).is_none() {
        return false;
    }
    let Some(session) = byte(&mut body) else {
        return false;
    };
    if session > 32
        || take(&mut body, session).is_none()
        || word(&mut body).is_none()
        || byte(&mut body) != Some(0)
    {
        return false;
    }
    if body.is_empty() {
        return true;
    }
    if word(&mut body) != Some(body.len()) {
        return false;
    }
    let mut seen = HashSet::new();
    while !body.is_empty() {
        let Some(kind) = word(&mut body) else {
            return false;
        };
        let Some(len) = word(&mut body) else {
            return false;
        };
        if seen.len() >= 128 || !seen.insert(kind) || take(&mut body, len).is_none() {
            return false;
        }
    }
    true
}

pub(super) fn tls_config(roots: rustls::RootCertStore) -> Option<Arc<rustls::ClientConfig>> {
    crate::net::tls::application_probe(roots).ok().map(Arc::new)
}

pub(super) fn native_config() -> Option<Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            tls_config(crate::net::tls::native_roots())
        })
        .clone()
}

// A separate authenticated TLS probe to the exact policy-pinned address.
// Never send application data or disable hostname/certificate validation.
pub(super) use crate::net::error::ProbeVerdict;

#[cfg(test)]
pub(super) async fn probe(
    name: &str,
    address: SocketAddr,
    scope: Option<crate::network_scope::Scope>,
    strategy: Strategy,
    config: Arc<rustls::ClientConfig>,
) -> Option<()> {
    (probe_guarded(name, address, scope, strategy, config, std::time::Duration::from_secs(2), || true).await
        == ProbeVerdict::Verified).then_some(())
}

#[cfg(test)]
pub(super) async fn probe_guarded(
    name: &str,
    address: SocketAddr,
    scope: Option<crate::network_scope::Scope>,
    strategy: Strategy,
    config: Arc<rustls::ClientConfig>,
    budget: std::time::Duration,
    live: impl Fn() -> bool,
) -> ProbeVerdict {
    let mut rtt = None;
    probe_measured(name, address, scope, strategy, config, budget, live, &mut rtt).await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn probe_measured(
    name: &str,
    address: SocketAddr,
    scope: Option<crate::network_scope::Scope>,
    strategy: Strategy,
    config: Arc<rustls::ClientConfig>,
    budget: std::time::Duration,
    live: impl Fn() -> bool,
    rtt: &mut Option<std::time::Duration>,
) -> ProbeVerdict {
    use ProbeVerdict::*;
    use tokio::time::{timeout_at, Instant};
    if !live() { return Denied; }
    let Ok(server_name) = rustls::pki_types::ServerName::try_from(name.to_owned()) else { return Denied };
    let Ok(mut tls) = rustls::ClientConnection::new(config, server_name) else { return Unavailable };
    let deadline = Instant::now() + budget;
    *rtt = None;
    let connected_at = std::time::Instant::now();
    let (mut socket, _admission) = match timeout_at(deadline, super::tcp::connect(address)).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => return Denied,
        _ => return if live() { Unavailable } else { Denied },
    };
    if !live() || scope.is_some_and(|scope| {
        !socket.local_addr().is_ok_and(|local| scope.matches_local(local))
    }) {
        return Denied;
    }
    // TCP connect duration is a portable SYN round-trip estimate, not
    // kernel TCP_INFO SRTT. Only authenticated success publishes it.
    *rtt = Some(connected_at.elapsed());
    let mut attempted = false;
    let result = timeout_at(deadline, async {
        let mut first = true;
        let mut input = [0; RECORD_LIMIT];
        loop {
            while tls.wants_write() {
                let mut output = Vec::new();
                if !matches!(tls.write_tls(&mut output), Ok(n) if n != 0) { return Unavailable; }
                if first {
                    let Some(transformed) = transform(&output, name, strategy) else { return Unavailable };
                    if transformed == output { return Unavailable; }
                    output = transformed;
                    first = false;
                }
                let mut pending = output.as_slice();
                while !pending.is_empty() {
                    if !live() { return Denied; }
                    attempted = true;
                    match socket.write(pending).await {
                        Ok(n) if n > 0 => pending = &pending[n..],
                        _ => return StrategyFailed,
                    }
                }
            }
            if !tls.is_handshaking() {
                return if !live() { Denied } else if attempted { Verified } else { Unavailable };
            }
            if !tls.wants_read() { return StrategyFailed; }
            let count = match socket.read(&mut input).await {
                Ok(n) if n > 0 => n,
                _ => return StrategyFailed,
            };
            let mut bytes = &input[..count];
            while !bytes.is_empty() {
                if !matches!(tls.read_tls(&mut bytes), Ok(n) if n != 0) { return StrategyFailed; }
                if let Err(error) = tls.process_new_packets() {
                    return match error {
                        rustls::Error::InvalidCertificate(_)
                        | rustls::Error::NoCertificatesPresented
                        | rustls::Error::InvalidCertRevocationList(_)
                        | rustls::Error::UnsupportedNameType
                        | rustls::Error::DecryptError => IdentityRejected,
                        _ => StrategyFailed,
                    };
                }
            }
        }
    }).await;
    if !live() { return Denied; }
    match result {
        Ok(value) => value,
        Err(_) if attempted => StrategyFailed,
        Err(_) => Unavailable,
    }
}

#[cfg(test)]
pub(super) fn fixture(name: &str) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([0; 32]);
    body.extend([0, 0, 2, 0x13, 1, 1, 0]);
    let n = name.len();
    let mut extension = vec![0, 0, 0, (5 + n) as u8, 0, (3 + n) as u8, 0, 0, n as u8];
    extension.extend(name.as_bytes());
    body.extend((extension.len() as u16).to_be_bytes());
    body.extend(extension);
    let mut hello = vec![1, 0, 0, body.len() as u8];
    hello.extend(body);
    record(&hello)
}

#[cfg(test)]
fn record(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![22, 3, 1];
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
            assert_eq!(&bytes[..3], &[22, 3, 1]);
            let n = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            result.extend_from_slice(&bytes[5..5 + n]);
            bytes = &bytes[5 + n..];
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
                with_tail.extend([20, 3, 3, 0, 1, 1]);
                let transformed = transform(&with_tail, "example.org", strategy).unwrap();
                assert_eq!(&transformed[split.len()..], &[20, 3, 3, 0, 1, 1]);
            }
        }
        assert!(transform(&first, "other.org", Strategy::Header).is_none());
    }

    #[test]
    fn rejects_malformed_and_unrelated_data() {
        let original = fixture("example.org");
        for (offset, invalid) in [(0, 23), (1, 4), (2, 0), (3, 255), (5, 2), (9, 4)] {
            let mut bad = original.clone();
            bad[offset] = invalid;
            assert!(transform(&bad, "example.org", Strategy::Middle).is_none());
        }
        assert!(matches!(inspect(b"GET /"), Flight::Unsupported));
        assert!(matches!(
            inspect(&vec![0; FLIGHT_LIMIT + 1]),
            Flight::Unsupported
        ));
    }
}
