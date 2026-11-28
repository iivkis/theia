//! Standalone RFC 8484 DNS provider. No server channel or system lookup.
//! DNS is authenticated by TLS hostname/CA, not a claim of DNSSEC validation.
use super::{canonical_host, canonical_ip, Decision, PreparedPolicy, Resolver};
use crate::{
    net::{address::allowed_destination, guarded_io::{revoked, GuardedIo}, tls},
    network_scope,
    routing::carrier_socket,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

const MAX_MESSAGE: usize = 65535;
const MAX_RECORDS: usize = 128;
const MAX_CNAME: usize = 8;
/// Two families, each with at most eight alias follow-ups.
pub(crate) const MAX_DNS_REQUESTS: usize = 2 * (MAX_CNAME + 1);
const MAX_ADDRESSES: usize = 64;
const MAX_TTL: u32 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    NotConfigured,
    PolicyDenied,
    Cancelled,
    Timeout,
    Transport,
    Tls,
    Http,
    Malformed,
    NxDomain,
    NoAddress,
    ResolverFailure,
    Expired,
    Limit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    A,
    Aaaa,
}
impl Kind {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Answer {
    addresses: Vec<IpAddr>,
    aliases: Vec<String>,
    ttl: u32,
}

fn query(name: &str, kind: Kind) -> Result<Vec<u8>, DnsError> {
    if !canonical_host(name) {
        return Err(DnsError::Malformed);
    }
    // ID zero for DoH. Recursion desired; one exact IN question.
    let mut result = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0);
    result.extend_from_slice(&kind.code().to_be_bytes());
    result.extend_from_slice(&1u16.to_be_bytes());
    Ok(result)
}

fn take<'a>(message: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], DnsError> {
    let end = pos.checked_add(n).ok_or(DnsError::Malformed)?;
    let value = message.get(*pos..end).ok_or(DnsError::Malformed)?;
    *pos = end;
    Ok(value)
}
fn word(message: &[u8], pos: &mut usize) -> Result<u16, DnsError> {
    let b = take(message, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn long(message: &[u8], pos: &mut usize) -> Result<u32, DnsError> {
    let b = take(message, pos, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Backward-only compression pointers, bounded expansion and exact cursor
/// consumption. Root names are permitted for OPT records, not user targets.
fn name(message: &[u8], pos: &mut usize) -> Result<String, DnsError> {
    let mut cursor = *pos;
    let mut resumed = None;
    let mut labels = Vec::new();
    let mut expanded = 1usize;
    let mut jumps = 0;
    loop {
        let length = *message.get(cursor).ok_or(DnsError::Malformed)?;
        cursor += 1;
        if length == 0 {
            *pos = resumed.unwrap_or(cursor);
            return Ok(labels.join("."));
        }
        if length & 0xc0 == 0xc0 {
            let low = *message.get(cursor).ok_or(DnsError::Malformed)?;
            let target = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if target < 12 || target >= cursor - 1 || jumps >= 16 {
                return Err(DnsError::Malformed);
            }
            if resumed.is_none() {
                resumed = Some(cursor + 1);
            }
            cursor = target;
            jumps += 1;
            continue;
        }
        if length > 63 {
            return Err(DnsError::Malformed);
        }
        let label = take(message, &mut cursor, usize::from(length))?;
        expanded += label.len() + 1;
        if expanded > 255
            || !label.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
        {
            return Err(DnsError::Malformed);
        }
        labels.push(std::str::from_utf8(label)
            .map_err(|_| DnsError::Malformed)?.to_ascii_lowercase());
    }
}

fn parse(message: &[u8], expected: &str, kind: Kind) -> Result<Answer, DnsError> {
    if message.len() > MAX_MESSAGE {
        return Err(DnsError::Limit);
    }
    let mut pos = 0;
    let id = word(message, &mut pos)?;
    let flags = word(message, &mut pos)?;
    let questions = word(message, &mut pos)?;
    let answers = usize::from(word(message, &mut pos)?);
    let authority = usize::from(word(message, &mut pos)?);
    let additional = usize::from(word(message, &mut pos)?);
    if id != 0 || flags & 0x8000 == 0 || flags & 0x7a40 != 0 || questions != 1 {
        return Err(DnsError::Malformed);
    }
    if answers + authority + additional > MAX_RECORDS {
        return Err(DnsError::Limit);
    }
    if name(message, &mut pos)? != expected
        || word(message, &mut pos)? != kind.code()
        || word(message, &mut pos)? != 1
    {
        return Err(DnsError::Malformed);
    }

    let mut aliases = BTreeMap::<String, (String, u32)>::new();
    let mut addresses = BTreeMap::<String, Vec<(IpAddr, u32)>>::new();
    let mut extended_rcode = 0;
    let mut opt_seen = false;
    let mut count = 0;
    for i in 0..answers + authority + additional {
        let owner = name(message, &mut pos)?;
        let rr = word(message, &mut pos)?;
        let class = word(message, &mut pos)?;
        let ttl = long(message, &mut pos)?;
        let length = usize::from(word(message, &mut pos)?);
        let begin = pos;
        let data = take(message, &mut pos, length)?;

        if rr == 41 {
            if i < answers + authority || !owner.is_empty() || opt_seen {
                return Err(DnsError::Malformed);
            }
            opt_seen = true;
            extended_rcode = (ttl >> 24) as u16;
            if (ttl >> 16) & 0xff != 0 {
                return Err(DnsError::Malformed);
            }
            continue;
        }
        if i >= answers {
            // Authority/additional data cannot supply egress pins.
            continue;
        }
        if class != 1 || !canonical_host(&owner) {
            return Err(DnsError::Malformed);
        }
        match rr {
            5 => {
                let mut at = begin;
                let target = name(message, &mut at)?;
                if at != pos || !canonical_host(&target)
                    || aliases.insert(owner, (target, ttl)).is_some()
                {
                    return Err(DnsError::Malformed);
                }
            }
            1 | 28 => {
                if rr != kind.code() {
                    return Err(DnsError::Malformed);
                }
                let ip = match rr {
                    1 if data.len() == 4 => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    28 if data.len() == 16 => {
                        let octets: [u8; 16] = data.try_into().map_err(|_| DnsError::Malformed)?;
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => return Err(DnsError::Malformed),
                };
                if canonical_ip(ip) != ip || !allowed_destination(ip, false) {
                    return Err(DnsError::PolicyDenied);
                }
                count += 1;
                if count > MAX_ADDRESSES {
                    return Err(DnsError::Limit);
                }
                addresses.entry(owner).or_default().push((ip, ttl));
            }
            // RRSIGs are not interpreted as DNSSEC evidence.
            46 => {}
            _ => return Err(DnsError::Malformed),
        }
    }
    if pos != message.len() {
        return Err(DnsError::Malformed);
    }
    match (extended_rcode << 4) | (flags & 15) {
        0 => {}
        3 => return Err(DnsError::NxDomain),
        _ => return Err(DnsError::ResolverFailure),
    }

    let mut current = expected.to_owned();
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut ttl = MAX_TTL;
    while let Some((next, lifetime)) = aliases.remove(&current) {
        if addresses.contains_key(&current) || !seen.insert(current)
            || chain.len() >= MAX_CNAME
        {
            return Err(DnsError::Malformed);
        }
        ttl = ttl.min(lifetime);
        current = next;
        chain.push(current.clone());
    }
    // Removing an alias while traversing it must not hide a cycle that
    // returns to an already consumed owner (including a self-reference).
    if seen.contains(&current) || !aliases.is_empty() {
        return Err(DnsError::Malformed);
    }
    let records = addresses.remove(&current).unwrap_or_default();
    if !addresses.is_empty() {
        return Err(DnsError::Malformed);
    }
    let mut ips = BTreeSet::new();
    for (ip, lifetime) in records {
        ttl = ttl.min(lifetime);
        ips.insert(ip);
    }
    Ok(Answer { addresses: ips.into_iter().collect(), aliases: chain, ttl })
}

/// An immutable resolution for the current operation only, never a global
/// DNS cache. TTL zero cannot authorize reuse by a later diagnostic cell.
#[derive(Debug)]
pub(crate) struct Pins {
    addresses: Vec<IpAddr>,
    expires: Instant,
    single_use: bool,
    decision: Decision,
}

impl Pins {
    pub(crate) fn addresses(&self) -> &[IpAddr] { &self.addresses }
    pub(crate) fn decision(&self) -> Decision { self.decision }
    pub(crate) fn single_use(&self) -> bool { self.single_use }
    pub(crate) fn current(&self) -> bool {
        Instant::now() < self.expires
    }
}

fn combine(
    policy: &PreparedPolicy,
    target: &str,
    a: (Answer, Instant),
    aaaa: (Answer, Instant),
    deadline: Instant,
) -> Result<Pins, DnsError> {
    let (a, a_at) = a;
    let (aaaa, aaaa_at) = aaaa;
    if !a.addresses.is_empty() && !aaaa.addresses.is_empty() && a.aliases != aaaa.aliases {
        return Err(DnsError::Malformed);
    }
    let mut addresses = a.addresses;
    addresses.extend(aaaa.addresses);
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(DnsError::NoAddress);
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(DnsError::Limit);
    }
    let decision = policy.classify_resolved(target, &addresses);
    if !matches!(decision, Decision::Pass | Decision::Modify) {
        return Err(DnsError::PolicyDenied);
    }
    for alias in a.aliases.iter().chain(&aaaa.aliases) {
        if policy.classify_resolved(alias, &addresses) != decision {
            return Err(DnsError::PolicyDenied);
        }
    }
    let single_use = a.ttl == 0 || aaaa.ttl == 0;
    let expiry = |ttl: u32, at: Instant| {
        if ttl == 0 {
            deadline
        } else {
            at + Duration::from_secs(u64::from(ttl))
        }
    };
    let expires = expiry(a.ttl, a_at).min(expiry(aaaa.ttl, aaaa_at))
        .min(if single_use { deadline } else { Instant::now() + Duration::from_secs(60) });
    if Instant::now() >= expires {
        return Err(DnsError::Expired);
    }
    Ok(Pins { addresses, expires, single_use, decision })
}

async fn exchange(
    resolver: &Resolver,
    peer: SocketAddr,
    request_bytes: Vec<u8>,
    config: Arc<rustls::ClientConfig>,
    live: &(dyn Fn() -> bool + Sync),
) -> Result<(Vec<u8>, u32), DnsError> {
    if !live() {
        return Err(DnsError::Cancelled);
    }
    let scope = network_scope::observe(peer).ok_or(DnsError::PolicyDenied)?;
    let scoped = || live() && network_scope::observe(peer) == Some(scope);
    let operation = async {
        if !scoped() {
            return Err(DnsError::PolicyDenied);
        }
        let socket = carrier_socket::connect_plain_tcp(peer).await.map_err(|_| DnsError::Transport)?;
        if !socket.local_addr().is_ok_and(|local| scope.matches_local(local)) || !scoped() {
            return Err(DnsError::PolicyDenied);
        }
        let server = rustls::pki_types::ServerName::try_from(resolver.hostname.clone())
            .map_err(|_| DnsError::Tls)?;
        let guarded = GuardedIo::new(socket, &scoped);
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(server, guarded).await.map_err(|_| DnsError::Tls)?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(DnsError::Tls);
        }
        let (sender, connection) = h2::client::Builder::new()
            .max_header_list_size(8 * 1024)
            .handshake::<_, bytes::Bytes>(stream).await.map_err(|_| DnsError::Transport)?;
        // Drive the HTTP/2 connection in the same future: no detached task,
        // retries, redirects, cookies or mutable system resolver dependency.
        let response = async {
            let mut sender = sender.ready().await.map_err(|_| DnsError::Transport)?;
            let uri = format!("https://{}/dns-query?dns={}", resolver.hostname,
                URL_SAFE_NO_PAD.encode(request_bytes));
            let request = http::Request::get(uri)
                .header(http::header::ACCEPT, "application/dns-message")
                .header(http::header::ACCEPT_ENCODING, "identity")
                .header(http::header::CACHE_CONTROL, "no-cache, no-store")
                .body(()).map_err(|_| DnsError::Malformed)?;
            if !scoped() {
                return Err(DnsError::Cancelled);
            }
            let (response, _) = sender.send_request(request, true)
                .map_err(|_| DnsError::Transport)?;
            let response = response.await.map_err(|_| DnsError::Transport)?;
            let headers = response.headers();
            if response.status() != http::StatusCode::OK
                || headers.get_all(http::header::CONTENT_TYPE).iter().count() != 1
                || !headers.get(http::header::CONTENT_TYPE)
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"application/dns-message"))
                || headers.get_all(http::header::CONTENT_LENGTH).iter().count() > 1
                || headers.get_all(http::header::CONTENT_ENCODING).iter().count() > 1
                || headers.get(http::header::CONTENT_ENCODING)
                    .is_some_and(|v| v.as_bytes() != b"identity")
            {
                return Err(DnsError::Http);
            }
            if headers.get_all(http::header::AGE).iter().count() > 1 {
                return Err(DnsError::Http);
            }
            let age = headers.get(http::header::AGE)
                .map(|v| v.to_str().ok().and_then(|s| s.parse::<u32>().ok())
                    .ok_or(DnsError::Http)).transpose()?.unwrap_or(0);
            let length = headers.get(http::header::CONTENT_LENGTH)
                .map(|v| v.to_str().ok().and_then(|s| s.parse::<usize>().ok())
                    .ok_or(DnsError::Http)).transpose()?;
            if length.is_some_and(|n| n > MAX_MESSAGE) {
                return Err(DnsError::Limit);
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|_| DnsError::Transport)?;
                if !scoped() {
                    return Err(DnsError::Cancelled);
                }
                if bytes.len().saturating_add(chunk.len()) > MAX_MESSAGE {
                    return Err(DnsError::Limit);
                }
                bytes.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).map_err(|_| DnsError::Transport)?;
            }
            if length.is_some_and(|n| n != bytes.len()) || body.trailers().await
                .map_err(|_| DnsError::Transport)?.is_some() {
                return Err(DnsError::Http);
            }
            Ok((bytes, age))
        };
        tokio::pin!(response, connection);
        tokio::select! {
            biased;
            result = &mut response => result,
            _ = &mut connection => Err(DnsError::Transport),
        }
    };
    tokio::select! {
        biased;
        _ = revoked(&scoped) => Err(if live() { DnsError::PolicyDenied } else { DnsError::Cancelled }),
        result = operation => if scoped() { result } else {
            Err(if live() { DnsError::PolicyDenied } else { DnsError::Cancelled })
        },
    }
}

fn aged(mut answer: Answer, age: u32) -> Result<Answer, DnsError> {
    if age > 0 && age >= answer.ttl {
        return Err(DnsError::Expired);
    }
    answer.ttl = answer.ttl.saturating_sub(age);
    Ok(answer)
}

/// Continue an authenticated CNAME-only response on the same resolver and
/// original deadline. All traversed aliases are checked before another query
/// and again against the eventual exact egress pins.
struct Chain {
    target: String,
    aliases: Vec<String>,
    seen: BTreeSet<String>,
    ttl: u32,
}

impl Chain {
    fn new(target: &str) -> Self {
        Self {
            target: target.to_owned(),
            aliases: Vec::new(),
            seen: BTreeSet::from([target.to_owned()]),
            ttl: MAX_TTL,
        }
    }

    fn extend(&mut self, answer: Answer, policy: &PreparedPolicy)
        -> Result<Option<Answer>, DnsError>
    {
        self.ttl = self.ttl.min(answer.ttl);
        let had_alias = !answer.aliases.is_empty();
        for alias in answer.aliases {
            if self.aliases.len() >= MAX_CNAME || !self.seen.insert(alias.clone()) {
                return Err(DnsError::Malformed);
            }
            if policy.classify_domain(&alias) == Decision::Drop {
                return Err(DnsError::PolicyDenied);
            }
            self.target = alias.clone();
            self.aliases.push(alias);
        }
        if answer.addresses.is_empty() && had_alias {
            return Ok(None);
        }
        Ok(Some(Answer {
            addresses: answer.addresses,
            aliases: self.aliases.clone(),
            ttl: self.ttl,
        }))
    }
}

async fn lookup_family(
    resolver: &Resolver,
    peer: SocketAddr,
    policy: &PreparedPolicy,
    target: &str,
    kind: Kind,
    config: Arc<rustls::ClientConfig>,
    live: &(dyn Fn() -> bool + Sync),
) -> Result<(Answer, Instant), DnsError> {
    let started = Instant::now();
    let mut chain = Chain::new(target);
    for _ in 0..=MAX_CNAME {
        if !live() {
            return Err(DnsError::Cancelled);
        }
        let (raw, age) = exchange(resolver, peer, query(&chain.target, kind)?, config.clone(), live).await?;
        let answer = aged(parse(&raw, &chain.target, kind)?, age)?;
        if let Some(result) = chain.extend(answer, policy)? {
            // Use earliest query start and minimum TTL, conservatively
            // bounding every intermediate record rather than extending it.
            return Ok((result, started));
        }
    }
    Err(DnsError::Limit)
}

/// Both address families must complete under the same deadline. A failed
/// AAAA lookup cannot silently become an A-only policy decision.
pub(crate) async fn resolve(
    resolver: Option<&Resolver>,
    policy: &PreparedPolicy,
    target: &str,
    roots: &rustls::RootCertStore,
    live: &(dyn Fn() -> bool + Sync),
    deadline: Instant,
) -> Result<Pins, DnsError> {
    if !live() {
        return Err(DnsError::Cancelled);
    }
    if policy.classify_domain(target) == Decision::Drop {
        return Err(DnsError::PolicyDenied);
    }
    let resolver = resolver.ok_or(DnsError::NotConfigured)?;
    resolver.validate().map_err(|_| DnsError::PolicyDenied)?;
    if !matches!(policy.classify_resolved(&resolver.hostname, &resolver.bootstrap),
        Decision::Pass | Decision::Modify) {
        return Err(DnsError::PolicyDenied);
    }
    // Explicit deterministic bootstrap, no implicit fallback or second dial.
    let peer = SocketAddr::new(resolver.bootstrap[0], 443);
    let mut config = tls::application_probe(roots.clone()).map_err(|_| DnsError::Tls)?;
    tls::configure_client(&mut config, b"h2");
    let config = Arc::new(config);
    let result = tokio::time::timeout_at(deadline, async {
        let a = lookup_family(resolver, peer, policy, target, Kind::A, config.clone(), live).await?;
        let aaaa = lookup_family(resolver, peer, policy, target, Kind::Aaaa, config, live).await?;
        if !live() {
            return Err(DnsError::Cancelled);
        }
        combine(policy, target, a, aaaa, deadline)
    }).await.map_err(|_| DnsError::Timeout)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(name: &str, kind: Kind, count: u16) -> Vec<u8> {
        let mut result = query(name, kind).unwrap();
        result[2..4].copy_from_slice(&[0x81, 0x80]);
        result[6..8].copy_from_slice(&count.to_be_bytes());
        result
    }

    fn rr(out: &mut Vec<u8>, owner: &[u8], kind: u16, ttl: u32, data: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    #[test]
    fn exact_question_flags_and_full_message() {
        let mut bytes = response("example.com", Kind::A, 1);
        rr(&mut bytes, &[0xc0, 12], 1, 200, &[1, 1, 1, 1]);
        let result = parse(&bytes, "example.com", Kind::A).unwrap();
        assert_eq!(result.ttl, 60);
        assert_eq!(result.addresses, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(parse(&bytes, "other.com", Kind::A), Err(DnsError::Malformed));
        assert_eq!(parse(&bytes, "example.com", Kind::Aaaa), Err(DnsError::Malformed));
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n], "example.com", Kind::A).is_err());
        }
        let mut truncated = bytes.clone();
        truncated[2] |= 2;
        assert_eq!(parse(&truncated, "example.com", Kind::A), Err(DnsError::Malformed));
        bytes.push(0);
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::Malformed));
    }

    #[test]
    fn cname_and_ttl_zero_and_mixed_private() {
        let mut bytes = response("example.com", Kind::A, 2);
        let alias = b"\x05alias\x07example\x03com\x00";
        rr(&mut bytes, &[0xc0, 12], 5, 0, alias);
        rr(&mut bytes, alias, 1, 30, &[8, 8, 8, 8]);
        let result = parse(&bytes, "example.com", Kind::A).unwrap();
        assert_eq!(result.aliases, vec!["alias.example.com"]);
        assert_eq!(result.ttl, 0);
        let mut denied = response("example.com", Kind::A, 2);
        rr(&mut denied, &[0xc0, 12], 1, 60, &[8, 8, 8, 8]);
        rr(&mut denied, &[0xc0, 12], 1, 60, &[127, 0, 0, 1]);
        assert_eq!(parse(&denied, "example.com", Kind::A), Err(DnsError::PolicyDenied));
    }

    #[test]
    fn nxdomain_and_empty_answer_are_distinct() {
        let mut bytes = response("example.com", Kind::A, 0);
        assert!(parse(&bytes, "example.com", Kind::A).unwrap().addresses.is_empty());
        bytes[3] |= 3;
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::NxDomain));
        bytes[3] &= !15;
        bytes[3] |= 2;
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::ResolverFailure));
    }

    #[test]
    fn cross_response_alias_chain_is_bounded_and_cycle_safe() {
        let doc = super::super::Document::parse(include_str!("../../../../examples/anti-dpi.toml")).unwrap();
        let policy = doc.prepare().unwrap();
        let mut chain = Chain::new("example.com");
        let alias = |host: String| Answer { addresses: Vec::new(), aliases: vec![host], ttl: 30 };
        assert!(chain.extend(alias("alias.example.com".into()), &policy).unwrap().is_none());
        assert_eq!(chain.target, "alias.example.com");
        assert_eq!(chain.extend(alias("example.com".into()), &policy), Err(DnsError::Malformed));

        let mut chain = Chain::new("example.com");
        for i in 0..8 {
            assert!(chain.extend(alias(format!("a{i}.example.com")), &policy).unwrap().is_none());
        }
        assert_eq!(chain.extend(alias("overflow.example.com".into()), &policy), Err(DnsError::Malformed));

        let mut chain = Chain::new("example.com");
        chain.extend(alias("alias.example.com".into()), &policy).unwrap();
        let answer = chain.extend(Answer {
            addresses: vec!["1.1.1.1".parse().unwrap()], aliases: vec![], ttl: 60,
        }, &policy).unwrap().unwrap();
        assert_eq!(answer.ttl, 30);
        assert_eq!(answer.aliases, vec!["alias.example.com"]);
    }

    #[test]
    fn cname_cycle_and_unrelated_answer_fail_closed() {
        let mut bytes = response("example.com", Kind::A, 1);
        rr(&mut bytes, &[0xc0, 12], 5, 10, &[0xc0, 12]);
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::Malformed));
        let mut bytes = response("example.com", Kind::A, 2);
        rr(&mut bytes, &[0xc0, 12], 5, 10, b"\x05alias\x07example\x03com\x00");
        rr(&mut bytes, b"\x05alias\x07example\x03com\x00", 5, 10, &[0xc0, 12]);
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::Malformed));
        let mut bytes = response("example.com", Kind::A, 1);
        rr(&mut bytes, b"\x05other\x03com\x00", 1, 10, &[1, 1, 1, 1]);
        assert_eq!(parse(&bytes, "example.com", Kind::A), Err(DnsError::Malformed));
    }
}
