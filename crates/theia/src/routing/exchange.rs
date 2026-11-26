//! Shared bounded policy publication and transport validation.
use crate::{
    client::ClientError,
    config::{Inbound, ServerPolicy},
    routing::{snapshot, Settings},
};
use http::header;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

pub(crate) const DOMAIN_HEADER: &str = "theia-routing-domain";
pub(crate) const DIGEST_HEADER: &str = "theia-routing-digest";
pub(crate) const DNS_LIMIT: usize = 1 + 64 * 17;
// Exact-digest receipt for an authenticated conditional refresh.
const UNCHANGED_MAGIC: &[u8; 8] = b"THEIANC1";

pub(crate) fn unchanged_receipt(digest: [u8; 32]) -> [u8; 40] {
    let mut receipt = [0; 40];
    receipt[..8].copy_from_slice(UNCHANGED_MAGIC);
    receipt[8..].copy_from_slice(&digest);
    receipt
}

fn digest_text(digest: [u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn request_digest(
    request: &mut http::Request<()>,
    digest: [u8; 32],
) -> Result<(), ClientError> {
    request.headers_mut().insert(
        DIGEST_HEADER,
        http::HeaderValue::from_str(&digest_text(digest)).map_err(|_| ClientError::Protocol)?,
    );
    Ok(())
}
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) struct Published {
    pub(crate) snapshot: snapshot::Snapshot,
    pub(crate) wire: Arc<[u8]>,
}

impl Published {
    pub(crate) fn prepare(inbound: &Inbound, policy: &ServerPolicy) -> Result<Self, ()> {
        // Own-TLS profiles already pin the configured unique path prefix.
        // REALITY profiles pin the signed inbound ID.
        Self::for_scope(Self::scope(inbound), policy)
    }

    pub(crate) fn scope(inbound: &Inbound) -> &str {
        if inbound.security_mode.is_plain() {
            inbound
                .path_prefix
                .as_deref()
                .and_then(|p| p.strip_prefix("/v1/"))
                .unwrap_or(&inbound.id)
        } else {
            &inbound.id
        }
    }

    pub(crate) fn for_scope(scope: &str, policy: &ServerPolicy) -> Result<Self, ()> {
        let (snapshot, wire) = match &policy.routing {
            Some(settings) => Settings::prepare(settings, scope).map_err(|_| ())?,
            None => snapshot::Snapshot::build(scope, 1, &[], &[], &[]).map_err(|_| ())?,
        };
        Ok(Self {
            snapshot,
            wire: wire.into(),
        })
    }
}

pub(crate) fn validate_headers(headers: &http::HeaderMap) -> Result<usize, ClientError> {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get(header::CONTENT_TYPE).map(|v| v.as_bytes())
            != Some(b"application/octet-stream".as_slice())
        || headers.get_all(header::CONTENT_LENGTH).iter().count() != 1
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return Err(ClientError::Protocol);
    }
    let raw = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .ok_or(ClientError::Protocol)?;
    let len: usize = raw.parse().map_err(|_| ClientError::Protocol)?;
    if !(1..=snapshot::MAX_SNAPSHOT).contains(&len) || raw != len.to_string() {
        return Err(ClientError::Protocol);
    }
    Ok(len)
}

pub(crate) fn append(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    expected: usize,
) -> Result<(), ClientError> {
    if expected > snapshot::MAX_SNAPSHOT
        || bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > expected)
    {
        return Err(ClientError::Protocol);
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn finish(bytes: Vec<u8>, expected: usize) -> Result<Vec<u8>, ClientError> {
    if expected == bytes.len() && expected > 0 && expected <= snapshot::MAX_SNAPSHOT {
        Ok(bytes)
    } else {
        Err(ClientError::Protocol)
    }
}

pub(crate) fn request_domain(
    request: &mut http::Request<()>,
    domain: &str,
    digest: [u8; 32],
) -> Result<(), ClientError> {
    let host = super::domain_name(domain).map_err(|_| ClientError::Protocol)?;
    let mut name = http::HeaderValue::from_str(&host).map_err(|_| ClientError::Protocol)?;
    name.set_sensitive(true);
    request.headers_mut().insert(DOMAIN_HEADER, name);
    request_digest(request, digest)
}

/// This read-only DNS preflight is bound to the exact published policy.
/// No target dial occurs. The caller has already verified TLS/grants,
/// channel binding and empty request body.
pub(crate) async fn response_data(
    publication: &Published,
    headers: &http::HeaderMap,
    allow_private: bool,
    deadline: Duration,
) -> Result<Arc<[u8]>, http::StatusCode> {
    use http::StatusCode;
    let domain_count = headers.get_all(DOMAIN_HEADER).iter().count();
    let digest_count = headers.get_all(DIGEST_HEADER).iter().count();
    if domain_count == 0 {
        if digest_count == 0 {
            return Ok(publication.wire.clone());
        }
        let digest = headers
            .get(DIGEST_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| {
                digest_count == 1
                    && v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or(StatusCode::BAD_REQUEST)?;
        if digest == digest_text(publication.snapshot.digest()) {
            return Ok(Arc::from(
                unchanged_receipt(publication.snapshot.digest()).as_slice(),
            ));
        }
        return Ok(publication.wire.clone());
    }
    if domain_count != 1 || digest_count != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let domain = headers
        .get(DOMAIN_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| super::domain_name(v).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let expected = digest_text(publication.snapshot.digest());
    if headers.get(DIGEST_HEADER).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return Err(StatusCode::CONFLICT);
    }
    // An explicitly selected direct_dpi route may request authenticated
    // DNS pins even when its domain decision is already conclusive.
    if matches!(
        publication.snapshot.policy().domain_decision(&domain)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        Some(action) if action != super::Action::DirectDpi
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let addresses = tokio::time::timeout(deadline, tokio::net::lookup_host((domain.as_str(), 1)))
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut ips = Vec::new();
    for address in addresses.take(65) {
        if ips.len() == 64 {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let ip = match address.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            ip => ip,
        };
        // Do not turn the policy endpoint into a DNS oracle for restricted
        // private destinations. Explicit local direct rules need no preflight.
        if !crate::server::allowed_destination(ip, allow_private) {
            return Err(StatusCode::FORBIDDEN);
        }
        ips.push(ip);
    }
    ips.sort_unstable();
    ips.dedup();
    encode_ips(&ips)
        .map(Arc::from)
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

fn encode_ips(ips: &[IpAddr]) -> Result<Vec<u8>, ClientError> {
    if ips.is_empty() || ips.len() > 64 {
        return Err(ClientError::Protocol);
    }
    let mut out = vec![ips.len() as u8];
    for ip in ips {
        match ip {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
    }
    Ok(out)
}

pub(crate) fn decode_ips(bytes: &[u8]) -> Result<Vec<IpAddr>, ClientError> {
    let (&count, mut bytes) = bytes.split_first().ok_or(ClientError::Protocol)?;
    if count == 0 || count > 64 || bytes.len() >= DNS_LIMIT {
        return Err(ClientError::Protocol);
    }
    let mut out = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (&kind, rest) = bytes.split_first().ok_or(ClientError::Protocol)?;
        let ip = match kind {
            4 => {
                let value: [u8; 4] = rest
                    .get(..4)
                    .ok_or(ClientError::Protocol)?
                    .try_into()
                    .map_err(|_| ClientError::Protocol)?;
                bytes = &rest[4..];
                IpAddr::V4(Ipv4Addr::from(value))
            }
            6 => {
                let value: [u8; 16] = rest
                    .get(..16)
                    .ok_or(ClientError::Protocol)?
                    .try_into()
                    .map_err(|_| ClientError::Protocol)?;
                bytes = &rest[16..];
                let v6 = Ipv6Addr::from(value);
                if v6.to_ipv4_mapped().is_some() {
                    return Err(ClientError::Protocol);
                }
                IpAddr::V6(v6)
            }
            _ => return Err(ClientError::Protocol),
        };
        if ip.is_unspecified() || ip.is_multicast() || out.last().is_some_and(|last| *last >= ip) {
            return Err(ClientError::Protocol);
        }
        out.push(ip);
    }
    if !bytes.is_empty() {
        return Err(ClientError::Protocol);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_response_exact_encoding() {
        let ips = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let bytes = encode_ips(&ips).unwrap();
        assert_eq!(decode_ips(&bytes).unwrap(), ips);
        assert!(decode_ips(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_ips(&[0]).is_err());
        assert!(decode_ips(&encode_ips(&[ips[0], ips[0]]).unwrap()).is_err());
    }
    #[tokio::test]
    async fn dns_preflight_is_digest_bound_and_applies_private_acl() {
        use crate::routing::{Action, Rule};
        let (snapshot, wire) = snapshot::Snapshot::build(
            "scope",
            2,
            &[Rule {
                name: "ip rule".into(),
                action: Action::Direct,
                domains: vec![],
                ips: vec!["127.0.0.0/8".into()],
            }],
            &[],
            &[],
        )
        .unwrap();
        let published = Published {
            snapshot,
            wire: wire.into(),
        };
        let mut request = http::Request::new(());
        let deadline = Duration::from_secs(2);
        assert_eq!(
            response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap(),
            published.wire
        );
        request
            .headers_mut()
            .insert(DOMAIN_HEADER, "localhost".parse().unwrap());
        assert_eq!(
            response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );
        request_domain(&mut request, "localhost", [0; 32]).unwrap();
        assert_eq!(
            response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::CONFLICT
        );
        request_domain(&mut request, "localhost", published.snapshot.digest()).unwrap();
        assert_eq!(
            response_data(&published, request.headers(), false, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::FORBIDDEN
        );
        let ips = decode_ips(
            &response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!ips.is_empty() && ips.iter().all(IpAddr::is_loopback));
        assert!(request_domain(&mut request, "bad..name", [0; 32]).is_err());
        let (snapshot, wire) = snapshot::Snapshot::build("scope", 3, &[], &[], &[]).unwrap();
        let empty = Published {
            snapshot,
            wire: wire.into(),
        };
        request_domain(&mut request, "localhost", empty.snapshot.digest()).unwrap();
        assert_eq!(
            response_data(&empty, request.headers(), true, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn direct_dpi_dns_is_explicit_digest_bound_and_acl_checked() {
        use crate::routing::{Action, Rule};
        let (snapshot, wire) = snapshot::Snapshot::build(
            "scope",
            2,
            &[Rule {
                name: "dpi".into(),
                action: Action::DirectDpi,
                domains: vec!["full:localhost".into()],
                ips: vec![],
            }],
            &[],
            &[],
        )
        .unwrap();
        let published = Published {
            snapshot,
            wire: wire.into(),
        };
        let mut request = http::Request::new(());
        let deadline = Duration::from_secs(2);
        request_domain(&mut request, "localhost", [0; 32]).unwrap();
        assert_eq!(
            response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::CONFLICT
        );
        request_domain(&mut request, "localhost", published.snapshot.digest()).unwrap();
        assert_eq!(
            response_data(&published, request.headers(), false, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::FORBIDDEN
        );
        let ips = decode_ips(
            &response_data(&published, request.headers(), true, deadline)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!ips.is_empty() && ips.iter().all(IpAddr::is_loopback));
    }

    #[tokio::test]
    async fn conditional_snapshot_is_exact_and_rejects_ambiguous_headers() {
        let (snapshot, wire) = snapshot::Snapshot::build("scope", 2, &[], &[], &[]).unwrap();
        let publication = Published {
            snapshot,
            wire: wire.into(),
        };
        let mut request = http::Request::new(());
        let deadline = Duration::from_secs(1);
        request_digest(&mut request, publication.snapshot.digest()).unwrap();
        let receipt = response_data(&publication, request.headers(), false, deadline)
            .await
            .unwrap();
        assert_eq!(&*receipt, &unchanged_receipt(publication.snapshot.digest()));
        request_digest(&mut request, [0; 32]).unwrap();
        assert_eq!(
            response_data(&publication, request.headers(), false, deadline)
                .await
                .unwrap(),
            publication.wire
        );
        request
            .headers_mut()
            .append(DIGEST_HEADER, "invalid".parse().unwrap());
        assert_eq!(
            response_data(&publication, request.headers(), false, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );
        request
            .headers_mut()
            .insert(DIGEST_HEADER, "invalid".parse().unwrap());
        assert_eq!(
            response_data(&publication, request.headers(), false, deadline)
                .await
                .unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn bounded_binary_response() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
        headers.insert(header::CONTENT_LENGTH, "3".parse().unwrap());
        assert_eq!(validate_headers(&headers), Ok(3));
        let mut bytes = Vec::new();
        append(&mut bytes, &[1, 2], 3).unwrap();
        assert!(append(&mut bytes, &[3, 4], 3).is_err());
        append(&mut bytes, &[3], 3).unwrap();
        assert_eq!(finish(bytes, 3), Ok(vec![1, 2, 3]));
        headers.append(header::CONTENT_LENGTH, "3".parse().unwrap());
        assert!(validate_headers(&headers).is_err());
        assert!(finish(vec![1], 2).is_err());
    }
}
