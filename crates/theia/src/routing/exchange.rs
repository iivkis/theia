//! Shared bounded policy publication and transport validation.
use crate::{
    client::ClientError,
    config::{Inbound, ServerPolicy},
    routing::{snapshot, Settings},
};
use http::header;
use std::{sync::Arc, time::Duration};

pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) struct Published {
    pub(crate) snapshot: snapshot::Snapshot,
    pub(crate) wire: Arc<[u8]>,
}

impl Published {
    pub(crate) fn prepare(inbound: &Inbound, policy: &ServerPolicy) -> Result<Self, ()> {
        // Own-TLS profiles already pin the configured unique path prefix.
        // REALITY profiles pin the signed inbound ID.
        let scope = if inbound.security_mode.is_plain() {
            inbound.path_prefix.as_deref()
                .and_then(|p| p.strip_prefix("/v1/"))
                .unwrap_or(&inbound.id)
        } else {
            &inbound.id
        };
        Self::for_scope(scope, policy)
    }

    pub(crate) fn for_scope(scope: &str, policy: &ServerPolicy) -> Result<Self, ()> {
        let (snapshot, wire) = match &policy.routing {
            Some(settings) => Settings::prepare(settings, scope).map_err(|_| ())?,
            None => snapshot::Snapshot::build(scope, 1, &[], &[], &[]).map_err(|_| ())?,
        };
        Ok(Self { snapshot, wire: wire.into() })
    }
}

pub(crate) fn validate_headers(headers: &http::HeaderMap) -> Result<usize, ClientError> {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get(header::CONTENT_TYPE).map(|v| v.as_bytes()) != Some(b"application/octet-stream".as_slice())
        || headers.get_all(header::CONTENT_LENGTH).iter().count() != 1
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return Err(ClientError::Protocol);
    }
    let raw = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).ok_or(ClientError::Protocol)?;
    let len: usize = raw.parse().map_err(|_| ClientError::Protocol)?;
    if !(1..=snapshot::MAX_SNAPSHOT).contains(&len) || raw != len.to_string() {
        return Err(ClientError::Protocol);
    }
    Ok(len)
}

pub(crate) fn append(bytes: &mut Vec<u8>, chunk: &[u8], expected: usize) -> Result<(), ClientError> {
    if expected > snapshot::MAX_SNAPSHOT || bytes.len().checked_add(chunk.len()).is_none_or(|n| n > expected) {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_binary_response() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
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
