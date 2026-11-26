//! Bounded transport-parameter TLV parsing (RFC 9000 section 18).
//! This validates syntax and duplicate IDs only. An endpoint must separately
//! check role-specific parameters, CID binding and negotiated value limits.
use super::wire::{encode_varint, varint};

pub const MAX_PARAMETER_BYTES: usize = 16 * 1024;
pub const MAX_PARAMETERS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterError {
    Limit,
    Truncated,
    Duplicate,
    InvalidInteger,
}

#[derive(Debug)]
pub struct Parameters<'a> {
    entries: Vec<(u64, &'a [u8])>,
}

impl<'a> Parameters<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParameterError> {
        if bytes.len() > MAX_PARAMETER_BYTES {
            return Err(ParameterError::Limit);
        }
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            if entries.len() == MAX_PARAMETERS {
                return Err(ParameterError::Limit);
            }
            let id = varint(bytes, &mut pos).ok_or(ParameterError::Truncated)?;
            let len = varint(bytes, &mut pos).ok_or(ParameterError::Truncated)?;
            let len = usize::try_from(len).map_err(|_| ParameterError::Limit)?;
            let end = pos.checked_add(len).ok_or(ParameterError::Limit)?;
            let value = bytes.get(pos..end).ok_or(ParameterError::Truncated)?;
            if entries.iter().any(|(old, _)| *old == id) {
                return Err(ParameterError::Duplicate);
            }
            entries.push((id, value));
            pos = end;
        }
        Ok(Self { entries })
    }

    pub fn get(&self, id: u64) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find_map(|(key, value)| (*key == id).then_some(*value))
    }

    /// A scalar parameter must contain exactly one QUIC varint.
    pub fn integer(&self, id: u64) -> Result<Option<u64>, ParameterError> {
        let Some(value) = self.get(id) else {
            return Ok(None);
        };
        let mut pos = 0;
        let number = varint(value, &mut pos).ok_or(ParameterError::InvalidInteger)?;
        if pos != value.len() {
            return Err(ParameterError::InvalidInteger);
        }
        Ok(Some(number))
    }
}

/// Encode a single opaque parameter into a bounded output, leaving output
/// untouched if its ID or length is not representable or the budget is exceeded.
/// Duplicate IDs across multiple calls are the caller's responsibility.
pub fn append(output: &mut Vec<u8>, id: u64, value: &[u8]) -> Result<(), ParameterError> {
    let mut id_bytes = [0; 8];
    let mut len_bytes = [0; 8];
    let id = encode_varint(id, &mut id_bytes).ok_or(ParameterError::Limit)?;
    let len = encode_varint(value.len() as u64, &mut len_bytes).ok_or(ParameterError::Limit)?;
    let added = id
        .len()
        .checked_add(len.len())
        .and_then(|n| n.checked_add(value.len()))
        .ok_or(ParameterError::Limit)?;
    if output.len().saturating_add(added) > MAX_PARAMETER_BYTES {
        return Err(ParameterError::Limit);
    }
    output.extend_from_slice(id);
    output.extend_from_slice(len);
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_borrowed_unknown_and_integer() {
        let mut bytes = Vec::new();
        append(&mut bytes, 1, &[0x40, 0x40]).unwrap();
        append(&mut bytes, 0x0c, &[]).unwrap();
        append(&mut bytes, 0x1234, &[1, 2, 3]).unwrap();
        let parsed = Parameters::parse(&bytes).unwrap();
        assert_eq!(parsed.integer(1), Ok(Some(64)));
        assert_eq!(parsed.integer(2), Ok(None));
        assert_eq!(parsed.get(0x0c), Some([].as_slice()));
        assert_eq!(parsed.get(0x1234), Some([1, 2, 3].as_slice()));
        assert_eq!(parsed.integer(0x0c), Err(ParameterError::InvalidInteger));
        assert_eq!(parsed.integer(0x1234), Err(ParameterError::InvalidInteger));
        append(&mut bytes, 1, &[]).unwrap();
        assert_eq!(
            Parameters::parse(&bytes).unwrap_err(),
            ParameterError::Duplicate
        );
    }

    #[test]
    fn validates_budgets_without_partial_output() {
        let mut bytes = vec![1, 0];
        let before = bytes.clone();
        assert_eq!(
            append(&mut bytes, u64::MAX, &[]),
            Err(ParameterError::Limit)
        );
        assert_eq!(
            append(&mut bytes, 2, &vec![0; MAX_PARAMETER_BYTES]),
            Err(ParameterError::Limit)
        );
        assert_eq!(bytes, before);
        assert_eq!(
            Parameters::parse(&[1, 2, 0]).unwrap_err(),
            ParameterError::Truncated
        );
        assert_eq!(
            Parameters::parse(&[0x40]).unwrap_err(),
            ParameterError::Truncated
        );
        assert_eq!(
            Parameters::parse(&vec![0; MAX_PARAMETER_BYTES + 1]).unwrap_err(),
            ParameterError::Limit
        );
        let mut many = Vec::new();
        for id in 0..=MAX_PARAMETERS {
            append(&mut many, id as u64, &[]).unwrap();
        }
        assert_eq!(Parameters::parse(&many).unwrap_err(), ParameterError::Limit);
    }
}

/// Expected CID bindings must come from the connection's own packet history.
/// No Retry is inferred from untrusted transport parameters.
pub struct PeerContext<'a> {
    pub server: bool,
    pub initial_source: &'a [u8],
    pub original_destination: &'a [u8],
    pub retry_source: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticError {
    Encoding,
    Cid,
    Role,
    Value,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_udp_payload: u64,
    pub max_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay_ms: u64,
    pub active_cid_limit: u64,
}

impl Parameters<'_> {
    /// Core RFC 9000 transport parameter validation. Unsupported preferred
    /// addresses are rejected at this development stage. This is not
    /// compatible-version negotiation or a complete endpoint contract.
    pub fn validate(&self, peer: PeerContext<'_>) -> Result<Limits, SemanticError> {
        if peer.initial_source.len() > 20
            || peer.original_destination.len() > 20
            || peer.retry_source.is_some_and(|cid| cid.len() > 20)
            || self.get(0x0f) != Some(peer.initial_source)
        {
            return Err(SemanticError::Cid);
        }
        if peer.server {
            if self.get(0x00) != Some(peer.original_destination)
                || self.get(0x10) != peer.retry_source
            {
                return Err(SemanticError::Cid);
            }
            if self
                .get(0x02)
                .is_some_and(|token| token.len() != 16 || peer.initial_source.is_empty())
            {
                return Err(SemanticError::Value);
            }
        } else if [0x00, 0x02, 0x0d, 0x10]
            .iter()
            .any(|id| self.get(*id).is_some())
        {
            return Err(SemanticError::Role);
        }
        if self.get(0x0d).is_some() {
            return Err(SemanticError::Unsupported);
        }
        if self.get(0x0c).is_some_and(|value| !value.is_empty()) {
            return Err(SemanticError::Encoding);
        }
        let get = |id, default| {
            self.integer(id)
                .map(|n| n.unwrap_or(default))
                .map_err(|_| SemanticError::Encoding)
        };
        let max_udp_payload = get(0x03, 65527)?;
        let max_data = get(0x04, 0)?;
        let max_streams_bidi = get(0x08, 0)?;
        let max_streams_uni = get(0x09, 0)?;
        let ack_delay_exponent = get(0x0a, 3)?;
        let max_ack_delay_ms = get(0x0b, 25)?;
        let active_cid_limit = get(0x0e, 2)?;
        // Check encoding even for values not returned by this projection.
        for id in [0x01, 0x05, 0x06, 0x07] {
            get(id, 0)?;
        }
        if max_udp_payload < 1200
            || max_streams_bidi > (1u64 << 60)
            || max_streams_uni > (1u64 << 60)
            || ack_delay_exponent > 20
            || max_ack_delay_ms >= (1 << 14)
            || active_cid_limit < 2
        {
            return Err(SemanticError::Value);
        }
        Ok(Limits {
            max_udp_payload,
            max_data,
            max_streams_bidi,
            max_streams_uni,
            ack_delay_exponent,
            max_ack_delay_ms,
            active_cid_limit,
        })
    }
}

#[cfg(test)]
mod semantic_tests {
    use super::*;

    #[test]
    fn cid_role_and_value_validation() {
        let cid = [1; 8];
        let original = [2; 8];
        let ctx = || PeerContext {
            server: true,
            initial_source: &cid,
            original_destination: &original,
            retry_source: None,
        };
        let mut p = Vec::new();
        append(&mut p, 0x0f, &cid).unwrap();
        assert_eq!(
            Parameters::parse(&p).unwrap().validate(ctx()),
            Err(SemanticError::Cid)
        );
        append(&mut p, 0x00, &original).unwrap();
        assert_eq!(
            Parameters::parse(&p)
                .unwrap()
                .validate(ctx())
                .unwrap()
                .max_udp_payload,
            65527
        );
        let client = PeerContext {
            server: false,
            ..ctx()
        };
        assert_eq!(
            Parameters::parse(&p).unwrap().validate(client),
            Err(SemanticError::Role)
        );
        append(&mut p, 0x0a, &[21]).unwrap();
        assert_eq!(
            Parameters::parse(&p).unwrap().validate(ctx()),
            Err(SemanticError::Value)
        );
    }
}
