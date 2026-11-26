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
        self.entries.iter().find_map(|(key, value)| (*key == id).then_some(*value))
    }

    /// A scalar parameter must contain exactly one QUIC varint.
    pub fn integer(&self, id: u64) -> Result<Option<u64>, ParameterError> {
        let Some(value) = self.get(id) else { return Ok(None); };
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
    let added = id.len().checked_add(len.len()).and_then(|n| n.checked_add(value.len())).ok_or(ParameterError::Limit)?;
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
        assert_eq!(Parameters::parse(&bytes).unwrap_err(), ParameterError::Duplicate);
    }

    #[test]
    fn validates_budgets_without_partial_output() {
        let mut bytes = vec![1, 0];
        let before = bytes.clone();
        assert_eq!(append(&mut bytes, u64::MAX, &[]), Err(ParameterError::Limit));
        assert_eq!(append(&mut bytes, 2, &vec![0; MAX_PARAMETER_BYTES]), Err(ParameterError::Limit));
        assert_eq!(bytes, before);
        assert_eq!(Parameters::parse(&[1, 2, 0]).unwrap_err(), ParameterError::Truncated);
        assert_eq!(Parameters::parse(&[0x40]).unwrap_err(), ParameterError::Truncated);
        assert_eq!(Parameters::parse(&vec![0; MAX_PARAMETER_BYTES + 1]).unwrap_err(), ParameterError::Limit);
        let mut many = Vec::new();
        for id in 0..=MAX_PARAMETERS {
            append(&mut many, id as u64, &[]).unwrap();
        }
        assert_eq!(Parameters::parse(&many).unwrap_err(), ParameterError::Limit);
    }
}
