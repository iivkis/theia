//! Shared RFC 9000 wire primitives; no dependency on a QUIC endpoint.
pub const MAX_VARINT: u64 = (1 << 62) - 1;
pub const V1: u32 = 1;
pub const V2: u32 = 0x6b3343cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    pub fn from_wire(value: u32) -> Option<Self> {
        match value {
            V1 => Some(Self::V1),
            V2 => Some(Self::V2),
            _ => None,
        }
    }

    pub fn wire(self) -> u32 {
        match self {
            Self::V1 => V1,
            Self::V2 => V2,
        }
    }
}

/// Accept all legal QUIC varint widths. On failure leave the cursor untouched.
pub fn varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *bytes.get(*pos)?;
    let width = 1usize << (first >> 6);
    let end = pos.checked_add(width)?;
    let mut value = u64::from(first & 63);
    for &byte in bytes.get(*pos + 1..end)? {
        value = (value << 8) | u64::from(byte);
    }
    *pos = end;
    Some(value)
}

/// Encode at the smallest legal width, without allocation.
pub fn encode_varint(value: u64, output: &mut [u8; 8]) -> Option<&[u8]> {
    let width = match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 4,
        1073741824..=MAX_VARINT => 8,
        _ => return None,
    };
    let bytes = value.to_be_bytes();
    output[..width].copy_from_slice(&bytes[8 - width..]);
    output[0] |= match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    Some(&output[..width])
}

/// RFC 9000 Appendix A.3. Reject invalid input rather than shifting or
/// wrapping an out-of-domain packet number.
pub fn decode_number(truncated: u64, len: usize, largest: Option<u64>) -> Option<u64> {
    if !(1..=4).contains(&len) || largest.is_some_and(|n| n > MAX_VARINT) {
        return None;
    }
    let window = 1u64 << (len * 8);
    if truncated >= window {
        return None;
    }
    let expected = largest.map_or(0, |n| n + 1);
    let half = window / 2;
    let mut candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < (1u64 << 62) - window {
        candidate += window;
    } else if candidate > expected + half && candidate >= window {
        candidate -= window;
    }
    (candidate <= MAX_VARINT).then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrips_boundaries_and_rejects_overflow() {
        let mut bytes = [0; 8];
        for (value, width) in [
            (0, 1), (63, 1), (64, 2), (16383, 2), (16384, 4),
            (1073741823, 4), (1073741824, 8), (MAX_VARINT, 8),
        ] {
            let encoded = encode_varint(value, &mut bytes).unwrap();
            assert_eq!(encoded.len(), width);
            let mut pos = 0;
            assert_eq!(varint(encoded, &mut pos), Some(value));
            assert_eq!(pos, width);
            for cut in 0..width {
                let mut pos = 0;
                assert_eq!(varint(&encoded[..cut], &mut pos), None);
                assert_eq!(pos, 0);
            }
        }
        assert!(encode_varint(MAX_VARINT + 1, &mut bytes).is_none());
        let mut pos = 1;
        assert_eq!(varint(&[0, 0x40, 1], &mut pos), Some(1));
        assert_eq!(pos, 3);
        let mut invalid = usize::MAX;
        assert_eq!(varint(&[], &mut invalid), None);
    }

    #[test]
    fn version_and_packet_number_bounds() {
        for v in [Version::V1, Version::V2] {
            assert_eq!(Version::from_wire(v.wire()), Some(v));
        }
        assert_eq!(Version::from_wire(0), None);
        assert_eq!(decode_number(0x9b32, 2, Some(0xa82f30ea)), Some(0xa82f9b32));
        assert_eq!(decode_number(0, 1, Some(255)), Some(256));
        assert_eq!(decode_number(255, 1, Some(256)), Some(255));
        assert_eq!(decode_number(0, 1, None), Some(0));
        assert_eq!(decode_number(256, 1, None), None);
        assert_eq!(decode_number(0, 0, None), None);
        assert_eq!(decode_number(0, 5, None), None);
        assert_eq!(decode_number(0, 1, Some(u64::MAX)), None);
        assert_eq!(decode_number(255, 1, Some(MAX_VARINT)), Some(MAX_VARINT));
    }
}
