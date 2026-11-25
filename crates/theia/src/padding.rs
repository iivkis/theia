//! Bounded policy-driven padding shared by the two HTTP carriers.
//! No timers, idle refresh, unnegotiated frames or padding on rejected requests.
use crate::{
    client::ClientError,
    descriptor::Padding,
    protocol::{self, Frame},
};
use http::{HeaderMap, HeaderValue, Request};
use ring::rand::{SecureRandom, SystemRandom};

pub(crate) const MAX_HEADER: u16 = 4096;
const HEADER: &str = "theia-padding";

// Fixed, shared Own-TLS wire-v1 defaults. No remote policy input or new
// trust mechanism. These are conservative engineering candidates, not
// measured optimal settings; REALITY continues to use its signed policy.
pub(crate) const OWN_TLS_PADDING: Padding = Padding {
    header_min: 16,
    header_max: 64,
    frame_min: 16,
    frame_max: 128,
};
pub(crate) const OWN_TLS_ROTATION: crate::descriptor::Rotation = crate::descriptor::Rotation {
    lifetime_min_s: 15,
    lifetime_max_s: 20,
    volume_min_bytes: 32 * 1024 * 1024,
    volume_max_bytes: 64 * 1024 * 1024,
};

impl Padding {
    pub(crate) fn valid(&self) -> bool {
        self.header_min <= self.header_max
            && self.header_max <= MAX_HEADER
            && self.frame_min <= self.frame_max
            && self.frame_max <= protocol::MAX_PAYLOAD as u32
    }

    pub(crate) fn add_header(&self, headers: &mut HeaderMap) -> Result<(), ClientError> {
        if !self.valid() || headers.contains_key(HEADER) {
            return Err(ClientError::Configuration);
        }
        if self.header_max == 0 {
            return Ok(());
        }
        let mut bytes = random_bytes(u32::from(self.header_min), u32::from(self.header_max))?;
        // All 64 symbols have equal probability; the value has exactly the
        // selected length, without control characters or base64 expansion.
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for byte in &mut bytes {
            *byte = ALPHABET[usize::from(*byte & 63)];
        }
        let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| ClientError::Configuration)?;
        value.set_sensitive(true);
        headers.insert(HEADER, value);
        Ok(())
    }

    pub(crate) fn request<T>(&self, mut request: Request<T>) -> Result<Request<T>, ClientError> {
        self.add_header(request.headers_mut())?;
        Ok(request)
    }

    pub(crate) fn frame(&self, accepted: u32) -> Result<Option<Frame>, ClientError> {
        if !self.valid() {
            return Err(ClientError::Configuration);
        }
        if accepted & protocol::CAP_PADDING == 0 || self.frame_max == 0 {
            return Ok(None);
        }
        Ok(Some(Frame::Padding(random_bytes(
            self.frame_min,
            self.frame_max,
        )?)))
    }
}

fn random_bytes(min: u32, max: u32) -> Result<Vec<u8>, ClientError> {
    let rng = SystemRandom::new();
    let width = max
        .checked_sub(min)
        .and_then(|n| n.checked_add(1))
        .ok_or(ClientError::Configuration)?;
    let threshold = width.wrapping_neg() % width;
    for _ in 0..32 {
        let mut word = [0; 4];
        rng.fill(&mut word)
            .map_err(|_| ClientError::Configuration)?;
        let value = u32::from_le_bytes(word);
        if value >= threshold {
            let mut bytes = vec![0; (min + value % width) as usize];
            if !bytes.is_empty() {
                rng.fill(&mut bytes)
                    .map_err(|_| ClientError::Configuration)?;
            }
            return Ok(bytes);
        }
    }
    Err(ClientError::Configuration)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_tls_v1_policy_is_bounded_and_requires_capability() {
        assert!(OWN_TLS_PADDING.valid());
        let mut headers = HeaderMap::new();
        OWN_TLS_PADDING.add_header(&mut headers).unwrap();
        assert!((16..=64).contains(&headers[HEADER].as_bytes().len()));
        assert!(OWN_TLS_PADDING.frame(0).unwrap().is_none());
        assert!(matches!(OWN_TLS_PADDING.frame(protocol::CAP_PADDING).unwrap(),
            Some(Frame::Padding(bytes)) if (16..=128).contains(&bytes.len())));
    }

    #[test]
    fn bounded_header_and_negotiated_frame() {
        let policy = Padding {
            header_min: 17,
            header_max: 23,
            frame_min: 5,
            frame_max: 8,
        };
        for _ in 0..64 {
            let mut headers = HeaderMap::new();
            policy.add_header(&mut headers).unwrap();
            let value = &headers[HEADER];
            assert!((17..=23).contains(&value.as_bytes().len()));
            assert!(value.is_sensitive());
            assert!(policy.add_header(&mut headers).is_err());
            assert!(policy.frame(0).unwrap().is_none());
            assert!(
                matches!(policy.frame(protocol::CAP_PADDING).unwrap(), Some(Frame::Padding(bytes)) if (5..=8).contains(&bytes.len()))
            );
        }
        let mut headers = HeaderMap::new();
        Padding::default().add_header(&mut headers).unwrap();
        assert!(headers.is_empty());
        assert!(Padding::default()
            .frame(protocol::CAP_PADDING)
            .unwrap()
            .is_none());
    }
}
