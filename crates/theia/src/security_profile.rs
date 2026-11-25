//! Explicit additional TLS certificate identity. This is NOT a modified
//! REALITY handshake or an alternative to normal PKI, hostname or ALPN.
use crate::client::ClientError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PROFILE_PREFIX: &str = "pinned-cert-v1:";
const SPLIT_PROFILE_PREFIX: &str = "pinned-cert-stream-up-v1:";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    #[default]
    #[serde(rename = "own-tls")]
    Plain,
    // Laboratory-only typed fixtures. Neither mode is a product setting.
    #[serde(skip)]
    PinnedCertV1,
    #[serde(skip)]
    PinnedCertStreamUpV1,
    SmartReality,
}

impl SecurityMode {
    /// Only these two names are part of the product configuration contract.
    pub fn from_product_name(name: &str) -> Option<Self> {
        match name {
            "own-tls" => Some(Self::Plain),
            "smart-reality" => Some(Self::SmartReality),
            _ => None,
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Plain => "own-tls",
            Self::SmartReality => "smart-reality",
            Self::PinnedCertV1 => "pinned-cert-v1 (laboratory)",
            Self::PinnedCertStreamUpV1 => "pinned-cert-stream-up-v1 (laboratory)",
        }
    }

    pub fn is_plain(&self) -> bool {
        *self == Self::Plain
    }

    pub(crate) fn is_stream_up(self) -> bool {
        self == Self::PinnedCertStreamUpV1
    }
}

/// Pin the entire DER leaf, not just the SPKI. Certificate renewal requires
/// explicit replacement of the pin. No implicit trust on first use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CertificatePin([u8; 32]);

impl CertificatePin {
    pub fn from_der(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    pub fn parse_profile(profile: &str) -> Option<Self> {
        let raw = profile
            .strip_prefix(PROFILE_PREFIX)
            .or_else(|| profile.strip_prefix(SPLIT_PROFILE_PREFIX))?
            .as_bytes();
        if raw.len() != 64
            || !raw
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return None;
        }
        let mut pin = [0; 32];
        for (byte, pair) in pin.iter_mut().zip(raw.as_chunks::<2>().0) {
            let value = |n: u8| {
                if n.is_ascii_digit() {
                    n - b'0'
                } else {
                    n - b'a' + 10
                }
            };
            *byte = value(pair[0]) * 16 + value(pair[1]);
        }
        Some(Self(pin))
    }

    pub fn is_stream_up_profile(profile: &str) -> bool {
        profile.starts_with(SPLIT_PROFILE_PREFIX) && Self::parse_profile(profile).is_some()
    }

    pub fn stream_up_profile(self) -> String {
        self.profile()
            .replacen(PROFILE_PREFIX, SPLIT_PROFILE_PREFIX, 1)
    }

    pub fn profile(self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        format!("{PROFILE_PREFIX}{hex}")
    }

    pub(crate) fn verify(self, der: &[u8]) -> Result<(), ClientError> {
        if bool::from(self.0.ct_eq(&Self::from_der(der).0)) {
            Ok(())
        } else {
            Err(ClientError::Tls)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laboratory_security_modes_are_not_serializable_product_modes() {
        for mode in [
            SecurityMode::PinnedCertV1,
            SecurityMode::PinnedCertStreamUpV1,
        ] {
            let source = include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"42".repeat(32));
            let crate::config::Config::Server(mut doc) = crate::config::parse(&source).unwrap()
            else {
                panic!()
            };
            doc.server.inbounds[0].security_mode = mode;
            assert!(crate::config::Config::Server(doc).validate().is_err());
        }
    }

    #[test]
    fn canonical_pin_and_exact_der() {
        let pin = CertificatePin::from_der(b"cert");
        assert!(CertificatePin::parse_profile(&pin.profile()).is_some_and(|p| p == pin));
        assert!(pin.verify(b"cert").is_ok());
        assert_eq!(pin.verify(b"other"), Err(ClientError::Tls));
        for value in [
            "default",
            "pinned-cert-v2:",
            "pinned-cert-v1:AB",
            "pinned-cert-v1:00",
        ] {
            assert!(CertificatePin::parse_profile(value).is_none());
        }
    }
}
