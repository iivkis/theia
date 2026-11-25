//! Explicit additional TLS certificate identity. This is NOT a modified
//! REALITY handshake or an alternative to normal PKI, hostname or ALPN.
use crate::client::ClientError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const PINNED_PATH: &str = "/v1/pinned-session";
const PROFILE_PREFIX: &str = "pinned-cert-v1:";
const SPLIT_PROFILE_PREFIX: &str = "pinned-cert-stream-up-v1:";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    #[default]
    Plain,
    PinnedCertV1,
    PinnedCertStreamUpV1,
    SmartReality,
}

impl SecurityMode {
    pub fn is_plain(&self) -> bool {
        *self == Self::Plain
    }

    pub(crate) fn is_stream_up(self) -> bool {
        self == Self::PinnedCertStreamUpV1
    }

    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Plain => "/v1/session",
            Self::PinnedCertV1 => PINNED_PATH,
            Self::PinnedCertStreamUpV1 => crate::split_http::UPLOAD_PATH,
            // No generic HTTP route is valid for this security mode.
            Self::SmartReality => "",
        }
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
    fn explicit_profile_config_and_replacement_v1_preserve_pin() {
        use crate::{
            config::{self, Config, Transport},
            invite::Invitation,
        };

        let pin = CertificatePin::from_der(b"fixture");
        let Config::Client(mut client) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture");
        };
        for transport in [Transport::H2, Transport::H3, Transport::Auto] {
            client.client.profiles[0].transport = transport;
            client.client.profiles[0].tls_profile = pin.profile();
            let document = Config::Client(client.clone());
            document.validate().unwrap();
            assert_eq!(
                config::parse(&document.to_toml().unwrap()).unwrap(),
                document
            );
            let invitation = Invitation::public_from_profile(&client.client.profiles[0]).unwrap();
            assert_eq!(
                invitation.tls_profile(),
                client.client.profiles[0].tls_profile
            );
        }
        client.client.profiles[0].tls_profile =
            pin.profile().replace("pinned-cert-v1:", "pinned-cert-v2:");
        assert!(Config::Client(client).validate().is_err());

        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"42".repeat(32));
        let Config::Server(mut server) = config::parse(&source).unwrap() else {
            panic!("server fixture");
        };
        assert_eq!(server.server.inbounds[0].security_mode, SecurityMode::Plain);
        server.server.inbounds[0].security_mode = SecurityMode::PinnedCertV1;
        let document = Config::Server(server);
        let encoded = document.to_toml().unwrap();
        assert!(encoded.contains("pinned-cert-v1"));
        assert_eq!(config::parse(&encoded).unwrap(), document);
        assert!(Invitation::public_from_server(&document, "public").is_err());
        assert!(config::parse(&encoded.replace("pinned-cert-v1", "pinned-cert-v2")).is_err());
    }

    #[test]
    fn stream_up_profile_is_explicit_in_replacement_invitation_v1() {
        use crate::{
            config::{self, Config, Transport},
            invite::Invitation,
        };
        let pin = CertificatePin::from_der(b"fixture");
        let profile = pin.stream_up_profile();
        assert!(CertificatePin::is_stream_up_profile(&profile));
        assert!(!CertificatePin::is_stream_up_profile(&pin.profile()));
        assert!(CertificatePin::parse_profile(&profile).is_some_and(|value| value == pin));
        let Config::Client(mut client) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture");
        };
        for transport in [Transport::H2, Transport::H3, Transport::Auto] {
            client.client.profiles[0].transport = transport;
            client.client.profiles[0].tls_profile.clone_from(&profile);
            let config = Config::Client(client.clone());
            config.validate().unwrap();
            assert_eq!(config::parse(&config.to_toml().unwrap()).unwrap(), config);
            let invitation = Invitation::public_from_profile(&client.client.profiles[0]).unwrap();
            assert_eq!(
                invitation.tls_profile(),
                client.client.profiles[0].tls_profile
            );
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
