//! Strict, versioned Theia v1 connection invitation. Never log secret-bearing URIs.
use crate::config::{
    ClientDocument, ClientSettings, Config, LocalProxy, Management, Profile, SystemProxy,
    Transport, Ui,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, net::SocketAddr};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "theia://v1/";
const MAX_DATA: usize = 3072;
const MAX_URI: usize = 4096;

/// This type may contain a live 32-byte bearer secret. No derived Debug.
pub struct Invitation {
    pub id: String,
    pub endpoint: String,
    pub server_name: String,
    pub transport: Transport,
    token: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteError {
    Invalid,
    Unavailable,
    IncompatiblePorts,
}
impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unavailable Theia invitation")
    }
}
impl std::error::Error for InviteError {}
impl fmt::Debug for Invitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invitation")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("transport", &self.transport)
            .field("contains_token", &self.has_token())
            .finish()
    }
}

// Wipe the raw bearer when an issued invitation is discarded.
impl Drop for Invitation {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_mut() {
            token.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    id: String,
    endpoint: String,
    server_name: String,
    tls_profile: String,
    transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_mut() {
            token.zeroize();
        }
    }
}

impl Invitation {
    /// Safe, token-free share for manual credential provisioning.
    pub fn public_from_profile(profile: &Profile) -> Result<Self, InviteError> {
        // v1 cannot represent a non-default TLS profile. Refuse export
        // rather than silently converting the caller's explicit selection.
        if profile.tls_profile != "default" {
            return Err(InviteError::Invalid);
        }
        let invite = Self {
            id: profile.id.clone(),
            endpoint: profile.server.clone(),
            server_name: profile.server_name.clone(),
            transport: profile.transport,
            token: None,
        };
        invite.check()?;
        Ok(invite)
    }

    /// The server config has local bind IPs, not publicly routable addresses.
    /// Export its configured DNS name only if the H2/H3 port numbers agree.
    pub fn public_from_server(config: &Config, inbound_id: &str) -> Result<Self, InviteError> {
        let Config::Server(doc) = config else {
            return Err(InviteError::Unavailable);
        };
        config.validate().map_err(|_| InviteError::Unavailable)?;
        if !doc.server.enabled {
            return Err(InviteError::Unavailable);
        }
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|item| item.id == inbound_id)
            .ok_or(InviteError::Unavailable)?;
        if !inbound.security_mode.is_plain() {
            return Err(InviteError::Unavailable);
        }
        let h2 = inbound
            .h2_listen
            .parse::<SocketAddr>()
            .map_err(|_| InviteError::Unavailable)?;
        let h3 = inbound
            .quic_listen
            .parse::<SocketAddr>()
            .map_err(|_| InviteError::Unavailable)?;
        if h2.port() != h3.port() {
            return Err(InviteError::IncompatiblePorts);
        }
        let invite = Self {
            id: inbound.id.clone(),
            endpoint: format!("{}:{}", inbound.server_name, h2.port()),
            server_name: inbound.server_name.clone(),
            transport: Transport::Auto,
            token: None,
        };
        invite.check()?;
        Ok(invite)
    }

    /// Caller must supply the freshly generated 256-bit token at issuance
    /// or rotation. The stored SHA-256 digest cannot recover an old token.
    pub fn issued_from_server(
        config: &Config,
        inbound_id: &str,
        user_id: &str,
        token: &[u8; 32],
    ) -> Result<Self, InviteError> {
        let mut invite = Self::public_from_server(config, inbound_id)?;
        let Config::Server(doc) = config else {
            return Err(InviteError::Unavailable);
        };
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|item| item.id == inbound_id)
            .ok_or(InviteError::Unavailable)?;
        let user = doc
            .server
            .users
            .iter()
            .find(|item| item.id == user_id && !item.disabled)
            .ok_or(InviteError::Unavailable)?;
        if !inbound.allowed_user_ids.iter().any(|id| id == user_id) {
            return Err(InviteError::Unavailable);
        }
        let digest = format!("{:x}", Sha256::digest(token));
        if !bool::from(user.token_sha256.as_bytes().ct_eq(digest.as_bytes())) {
            return Err(InviteError::Unavailable);
        }
        invite.token = Some(*token);
        Ok(invite)
    }

    /// Returned URI is confidential whenever it contains a token.
    pub fn encode(&self) -> Result<String, InviteError> {
        self.check()?;
        let wire = Wire {
            version: 1,
            id: self.id.clone(),
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            tls_profile: "default".into(),
            transport: self.transport,
            token: self.token.as_ref().map(|v| URL_SAFE_NO_PAD.encode(v)),
        };
        let text = Zeroizing::new(toml::to_string(&wire).map_err(|_| InviteError::Invalid)?);
        if text.len() > MAX_DATA {
            return Err(InviteError::Invalid);
        }
        let mut uri = Zeroizing::new(PREFIX.to_owned());
        URL_SAFE_NO_PAD.encode_string(text.as_bytes(), &mut uri);
        if uri.len() > MAX_URI {
            return Err(InviteError::Invalid);
        }
        Ok(std::mem::take(&mut *uri))
    }

    /// Reject non-canonical base64url, unknown fields/versions, invalid
    /// credential lengths, and invalid core profile fields.
    pub fn decode(uri: &str) -> Result<Self, InviteError> {
        if uri.len() > MAX_URI {
            return Err(InviteError::Invalid);
        }
        let encoded = uri.strip_prefix(PREFIX).ok_or(InviteError::Invalid)?;
        if encoded.is_empty()
            || encoded
                .bytes()
                .any(|c| !c.is_ascii_alphanumeric() && c != b'-' && c != b'_')
        {
            return Err(InviteError::Invalid);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| InviteError::Invalid)?,
        );
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
        if bytes.len() > MAX_DATA || canonical.as_str() != encoded {
            return Err(InviteError::Invalid);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| InviteError::Invalid)?;
        let mut wire: Wire = toml::from_str(text).map_err(|_| InviteError::Invalid)?;
        if wire.version != 1 || wire.tls_profile != "default" {
            return Err(InviteError::Invalid);
        }
        let token = match wire.token.as_ref() {
            Some(raw) => {
                let value = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(raw)
                        .map_err(|_| InviteError::Invalid)?,
                );
                let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(value.as_slice()));
                if value.len() != 32 || canonical.as_str() != raw.as_str() {
                    return Err(InviteError::Invalid);
                }
                Some(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| InviteError::Invalid)?,
                )
            }
            None => None,
        };
        let invite = Self {
            id: std::mem::take(&mut wire.id),
            endpoint: std::mem::take(&mut wire.endpoint),
            server_name: std::mem::take(&mut wire.server_name),
            transport: wire.transport,
            token,
        };
        invite.check()?;
        Ok(invite)
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Explicit secret access for future secure file/env import transactions.
    pub fn token_bytes(&self) -> Option<[u8; 32]> {
        self.token
    }

    /// Convert only non-secret profile fields. The caller must provision
    /// the token as a secure env/file reference; never embed it in TOML.
    pub fn to_profile(
        &self,
        secret_ref: &str,
        tls_ca: Option<String>,
    ) -> Result<Profile, InviteError> {
        self.check()?;
        validate_profile(Profile {
            id: self.id.clone(),
            server: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            auth_token: secret_ref.into(),
            tls_profile: "default".into(),
            tls_ca,
            transport: self.transport,
            quic_connect_timeout_ms: 1600,
            quic_negative_cache_ttl_s: 900,
        })
    }

    fn check(&self) -> Result<(), InviteError> {
        self.to_profile_unchecked("env:THEIA_INVITE_TOKEN".into(), None)
            .map(|_| ())
    }

    fn to_profile_unchecked(
        &self,
        auth_token: String,
        tls_ca: Option<String>,
    ) -> Result<Profile, InviteError> {
        validate_profile(Profile {
            id: self.id.clone(),
            server: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            auth_token,
            tls_profile: "default".into(),
            tls_ca,
            transport: self.transport,
            quic_connect_timeout_ms: 1600,
            quic_negative_cache_ttl_s: 900,
        })
    }
}

/// Validate via the existing full TOML v1 document, not a weaker URL parser.
fn validate_profile(profile: Profile) -> Result<Profile, InviteError> {
    let config = Config::Client(ClientDocument {
        schema_version: 1,
        client: ClientSettings {
            active_profile: profile.id.clone(),
            profiles: vec![profile.clone()],
            proxy: LocalProxy {
                http_listen: "127.0.0.1:7890".into(),
                socks5_listen: "127.0.0.1:7891".into(),
                system_proxy: SystemProxy::Off,
            },
        },
        management: Management {
            ipc: "auto".into(),
            log_level: "info".into(),
        },
        ui: Ui {
            language: "ru".into(),
        },
    });
    config.validate().map_err(|_| InviteError::Invalid)?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_with_token(token: &[u8; 32]) -> Config {
        let fixture = include_str!("../../../examples/server.toml");
        let src = fixture.replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest(token)),
        );
        crate::config::parse(&src).unwrap()
    }

    #[test]
    fn server_issue_roundtrip_to_typed_client_profile_never_stores_literal() {
        let token = [0x42; 32];
        let server = server_with_token(&token);
        let issued = Invitation::issued_from_server(&server, "public", "device-a", &token).unwrap();
        let encoded = issued.encode().unwrap();
        assert!(encoded.starts_with(PREFIX));
        let received = Invitation::decode(&encoded).unwrap();
        assert_eq!(received.token_bytes(), Some(token));
        assert!(!format!("{received:?}").contains(&URL_SAFE_NO_PAD.encode(token)));
        let profile = received
            .to_profile("file:/trusted/theia-token", None)
            .unwrap();
        assert_eq!(profile.server, "edge.example.org:443");
        assert_eq!(profile.auth_token, "file:/trusted/theia-token");
        assert_eq!(profile.transport, Transport::Auto);
    }

    #[test]
    fn public_share_has_no_secret_and_requires_auth_reference() {
        let invite =
            Invitation::public_from_server(&server_with_token(&[0x42; 32]), "public").unwrap();
        assert!(!Invitation::decode(&invite.encode().unwrap())
            .unwrap()
            .has_token());
        assert!(invite.to_profile("literal-token", None).is_err());
        assert!(invite.to_profile("env:THEIA_AUTH_TOKEN", None).is_ok());
        assert!(invite
            .to_profile("env:THEIA_AUTH_TOKEN", Some("file:relative.pem".into()))
            .is_err());
    }

    #[test]
    fn public_export_preserves_default_transport_and_rejects_profile_downgrade() {
        let Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let mut profile = doc.client.profiles[0].clone();
        for transport in [Transport::Auto, Transport::H2, Transport::H3] {
            profile.transport = transport;
            let encoded = Invitation::public_from_profile(&profile)
                .unwrap()
                .encode()
                .unwrap();
            let decoded = Invitation::decode(&encoded).unwrap();
            assert!(!decoded.has_token());
            let restored = decoded.to_profile("env:TOKEN", None).unwrap();
            assert_eq!(restored.tls_profile, "default");
            assert_eq!(restored.transport, transport);
        }
        for name in ["browser-h2-btls-v1", "smart-reality-v1", "unknown", ""] {
            profile.tls_profile = name.into();
            for transport in [Transport::Auto, Transport::H2, Transport::H3] {
                profile.transport = transport;
                assert_eq!(
                    Invitation::public_from_profile(&profile).unwrap_err(),
                    InviteError::Invalid
                );
            }
        }
    }

    #[test]
    fn must_match_granted_active_user_and_real_token_digest() {
        let token = [0x42; 32];
        let server = server_with_token(&token);
        assert!(Invitation::issued_from_server(&server, "public", "device-a", &[0; 32]).is_err());
        assert!(Invitation::issued_from_server(&server, "public", "missing", &token).is_err());
        let Config::Server(mut doc) = server else {
            panic!("server");
        };
        doc.server.users[0].disabled = true;
        assert!(
            Invitation::issued_from_server(&Config::Server(doc), "public", "device-a", &token)
                .is_err()
        );
    }

    #[test]
    fn valid_but_ungranted_user_cannot_receive_selected_inbound_invite() {
        let mut server = server_with_token(&[0x42; 32]);
        let other = [0x31; 32];
        let Config::Server(doc) = &mut server else {
            panic!("server");
        };
        doc.server.users.push(crate::config::User {
            id: "ungranted".into(),
            token_sha256: format!("{:x}", Sha256::digest(other)),
            disabled: false,
        });
        assert_eq!(server.validate(), Ok(()));
        assert_eq!(
            Invitation::issued_from_server(&server, "public", "ungranted", &other).unwrap_err(),
            InviteError::Unavailable
        );
    }

    #[test]
    fn incompatible_h2_h3_ports_are_rejected_instead_of_broken_auto_profile() {
        let mut server = server_with_token(&[0x42; 32]);
        assert!(Invitation::public_from_server(&server, "missing").is_err());
        let Config::Server(doc) = &mut server else {
            panic!("server");
        };
        doc.server.inbounds[0].quic_listen = "0.0.0.0:444".into();
        assert_eq!(
            Invitation::public_from_server(&server, "public").unwrap_err(),
            InviteError::IncompatiblePorts
        );
    }

    #[test]
    fn malformed_links_unknown_fields_versions_and_token_bytes_fail_closed() {
        let inv = Invitation::issued_from_server(
            &server_with_token(&[0x42; 32]),
            "public",
            "device-a",
            &[0x42; 32],
        )
        .unwrap();
        let uri = inv.encode().unwrap();
        for bad in [
            "theia://v2/aA",
            "theia://v1/",
            "theia://v1/Zg==",
            "https://example.test",
            "theia://v1/??",
        ] {
            assert!(Invitation::decode(bad).is_err());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(uri.strip_prefix(PREFIX).unwrap())
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for altered in [
            text.replace("version = 1", "version = 2"),
            text.replace("tls_profile = \"default\"", "tls_profile = \"chrome133\""),
            text.replace(
                "server_name = \"edge.example.org\"",
                "server_name = \"127.0.0.1\"",
            ),
            format!("{text}unknown = \"extra\"\n"),
            text.replace(
                &format!("token = \"{}\"", URL_SAFE_NO_PAD.encode([0x42; 32])),
                "token = \"secret\"",
            ),
        ] {
            let link = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(altered.as_bytes()));
            assert!(Invitation::decode(&link).is_err());
        }
        assert!(Invitation::decode(&format!("{PREFIX}{}", "A".repeat(MAX_URI))).is_err());
    }
}
