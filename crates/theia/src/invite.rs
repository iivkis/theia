//! Strict replacement Theia v1 invitation for SmartTheia XHTTP. Never log bearer URIs.
use crate::config::{
    ClientDocument, ClientSettings, Config, LocalProxy, Management, Profile, SystemProxy,
    Transport, Ui, XhttpMode,
};
use crate::security_profile::SecurityMode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, net::SocketAddr};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const PREFIX: &str = "theia://v1/";
/// The full ASCII access key, including its scheme/version prefix.
pub const MAX_URI: usize = 2048;
const MAX_DATA: usize = (MAX_URI - PREFIX.len()) * 3 / 4;

/// This type may contain a live 32-byte bearer secret. No derived Debug.
pub struct Invitation {
    pub id: String,
    pub path_prefix: String,
    pub endpoint: String,
    pub server_name: String,
    pub transport: Transport,
    xhttp_mode: XhttpMode,
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
            .field("security_mode", &self.security_mode())
            .field("xhttp_mode", &self.xhttp_mode)
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireSecurity {
    OwnTls,
    SmartReality,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Wire {
    pub(crate) version: u32,
    pub(crate) path_prefix: String,
    pub(crate) id: String,
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) carrier: String,
    pub(crate) security_mode: WireSecurity,
    pub(crate) xhttp_mode: XhttpMode,
    pub(crate) transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) minimum_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) descriptor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admission: Option<String>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_mut() {
            token.zeroize();
        }
        if let Some(admission) = self.admission.as_mut() {
            admission.zeroize();
        }
    }
}

fn check_wire(wire: &Wire) -> Result<(), InviteError> {
    if wire.version != 1
        || wire.carrier != "smarttheia-xhttp"
        || !crate::config::valid_id(&wire.id)
        || !crate::config::valid_remote(&wire.endpoint)
        || !crate::split_http::valid_prefix(&wire.path_prefix)
    {
        return Err(InviteError::Invalid);
    }
    let valid = match wire.security_mode {
        WireSecurity::OwnTls => {
            wire.public_key.is_none()
                && wire.minimum_revision.is_none()
                && wire.descriptor.is_none()
                && wire.admission.is_none()
        }
        WireSecurity::SmartReality => {
            wire.public_key.is_some()
                && wire.minimum_revision.is_some_and(|revision| revision > 0)
                && wire.descriptor.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= crate::descriptor::MAX_DOCUMENT
                })
                && wire.token.is_some() == wire.admission.is_some()
        }
    };
    if !valid {
        return Err(InviteError::Invalid);
    }
    Ok(())
}

// The compact v1 format has one canonical representation. It uses fixed
// width big-endian integers, length-prefixed UTF-8 strings and raw keys.
// REALITY scope, route and reference data are encoded once in the signed
// descriptor. Reconstructing its original envelope preserves signature,
// revision and equivocation checks; no alternate signature format exists.
fn put_text(out: &mut Vec<u8>, value: &str) -> Result<(), InviteError> {
    let len = u16::try_from(value.len()).map_err(|_| InviteError::Invalid)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], InviteError> {
        let (value, rest) = self.0.split_at_checked(N).ok_or(InviteError::Invalid)?;
        self.0 = rest;
        value.try_into().map_err(|_| InviteError::Invalid)
    }

    fn byte(&mut self) -> Result<u8, InviteError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, InviteError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, InviteError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, InviteError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<String, InviteError> {
        let len = usize::from(self.u16()?);
        let (value, rest) = self.0.split_at_checked(len).ok_or(InviteError::Invalid)?;
        self.0 = rest;
        String::from_utf8(value.to_vec()).map_err(|_| InviteError::Invalid)
    }

    fn flag(&mut self) -> Result<bool, InviteError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(InviteError::Invalid),
        }
    }
}

fn raw_key<const N: usize>(value: &str) -> Result<Zeroizing<[u8; N]>, InviteError> {
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).map_err(|_| InviteError::Invalid)?);
    let result: [u8; N] = bytes.as_slice().try_into().map_err(|_| InviteError::Invalid)?;
    if Zeroizing::new(URL_SAFE_NO_PAD.encode(result)).as_str() != value {
        return Err(InviteError::Invalid);
    }
    Ok(Zeroizing::new(result))
}

fn put_descriptor(
    out: &mut Vec<u8>,
    d: &crate::descriptor::Descriptor,
    signature: [u8; 64],
) -> Result<(), InviteError> {
    put_text(out, &d.scope.inbound)?;
    put_text(out, &d.scope.endpoint)?;
    put_text(out, &d.path_prefix)?;
    out.extend_from_slice(&d.revision.to_be_bytes());
    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.push(d.active_reference);
    out.push(u8::from(d.h3) | (u8::from(d.stream_one) << 1) | (u8::from(d.stream_up) << 2)
        | (u8::from(d.next_identity.is_some()) << 3));
    if let Some(next) = &d.next_identity {
        out.extend_from_slice(&raw_key::<32>(next)?[..]);
    }
    out.extend_from_slice(&d.padding.header_min.to_be_bytes());
    out.extend_from_slice(&d.padding.header_max.to_be_bytes());
    out.extend_from_slice(&d.padding.frame_min.to_be_bytes());
    out.extend_from_slice(&d.padding.frame_max.to_be_bytes());
    out.extend_from_slice(&d.rotation.lifetime_min_s.to_be_bytes());
    out.extend_from_slice(&d.rotation.lifetime_max_s.to_be_bytes());
    out.extend_from_slice(&d.rotation.volume_min_bytes.to_be_bytes());
    out.extend_from_slice(&d.rotation.volume_max_bytes.to_be_bytes());
    out.push(u8::try_from(d.references.len()).map_err(|_| InviteError::Invalid)?);
    for reference in &d.references {
        put_text(out, &reference.server_name)?;
        out.extend_from_slice(&reference.port.to_be_bytes());
        out.push(u8::from(reference.h3));
    }
    out.extend_from_slice(&signature);
    Ok(())
}

fn get_descriptor(r: &mut Reader<'_>) -> Result<(crate::descriptor::Descriptor, String), InviteError> {
    use crate::descriptor::{Descriptor, Padding, Reference, Rotation, Scope, SecurityMode};
    let scope = Scope { inbound: r.text()?, endpoint: r.text()? };
    let path_prefix = r.text()?;
    let revision = r.u64()?;
    let not_before = r.u64()?;
    let not_after = r.u64()?;
    let active_reference = r.byte()?;
    let flags = r.byte()?;
    if flags & !0x0f != 0 {
        return Err(InviteError::Invalid);
    }
    let next_identity = if flags & 8 != 0 {
        Some(URL_SAFE_NO_PAD.encode(r.array::<32>()?))
    } else {
        None
    };
    let padding = Padding {
        header_min: r.u16()?, header_max: r.u16()?,
        frame_min: r.u32()?, frame_max: r.u32()?,
    };
    let rotation = Rotation {
        lifetime_min_s: r.u32()?, lifetime_max_s: r.u32()?,
        volume_min_bytes: r.u64()?, volume_max_bytes: r.u64()?,
    };
    let count = r.byte()?;
    if !(1..=3).contains(&count) {
        return Err(InviteError::Invalid);
    }
    let mut references = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        references.push(Reference { server_name: r.text()?, port: r.u16()?, h3: r.flag()? });
    }
    let d = Descriptor {
        schema_version: 1, wire_version: 1, security_mode: SecurityMode::SmartReality,
        revision, not_before, not_after, active_reference,
        h3: flags & 1 != 0, stream_one: flags & 2 != 0, stream_up: flags & 4 != 0,
        path_prefix, next_identity, scope, padding, rotation, references,
    };
    let document = crate::descriptor::invitation_document(&d, r.array()?)
        .map_err(|_| InviteError::Invalid)?;
    Ok((d, document))
}

pub(crate) fn encode_wire(wire: &Wire) -> Result<Zeroizing<String>, InviteError> {
    check_wire(wire)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.push(1);
    bytes.push(match wire.security_mode { WireSecurity::OwnTls => 0, WireSecurity::SmartReality => 1 });
    bytes.push(match wire.transport { Transport::Auto => 0, Transport::H2 => 1, Transport::H3 => 2 });
    bytes.push(match wire.xhttp_mode { XhttpMode::Auto => 0, XhttpMode::StreamOne => 1, XhttpMode::StreamUp => 2 });
    bytes.push(u8::from(wire.token.is_some()) | (u8::from(wire.admission.is_some()) << 1));
    if let Some(token) = &wire.token {
        bytes.extend_from_slice(&raw_key::<32>(token)?[..]);
    }
    if let Some(admission) = &wire.admission {
        bytes.extend_from_slice(&raw_key::<32>(admission)?[..]);
    }
    match wire.security_mode {
        WireSecurity::OwnTls => {
            put_text(&mut bytes, &wire.id)?;
            put_text(&mut bytes, &wire.endpoint)?;
            put_text(&mut bytes, &wire.server_name)?;
            put_text(&mut bytes, &wire.path_prefix)?;
        }
        WireSecurity::SmartReality => {
            let public = raw_key::<32>(wire.public_key.as_deref().ok_or(InviteError::Invalid)?)?;
            let (d, signature) = crate::descriptor::invitation_parts(
                wire.descriptor.as_deref().ok_or(InviteError::Invalid)?
            ).map_err(|_| InviteError::Invalid)?;
            if d.scope.inbound != wire.id || d.scope.endpoint != wire.endpoint
                || d.path_prefix != wire.path_prefix || Some(d.revision) != wire.minimum_revision
                || d.references[usize::from(d.active_reference)].server_name != wire.server_name
            {
                return Err(InviteError::Invalid);
            }
            bytes.extend_from_slice(&public[..]);
            put_descriptor(&mut bytes, &d, signature)?;
        }
    }
    if bytes.len() > MAX_DATA {
        return Err(InviteError::Invalid);
    }
    let mut uri = Zeroizing::new(PREFIX.to_owned());
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut uri);
    if uri.len() > MAX_URI {
        return Err(InviteError::Invalid);
    }
    Ok(uri)
}

pub(crate) fn decode_wire(uri: &str) -> Result<Wire, InviteError> {
    if uri.len() > MAX_URI {
        return Err(InviteError::Invalid);
    }
    let encoded = uri.strip_prefix(PREFIX).ok_or(InviteError::Invalid)?;
    if encoded.is_empty() || encoded.bytes().any(|c| !c.is_ascii_alphanumeric() && c != b'-' && c != b'_') {
        return Err(InviteError::Invalid);
    }
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| InviteError::Invalid)?);
    if bytes.len() > MAX_DATA || Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice())).as_str() != encoded {
        return Err(InviteError::Invalid);
    }
    let mut r = Reader(bytes.as_slice());
    if r.byte()? != 1 {
        return Err(InviteError::Invalid);
    }
    let security_mode = match r.byte()? {
        0 => WireSecurity::OwnTls, 1 => WireSecurity::SmartReality, _ => return Err(InviteError::Invalid),
    };
    let transport = match r.byte()? {
        0 => Transport::Auto, 1 => Transport::H2, 2 => Transport::H3, _ => return Err(InviteError::Invalid),
    };
    let xhttp_mode = match r.byte()? {
        0 => XhttpMode::Auto, 1 => XhttpMode::StreamOne, 2 => XhttpMode::StreamUp, _ => return Err(InviteError::Invalid),
    };
    let mut wire = Wire {
        version: 1, carrier: "smarttheia-xhttp".into(), security_mode, transport, xhttp_mode,
        id: String::new(), endpoint: String::new(), server_name: String::new(), path_prefix: String::new(),
        token: None, admission: None, public_key: None, minimum_revision: None, descriptor: None,
    };
    let flags = r.byte()?;
    if flags & !3 != 0 {
        return Err(InviteError::Invalid);
    }
    if flags & 1 != 0 {
        let token = Zeroizing::new(r.array::<32>()?);
        wire.token = Some(URL_SAFE_NO_PAD.encode(&token[..]));
    }
    if flags & 2 != 0 {
        let admission = Zeroizing::new(r.array::<32>()?);
        if *admission == [0; 32] {
            return Err(InviteError::Invalid);
        }
        wire.admission = Some(URL_SAFE_NO_PAD.encode(&admission[..]));
    }
    match security_mode {
        WireSecurity::OwnTls => {
            wire.id = r.text()?;
            wire.endpoint = r.text()?;
            wire.server_name = r.text()?;
            wire.path_prefix = r.text()?;
        }
        WireSecurity::SmartReality => {
            wire.public_key = Some(URL_SAFE_NO_PAD.encode(r.array::<32>()?));
            let (d, document) = get_descriptor(&mut r)?;
            wire.id = d.scope.inbound;
            wire.endpoint = d.scope.endpoint;
            wire.path_prefix = d.path_prefix;
            wire.server_name = d.references[usize::from(d.active_reference)].server_name.clone();
            wire.minimum_revision = Some(d.revision);
            wire.descriptor = Some(document);
        }
    }
    if !r.0.is_empty() {
        return Err(InviteError::Invalid);
    }
    check_wire(&wire)?;
    Ok(wire)
}

impl Invitation {
    /// Safe token-free export of an exact supported profile.
    pub fn public_from_profile(profile: &Profile) -> Result<Self, InviteError> {
        if profile.reality_profile.is_some() || !profile.security_mode.is_plain() {
            return Err(InviteError::Invalid);
        }
        let invite = Self {
            id: profile.id.clone(),
            path_prefix: profile.path_prefix.clone().ok_or(InviteError::Invalid)?,
            endpoint: profile.server.clone(),
            server_name: profile.server_name.clone(),
            transport: profile.transport,
            xhttp_mode: profile.effective_xhttp_mode(),
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
        if inbound.security_mode == crate::security_profile::SecurityMode::SmartReality
            || inbound.reality.is_some()
        {
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
        if !inbound.security_mode.is_plain() {
            return Err(InviteError::Unavailable);
        }
        let invite = Self {
            id: inbound.id.clone(),
            path_prefix: inbound.path_prefix.clone().ok_or(InviteError::Invalid)?,
            endpoint: format!("{}:{}", inbound.server_name, h2.port()),
            server_name: inbound.server_name.clone(),
            transport: Transport::Auto,
            xhttp_mode: XhttpMode::Auto,
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
            path_prefix: self.path_prefix.clone(),
            id: self.id.clone(),
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            carrier: "smarttheia-xhttp".into(),
            security_mode: WireSecurity::OwnTls,
            xhttp_mode: self.xhttp_mode,
            transport: self.transport,
            public_key: None,
            minimum_revision: None,
            descriptor: None,
            token: self.token.as_ref().map(|v| URL_SAFE_NO_PAD.encode(v)),
            admission: None,
        };
        let mut uri = encode_wire(&wire)?;
        Ok(std::mem::take(&mut *uri))
    }

    /// Reject non-canonical base64url, unknown fields/versions, invalid
    /// credential lengths, and invalid core profile fields.
    pub fn decode(uri: &str) -> Result<Self, InviteError> {
        let mut wire = decode_wire(uri)?;
        if wire.security_mode != WireSecurity::OwnTls {
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
            path_prefix: std::mem::take(&mut wire.path_prefix),
            endpoint: std::mem::take(&mut wire.endpoint),
            server_name: std::mem::take(&mut wire.server_name),
            transport: wire.transport,
            xhttp_mode: wire.xhttp_mode,
            token,
        };
        invite.check()?;
        Ok(invite)
    }

    /// Non-secret, exact security/carrier selection for safe preview.
    pub fn security_mode(&self) -> SecurityMode {
        SecurityMode::Plain
    }

    pub fn xhttp_mode(&self) -> XhttpMode {
        self.xhttp_mode
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
            path_prefix: Some(self.path_prefix.clone()),
            server: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            auth_token: secret_ref.into(),
            security_mode: self.security_mode(),
            reality_profile: None,
            xhttp_mode: Some(self.xhttp_mode),
            tls_ca,
            transport: self.transport,
            quic_connect_timeout_ms: 1600,
            quic_negative_cache_ttl_s: 900,
        })
    }

    fn check(&self) -> Result<(), InviteError> {
        let profile = self.to_profile_unchecked("env:THEIA_INVITE_TOKEN".into(), None)?;
        if profile.effective_xhttp_mode() != self.xhttp_mode {
            return Err(InviteError::Invalid);
        }
        Ok(())
    }

    fn to_profile_unchecked(
        &self,
        auth_token: String,
        tls_ca: Option<String>,
    ) -> Result<Profile, InviteError> {
        validate_profile(Profile {
            id: self.id.clone(),
            path_prefix: Some(self.path_prefix.clone()),
            server: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            auth_token,
            security_mode: self.security_mode(),
            reality_profile: None,
            xhttp_mode: Some(self.xhttp_mode),
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
        assert_eq!(profile.effective_xhttp_mode(), XhttpMode::Auto);
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
    fn v1_roundtrips_all_own_tls_xhttp_modes() {
        let Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let mut profile = doc.client.profiles[0].clone();
        for mode in [XhttpMode::Auto, XhttpMode::StreamOne, XhttpMode::StreamUp] {
            profile.xhttp_mode = Some(mode);
            let invite = Invitation::public_from_profile(&profile).unwrap();
            let link = invite.encode().unwrap();
            let decoded = Invitation::decode(&link).unwrap();
            assert_eq!(decoded.xhttp_mode(), mode);
            assert_eq!(
                decoded
                    .to_profile("env:TOKEN", None)
                    .unwrap()
                    .effective_xhttp_mode(),
                mode
            );
            assert_eq!(decoded.encode().unwrap(), link);
        }
        profile.xhttp_mode = None;
        assert_eq!(
            Invitation::public_from_profile(&profile)
                .unwrap()
                .xhttp_mode(),
            XhttpMode::Auto
        );
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
            assert_eq!(restored.security_mode, SecurityMode::Plain);
            assert_eq!(restored.transport, transport);
        }
        for mode in [
            SecurityMode::PinnedCertV1,
            SecurityMode::PinnedCertStreamUpV1,
            SecurityMode::SmartReality,
        ] {
            profile.security_mode = mode;
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
    fn replacement_v1_roundtrips_own_tls_and_rejects_retired_profiles() {
        let Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!()
        };
        let mut profile = doc.client.profiles[0].clone();
        for transport in [Transport::H2, Transport::H3, Transport::Auto] {
            profile.transport = transport;
            let link = Invitation::public_from_profile(&profile)
                .unwrap()
                .encode()
                .unwrap();
            // Old textual v1 links are deliberately incompatible in DEV.
            let raw = toml::to_string(&decode_wire(&link).unwrap()).unwrap();
            let decoded = Invitation::decode(&link).unwrap();
            assert_eq!(
                decoded.to_profile("env:TOKEN", None).unwrap().path_prefix,
                profile.path_prefix
            );
            assert_eq!(decoded.transport, transport);
            assert_eq!(decoded.encode().unwrap(), link);
            for bad in [
                raw.replace("own-tls", "pinned-tls"),
                raw.replace("own-tls", "browser-h2-btls-v1"),
                raw.replace("/v1/theia-example", "/v1/../x"),
                raw.lines()
                    .filter(|line| !line.starts_with("path_prefix = "))
                    .collect::<Vec<_>>()
                    .join("\n"),
                format!("{raw}leaf_sha256 = \"{}\"\n", "42".repeat(32)),
                format!("{raw}tls_ca = \"file:/untrusted.pem\"\n"),
            ] {
                assert!(
                    Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bad)))
                        .is_err()
                );
            }
        }
        for mode in [
            SecurityMode::PinnedCertV1,
            SecurityMode::PinnedCertStreamUpV1,
            SecurityMode::SmartReality,
        ] {
            profile.security_mode = mode;
            assert!(Invitation::public_from_profile(&profile).is_err());
        }
    }

    #[test]
    fn retired_local_tls_reality_invitation_and_profile_fail_closed() {
        let Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture");
        };
        let mut profile = doc.client.profiles[0].clone();
        let key = URL_SAFE_NO_PAD.encode([0x42; 32]);
        let uri = Invitation::public_from_profile(&profile)
            .unwrap()
            .encode()
            .unwrap();
        let text = toml::to_string(&decode_wire(&uri).unwrap()).unwrap();
        let retired = format!(
            "{}server_public_key = \"{key}\"\n",
            text.replace(
                "security_mode = \"own-tls\"",
                "security_mode = \"smart-reality\""
            )
            .replace("xhttp_mode = \"stream-one\"", "xhttp_mode = \"stream-up\"")
        );
        assert!(
            Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(retired))).is_err()
        );
        profile.security_mode = SecurityMode::SmartReality;
        for transport in [Transport::H2, Transport::H3, Transport::Auto] {
            profile.transport = transport;
            assert!(Invitation::public_from_profile(&profile).is_err());
            let mut invalid = doc.clone();
            invalid.client.profiles[0] = profile.clone();
            assert!(Config::Client(invalid).validate().is_err());
        }
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
        let bytes = URL_SAFE_NO_PAD.decode(uri.strip_prefix(PREFIX).unwrap()).unwrap();
        for (offset, invalid) in [(0, 2), (1, 9), (2, 9), (3, 9), (4, 2)] {
            let mut changed = bytes.clone();
            changed[offset] = invalid;
            assert!(Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(changed))).is_err());
        }
        for end in 0..bytes.len() {
            assert!(Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&bytes[..end]))).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(trailing))).is_err());
        let text = toml::to_string(&decode_wire(&uri).unwrap()).unwrap();
        for altered in [
            text.replace("version = 1", "version = 2"),
            text.replace(
                "security_mode = \"own-tls\"",
                "security_mode = \"chrome133\"",
            ),
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
