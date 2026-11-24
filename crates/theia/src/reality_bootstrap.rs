//! Guarded F-18 provisioning and independent enrollment. The signed
//! descriptor is the single source of reference and offered-mode metadata.
//! No network activation, no automatic trust-on-first-use, no private key
//! or OS/file references in an invitation. No REALITY wire behavior claimed.
#![forbid(unsafe_code)]

use crate::{
    config::{self, Transport, WriteFailure, XhttpMode},
    descriptor::{self, Anchor, ClientPolicy, Descriptor, Scope, Verified},
    identity_tls::Identity,
    reference_health,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "theia://v1/";
pub const MAX_URI: usize = 32 * 1024;
const MAX_DATA: usize = 24 * 1024;
const MAX_PROFILE: usize = 64 * 1024;
const VALIDITY: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Format,
    Scope,
    Approval,
    Identity,
    Descriptor,
    Health,
    Grant,
    Credential,
    Storage,
    Indeterminate,
    Clock,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Format => "invalid REALITY provisioning document",
            Self::Scope => "inbound or endpoint scope differs",
            Self::Approval => "exact preview or independent identity confirmation differs",
            Self::Identity => "identity operation refused",
            Self::Descriptor => "signed descriptor rejected",
            Self::Health => "reference inventory is stale or ineligible",
            Self::Grant => "explicit enabled user grant required",
            Self::Credential => "missing or invalid credential",
            Self::Storage => "local publication refused",
            Self::Indeterminate => "local publication uncertain; inspect before retry",
            Self::Clock => "invalid local clock",
        })
    }
}
impl std::error::Error for Error {}

pub fn digest(raw: &str) -> [u8; 32] {
    Sha256::digest(raw.as_bytes()).into()
}

pub fn fingerprint(key: [u8; 32]) -> [u8; 32] {
    Sha256::digest(key).into()
}

fn key(raw: &str) -> Result<[u8; 32], Error> {
    if raw.len() != 43 {
        return Err(Error::Format);
    }
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Format)?;
    let result: [u8; 32] = decoded.try_into().map_err(|_| Error::Format)?;
    if result == [0; 32] || URL_SAFE_NO_PAD.encode(result) != raw {
        return Err(Error::Format);
    }
    Ok(result)
}

fn token(raw: &str) -> Result<[u8; 32], Error> {
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Credential)?);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    if raw.len() != 43 || encoded.as_str() != raw {
        return Err(Error::Credential);
    }
    bytes.as_slice().try_into().map_err(|_| Error::Credential)
}

fn scope_of(state: &reference_health::State) -> Scope {
    Scope {
        inbound: state.plan().inbound.clone(),
        endpoint: state.plan().endpoint.clone(),
    }
}

fn auto_policy() -> ClientPolicy {
    ClientPolicy { transport: Transport::Auto, xhttp_mode: XhttpMode::Auto }
}

fn verify(
    signed: &str,
    scope: &Scope,
    public: [u8; 32],
    minimum: u64,
    policy: ClientPolicy,
    now: u64,
) -> Result<Verified, Error> {
    let anchor = Anchor::new(scope.clone(), public, minimum, policy)
        .map_err(|_| Error::Descriptor)?;
    let value = descriptor::verify(signed, &anchor).map_err(|_| Error::Descriptor)?;
    value.check_time(now).map_err(|_| Error::Descriptor)?;
    Ok(value)
}

/// Generate once at initial provisioning; a normal refresh retains the
/// routing prefix and the identity, endpoint, grants and reference order.
/// Numeric parameters are provisional v1 implementation choices.
pub fn initial_descriptor(
    state: &reference_health::State,
    identity: &Identity,
    now: u64,
) -> Result<String, Error> {
    let scope = scope_of(state);
    if identity.scope() != &scope {
        return Err(Error::Scope);
    }
    let references = state.eligible_references(now).map_err(|_| Error::Health)?;
    let mut random = [0u8; 16];
    SystemRandom::new().fill(&mut random).map_err(|_| Error::Identity)?;
    let value = Descriptor {
        schema_version: 1,
        wire_version: 1,
        security_mode: descriptor::SecurityMode::SmartReality,
        revision: 1,
        not_before: now,
        not_after: now.checked_add(VALIDITY).ok_or(Error::Clock)?,
        active_reference: 0,
        h3: references[0].h3,
        stream_one: true,
        stream_up: true,
        path_prefix: format!("/v1/{}", URL_SAFE_NO_PAD.encode(random)),
        next_identity: None,
        scope,
        padding: descriptor::Padding {
            header_min: 0,
            header_max: 256,
            frame_min: 0,
            frame_max: 1024,
        },
        rotation: descriptor::Rotation {
            lifetime_min_s: 300,
            lifetime_max_s: 900,
            volume_min_bytes: 16 * 1024 * 1024,
            volume_max_bytes: 64 * 1024 * 1024,
        },
        references,
    };
    identity.sign_descriptor(&value).map_err(|_| Error::Descriptor)
}

/// Refresh expiry/revision of the exact previous signed descriptor without
/// resetting its revision floor or publishing a different bootstrap target.
/// A transport removed by reference degradation must not silently break
/// previously enrolled H3-only profiles. Reserve switching is not performed.
pub fn validate_publication(
    state: &reference_health::State,
    identity: &Identity,
    signed: &str,
    now: u64,
) -> Result<(), Error> {
    if identity.scope() != &scope_of(state) {
        return Err(Error::Scope);
    }
    let value = verify(signed, identity.scope(), identity.public_key(), 1, auto_policy(), now)?;
    let offered = &value.descriptor().references;
    let fresh = state.eligible_references(now).map_err(|_| Error::Health)?;
    if fresh.len() != offered.len()
        || fresh.iter().zip(offered).any(|(current, signed)| {
            current.server_name != signed.server_name || current.port != signed.port
                || (signed.h3 && !current.h3)
        })
    {
        return Err(Error::Health);
    }
    Ok(())
}

pub fn refresh_descriptor(
    state: &reference_health::State,
    identity: &Identity,
    previous: &str,
    now: u64,
) -> Result<String, Error> {
    let scope = scope_of(state);
    if identity.scope() != &scope {
        return Err(Error::Scope);
    }
    let anchor = Anchor::new(scope, identity.public_key(), 1, auto_policy())
        .map_err(|_| Error::Descriptor)?;
    let old = descriptor::verify(previous, &anchor).map_err(|_| Error::Descriptor)?;
    let mut next = old.descriptor().clone();
    if now <= next.not_before {
        return Err(Error::Clock);
    }
    let references = state.eligible_references(now).map_err(|_| Error::Health)?;
    if references.len() != next.references.len()
        || references.iter().zip(&next.references).any(|(fresh, prior)| {
            fresh.server_name != prior.server_name || fresh.port != prior.port
                || (prior.h3 && !fresh.h3)
        })
    {
        return Err(Error::Health);
    }
    // Do not enable a previously unavailable transport by refresh alone.
    next.revision = next.revision.checked_add(1).ok_or(Error::Descriptor)?;
    next.not_before = now;
    next.not_after = now.checked_add(VALIDITY).ok_or(Error::Clock)?;
    identity.sign_descriptor(&next).map_err(|_| Error::Descriptor)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u16,
    carrier: String,
    security_mode: String,
    inbound: String,
    endpoint: String,
    public_key: String,
    minimum_revision: u64,
    descriptor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
}

/// Incoming invitations are UNTRUSTED until explicitly matched with an
/// independently obtained public-key fingerprint. A valid self-signature
/// is not proof that the operator intended to trust the signer.
pub struct Invitation {
    scope: Scope,
    public: [u8; 32],
    revision: u64,
    signed: String,
    bearer: Option<Zeroizing<[u8; 32]>>,
}

impl Invitation {
    pub fn public(
        identity: &Identity,
        signed: &str,
        now: u64,
    ) -> Result<Self, Error> {
        let value = verify(signed, identity.scope(), identity.public_key(), 1, auto_policy(), now)?;
        Ok(Self {
            scope: identity.scope().clone(),
            public: identity.public_key(),
            revision: value.descriptor().revision,
            signed: signed.to_owned(),
            bearer: None,
        })
    }

    /// A confidential invitation is issued only for an existing exact
    /// enabled user grant. Never mint a credential from a stored digest.
    pub fn issued(
        identity: &Identity,
        signed: &str,
        document: &config::ServerDocument,
        user_id: &str,
        bearer: &[u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        config::Config::Server(document.clone()).validate().map_err(|_| Error::Grant)?;
        let mut invitation = Self::public(identity, signed, now)?;
        if !document.server.enabled {
            return Err(Error::Grant);
        }
        let inbound = document.server.inbounds.iter()
            .find(|item| item.id == invitation.scope.inbound)
            .ok_or(Error::Grant)?;
        let h2: std::net::SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let h3: std::net::SocketAddr = inbound.quic_listen.parse().map_err(|_| Error::Scope)?;
        if h2.port() != h3.port()
            || format!("{}:{}", inbound.server_name, h2.port()) != invitation.scope.endpoint
        {
            return Err(Error::Scope);
        }
        let user = document.server.users.iter()
            .find(|user| user.id == user_id && !user.disabled)
            .ok_or(Error::Grant)?;
        if !inbound.allowed_user_ids.iter().any(|id| id == user_id) {
            return Err(Error::Grant);
        }
        let digest = format!("{:x}", Sha256::digest(bearer));
        if !bool::from(user.token_sha256.as_bytes().ct_eq(digest.as_bytes())) {
            return Err(Error::Credential);
        }
        invitation.bearer = Some(Zeroizing::new(*bearer));
        Ok(invitation)
    }

    fn wire(&self) -> Wire {
        Wire {
            version: 1,
            carrier: "smarttheia-xhttp".into(),
            security_mode: "smart-reality".into(),
            inbound: self.scope.inbound.clone(),
            endpoint: self.scope.endpoint.clone(),
            public_key: URL_SAFE_NO_PAD.encode(self.public),
            minimum_revision: self.revision,
            descriptor: self.signed.clone(),
            token: self.bearer.as_ref().map(|value| URL_SAFE_NO_PAD.encode(&value[..])),
        }
    }

    pub fn encode(&self) -> Result<Zeroizing<String>, Error> {
        let raw = Zeroizing::new(toml::to_string(&self.wire()).map_err(|_| Error::Format)?);
        if raw.len() > MAX_DATA {
            return Err(Error::Format);
        }
        let mut uri = Zeroizing::new(PREFIX.to_owned());
        URL_SAFE_NO_PAD.encode_string(raw.as_bytes(), &mut uri);
        if uri.len() > MAX_URI {
            return Err(Error::Format);
        }
        Ok(uri)
    }

    pub fn decode(uri: &str, now: u64) -> Result<Self, Error> {
        if uri.len() > MAX_URI {
            return Err(Error::Format);
        }
        let encoded = uri.strip_prefix(PREFIX).ok_or(Error::Format)?;
        let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Error::Format)?);
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()));
        if raw.len() > MAX_DATA || canonical.as_str() != encoded {
            return Err(Error::Format);
        }
        let text = std::str::from_utf8(&raw).map_err(|_| Error::Format)?;
        let wire: Wire = toml::from_str(text).map_err(|_| Error::Format)?;
        if wire.version != 1 || wire.carrier != "smarttheia-xhttp" || wire.security_mode != "smart-reality"
            || Zeroizing::new(toml::to_string(&wire).map_err(|_| Error::Format)?).as_str() != text
        {
            return Err(Error::Format);
        }
        let public = key(&wire.public_key)?;
        let scope = Scope { inbound: wire.inbound.clone(), endpoint: wire.endpoint.clone() };
        let value = verify(&wire.descriptor, &scope, public, wire.minimum_revision, auto_policy(), now)?;
        if value.descriptor().revision != wire.minimum_revision {
            return Err(Error::Descriptor);
        }
        let bearer = wire.token.as_deref().map(token).transpose()?.map(Zeroizing::new);
        Ok(Self {
            scope,
            public,
            revision: wire.minimum_revision,
            signed: wire.descriptor.clone(),
            bearer,
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(self.public)
    }

    pub fn preview(&self, now: u64) -> Result<String, Error> {
        let value = verify(&self.signed, &self.scope, self.public, self.revision, auto_policy(), now)?;
        let d = value.descriptor();
        Ok(format!(
            "UNTRUSTED invitation; verify fingerprint independently; runtime UNCHANGED\ninbound={}\nendpoint={}\nidentity_sha256={:x}\nrevision={}\nreference={}\nh3={}\ncontains_token={}",
            self.scope.inbound,
            self.scope.endpoint,
            Sha256::digest(self.public),
            self.revision,
            d.references[usize::from(d.active_reference)].server_name,
            d.h3,
            self.bearer.is_some()
        ))
    }

    fn confirmed(&self, expected: [u8; 32], policy: ClientPolicy, now: u64) -> Result<Anchor, Error> {
        if !bool::from(self.fingerprint().ct_eq(&expected)) {
            return Err(Error::Approval);
        }
        verify(&self.signed, &self.scope, self.public, self.revision, policy, now)?;
        Anchor::new(self.scope.clone(), self.public, self.revision, policy).map_err(|_| Error::Descriptor)
    }
}

/// The imported independent root lives outside the mutable signed history.
/// This record is published last, after the trust snapshot exists. A failed
/// import cannot overwrite a profile, change the active profile or OS proxy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    schema_version: u16,
    inbound: String,
    endpoint: String,
    public_key: String,
    minimum_revision: u64,
    transport: Transport,
    xhttp_mode: XhttpMode,
    trust_store: String,
    auth_token: String,
}

impl Profile {
    fn anchor(&self) -> Result<Anchor, Error> {
        if self.schema_version != 1 || !config::valid_secret_ref(&self.auth_token)
            || !crate::bounded_input::explicit_file_path(Path::new(&self.trust_store))
        {
            return Err(Error::Format);
        }
        Anchor::new(
            Scope { inbound: self.inbound.clone(), endpoint: self.endpoint.clone() },
            key(&self.public_key)?,
            self.minimum_revision,
            ClientPolicy { transport: self.transport, xhttp_mode: self.xhttp_mode },
        ).map_err(|_| Error::Descriptor)
    }

    pub fn read(path: &Path) -> Result<Self, Error> {
        let raw = crate::bounded_input::read(path, MAX_PROFILE as u64, true, true)
            .map_err(|_| Error::Storage)?;
        let profile: Self = toml::from_str(std::str::from_utf8(&raw).map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?;
        profile.anchor()?;
        Ok(profile)
    }

    pub fn load(&self, now: u64) -> Result<Verified, Error> {
        descriptor::Store::new(Path::new(&self.trust_store), self.anchor()?)
            .map_err(|_| Error::Storage)?.load(now).map_err(|_| Error::Descriptor)
    }

    pub fn store(&self) -> Result<descriptor::Store, Error> {
        descriptor::Store::new(Path::new(&self.trust_store), self.anchor()?)
            .map_err(|_| Error::Storage)
    }

    pub fn credential_reference(&self) -> &str {
        &self.auth_token
    }
}

pub fn import(
    uri: &str,
    expected_document: [u8; 32],
    expected_identity: [u8; 32],
    profile_path: &Path,
    trust_path: &Path,
    external_token: Option<&str>,
    policy: ClientPolicy,
    now: u64,
) -> Result<(), Error> {
    if !bool::from(digest(uri).ct_eq(&expected_document)) {
        return Err(Error::Approval);
    }
    if !crate::bounded_input::explicit_file_path(profile_path)
        || !crate::bounded_input::explicit_file_path(trust_path)
        || profile_path == trust_path
    {
        return Err(Error::Storage);
    }
    // Early refusal; the final create-only CAS remains authoritative.
    for path in [profile_path, trust_path] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::Storage),
        }
    }
    let invitation = Invitation::decode(uri, now)?;
    let anchor = invitation.confirmed(expected_identity, policy, now)?;
    let trust_store = trust_path.to_str().ok_or(Error::Storage)?.to_owned();
    let mut staged = None;
    let auth_token = match (&invitation.bearer, external_token) {
        (Some(bearer), None) => {
            let guard = crate::client_import::PrivateBearer::create(profile_path, bearer)
                .map_err(|_| Error::Storage)?;
            let reference = guard.reference().map_err(|_| Error::Storage)?;
            staged = Some(guard);
            reference
        }
        (None, Some(reference)) if config::valid_secret_ref(reference) => reference.to_owned(),
        _ => return Err(Error::Credential),
    };
    let profile = Profile {
        schema_version: 1,
        inbound: invitation.scope.inbound.clone(),
        endpoint: invitation.scope.endpoint.clone(),
        public_key: URL_SAFE_NO_PAD.encode(invitation.public),
        minimum_revision: invitation.revision,
        transport: policy.transport,
        xhttp_mode: policy.xhttp_mode,
        trust_store,
        auth_token,
    };
    profile.anchor()?;
    let raw = Zeroizing::new(toml::to_string(&profile).map_err(|_| Error::Format)?);
    if raw.len() > MAX_PROFILE {
        return Err(Error::Format);
    }
    let store = descriptor::Store::new(trust_path, anchor).map_err(|_| Error::Storage)?;
    store.initialize(&invitation.signed, now).map_err(|error| match error {
        descriptor::Error::Indeterminate => Error::Indeterminate,
        _ => Error::Storage,
    })?;
    // A trust file can remain orphaned if the final publication fails.
    // Never remove a path which might be observed/replaced by another process.
    match config::guarded_trust_write(profile_path, &raw, None) {
        Ok(()) => {
            if let Some(guard) = &mut staged {
                guard.commit();
            }
            Ok(())
        }
        Err(WriteFailure::AfterReplace(_)) => {
            if let Some(guard) = &mut staged {
                guard.commit();
            }
            Err(Error::Indeterminate)
        }
        Err(WriteFailure::BeforeReplace(_)) => Err(Error::Storage),
    }
}

pub fn read_text(path: &Path, max: usize, private: bool) -> Result<Zeroizing<String>, Error> {
    let bytes = crate::bounded_input::read(path, max as u64, true, private)
        .map_err(|_| Error::Storage)?;
    Ok(Zeroizing::new(std::str::from_utf8(&bytes).map_err(|_| Error::Format)?.to_owned()))
}

pub fn create_text(path: &Path, raw: &str) -> Result<(), Error> {
    if !crate::bounded_input::explicit_file_path(path) {
        return Err(Error::Storage);
    }
    config::guarded_trust_write(path, raw, None).map_err(|error| match error {
        WriteFailure::BeforeReplace(_) => Error::Storage,
        WriteFailure::AfterReplace(_) => Error::Indeterminate,
    })
}

pub fn read_credential(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    let raw = read_text(path, 43, true)?;
    Ok(Zeroizing::new(token(&raw)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NOW: u64 = 1000;

    fn fixture() -> (reference_health::State, Identity) {
        let plan = reference_health::Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![reference_health::Target {
                server_name: "reference.example.org".into(),
                address: "93.184.216.2:443".parse().unwrap(),
            }],
        };
        let state = reference_health::State::new(
            plan,
            vec![reference_health::Evidence { h2_status: Some(200), h3_status: None }],
            NOW,
        ).unwrap();
        let identity = Identity::generate(scope_of(&state)).unwrap();
        (state, identity)
    }

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "theia-bootstrap-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn bootstrap_is_canonical_and_independent_confirmation_is_required() {
        let (state, identity) = fixture();
        let raw = initial_descriptor(&state, &identity, NOW).unwrap();
        let invite = Invitation::public(&identity, &raw, NOW).unwrap();
        let uri = invite.encode().unwrap();
        let received = Invitation::decode(&uri, NOW).unwrap();
        assert_eq!(received.fingerprint(), fingerprint(identity.public_key()));
        assert!(received.confirmed([0; 32], auto_policy(), NOW).is_err());
        received.confirmed(invite.fingerprint(), auto_policy(), NOW).unwrap();
        assert!(received.confirmed(invite.fingerprint(), ClientPolicy {
            transport: Transport::H3, xhttp_mode: XhttpMode::Auto,
        }, NOW).is_err());
        assert!(Invitation::decode(&format!("{uri}="), NOW).is_err());
        assert!(Invitation::decode(&uri, NOW + VALIDITY).is_err());
        let wire = received.wire();
        let mut value = toml::to_string(&wire).unwrap();
        value.push_str("unknown = 1\n");
        let malicious = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(value));
        assert!(Invitation::decode(&malicious, NOW).is_err());
    }

    #[test]
    fn refresh_preserves_prefix_scope_and_advances_revision() {
        let (state, identity) = fixture();
        let raw = initial_descriptor(&state, &identity, NOW).unwrap();
        let next = refresh_descriptor(&state, &identity, &raw, NOW + 1).unwrap();
        let old = verify(&raw, identity.scope(), identity.public_key(), 1, auto_policy(), NOW).unwrap();
        let fresh = verify(&next, identity.scope(), identity.public_key(), 1, auto_policy(), NOW + 1).unwrap();
        assert_eq!(fresh.descriptor().revision, 2);
        assert_eq!(fresh.descriptor().path_prefix, old.descriptor().path_prefix);
        assert!(fresh.descriptor().references == old.descriptor().references);
        assert!(refresh_descriptor(&state, &identity, &raw, NOW).is_err());
        let other = Identity::generate(identity.scope().clone()).unwrap();
        assert!(refresh_descriptor(&state, &other, &raw, NOW + 1).is_err());
        let failed = state.record(vec![reference_health::Evidence::default()], NOW + 1).unwrap();
        assert!(refresh_descriptor(&failed, &identity, &raw, NOW + 2).is_err());
    }

    #[test]
    fn import_publishes_last_and_preserves_existing_profile() {
        let (state, identity) = fixture();
        let raw = initial_descriptor(&state, &identity, NOW).unwrap();
        let uri = Invitation::public(&identity, &raw, NOW).unwrap().encode().unwrap();
        let scratch = Scratch::new();
        let profile = scratch.0.join("profile.toml");
        let trust = scratch.0.join("trust.toml");
        let expected = digest(&uri);
        let pin = fingerprint(identity.public_key());
        assert_eq!(import(&uri, expected, [0; 32], &profile, &trust, Some("env:TEST_TOKEN"), auto_policy(), NOW), Err(Error::Approval));
        assert!(!profile.exists() && !trust.exists());
        assert_eq!(import(&uri, expected, pin, &profile, &trust, None, auto_policy(), NOW), Err(Error::Credential));
        assert!(!profile.exists() && !trust.exists());
        import(&uri, expected, pin, &profile, &trust, Some("env:TEST_TOKEN"), auto_policy(), NOW).unwrap();
        let before = std::fs::read(&profile).unwrap();
        let loaded = Profile::read(&profile).unwrap();
        assert_eq!(loaded.credential_reference(), "env:TEST_TOKEN");
        assert_eq!(loaded.load(NOW).unwrap().signer(), identity.public_key());
        assert_eq!(import(&uri, expected, pin, &profile, &trust, Some("env:OTHER"), auto_policy(), NOW), Err(Error::Storage));
        assert_eq!(std::fs::read(&profile).unwrap(), before);
        let next = refresh_descriptor(&state, &identity, &raw, NOW + 1).unwrap();
        loaded.store().unwrap().update_at(&next, 1, NOW + 1).unwrap();
        assert_eq!(Profile::read(&profile).unwrap().load(NOW + 1).unwrap().descriptor().revision, 2);
    }

    #[test]
    fn confidential_invite_checks_existing_enabled_grant_and_redacts_token() {
        let (state, identity) = fixture();
        let raw = initial_descriptor(&state, &identity, NOW).unwrap();
        let credential = [42u8; 32];
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &format!("{:x}", Sha256::digest(credential)))
            .replace("id = \"public\"", "id = \"edge\"");
        let config::Config::Server(mut server) = config::parse(&source).unwrap() else { panic!() };
        let invite = Invitation::issued(&identity, &raw, &server, "device-a", &credential, NOW).unwrap();
        assert!(!invite.preview(NOW).unwrap().contains(&URL_SAFE_NO_PAD.encode(credential)));
        let uri = invite.encode().unwrap();
        let scratch = Scratch::new();
        let profile = scratch.0.join("profile.toml");
        let trust = scratch.0.join("trust.toml");
        import(&uri, digest(&uri), invite.fingerprint(), &profile, &trust, None, auto_policy(), NOW).unwrap();
        let loaded = Profile::read(&profile).unwrap();
        let path = loaded.credential_reference().strip_prefix("file:").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), URL_SAFE_NO_PAD.encode(credential));
        assert!(!std::fs::read_to_string(&profile).unwrap().contains(&URL_SAFE_NO_PAD.encode(credential)));
        server.server.users[0].disabled = true;
        assert!(Invitation::issued(&identity, &raw, &server, "device-a", &credential, NOW).is_err());
    }
}
