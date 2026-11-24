//! Candidate independent identity-authenticated TLS, using a pinned Ed25519
//! trust anchor and ordinary WebPKI path/hostname/CertificateVerify/Finished.
//!
//! No public CA is trusted for this mode, no external certificate is copied,
//! no custom verifier bypasses TLS, and no native listener is activated here.
//! This is the authenticated TLS part of F-18, NOT a ClientHello admission
//! adapter or an implementation of REALITY network behavior.
#![forbid(unsafe_code)]

use crate::{
    config::{self, WriteFailure},
    descriptor::{self, Descriptor, Scope},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, PKCS_ED25519,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, TrustAnchor},
    ClientConfig, RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

const KEY_FILE_MAX: u64 = 4096;
const KEY_FILE_PREFIX: &str = "theia-identity-v1";
const CA_NAME_PREFIX: &str = "Theia v1 ";
const SCOPE_DOMAIN: &[u8] = b"Theia/identity-tls/issuer/v1\0";
const LEAF_LIFETIME: i64 = 3600;
const LEAF_RENEWAL: i64 = LEAF_LIFETIME / 2;
const CLOCK_SKEW: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Scope,
    Key,
    Clock,
    Certificate,
    Tls,
    Descriptor,
    Storage,
    Indeterminate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scope => "identity scope or DNS name rejected",
            Self::Key => "invalid independent identity key",
            Self::Clock => "invalid certificate validity clock",
            Self::Certificate => "independent identity certificate generation failed",
            Self::Tls => "independent identity TLS configuration failed",
            Self::Descriptor => "identity descriptor signature refused",
            Self::Storage => "identity key storage refused",
            Self::Indeterminate => "identity key publication uncertain; inspect before retry",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    H2,
    H3,
}

impl Branch {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::H2 => b"h2",
            Self::H3 => b"h3",
        }
    }
}

fn valid_scope(scope: &Scope) -> bool {
    config::valid_id(&scope.inbound) && config::valid_remote(&scope.endpoint)
}

fn issuer_name(scope: &Scope, branch: Branch) -> Result<String, Error> {
    if !valid_scope(scope) {
        return Err(Error::Scope);
    }
    let mut hash = Sha256::new();
    hash.update(SCOPE_DOMAIN);
    hash.update(scope.inbound.as_bytes());
    hash.update([0]);
    hash.update(scope.endpoint.as_bytes());
    hash.update([0]);
    hash.update(branch.alpn());
    Ok(format!(
        "{CA_NAME_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    ))
}

/// The fixed single-CN DistinguishedName has a bounded, canonical DER
/// encoding. WebPKI anchors store the sequence VALUE, not its outer tag.
/// This is ordinary X.509 metadata, not a TLS transcript signature format.
fn subject_value(name: &str) -> Result<Vec<u8>, Error> {
    if name.len() > 64 || !name.is_ascii() {
        return Err(Error::Scope);
    }
    let len = u8::try_from(name.len()).map_err(|_| Error::Scope)?;
    let mut bytes = vec![
        0x31,
        len + 9,
        0x30,
        len + 7,
        0x06,
        0x03,
        0x55,
        0x04,
        0x03,
        0x0c,
        len,
    ];
    bytes.extend_from_slice(name.as_bytes());
    Ok(bytes)
}

/// RFC 8410 Ed25519 SubjectPublicKeyInfo sequence value. Parameters are
/// absent, and the bit string has zero unused bits.
fn spki_value(key: [u8; 32]) -> Result<Vec<u8>, Error> {
    if key == [0; 32] {
        return Err(Error::Key);
    }
    let mut bytes = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    bytes.extend_from_slice(&key);
    Ok(bytes)
}

fn pinned_roots(scope: &Scope, public: [u8; 32], branch: Branch) -> Result<RootCertStore, Error> {
    let subject = subject_value(&issuer_name(scope, branch)?)?;
    let spki = spki_value(public)?;
    let mut roots = RootCertStore::empty();
    roots.roots.push(TrustAnchor {
        subject: subject.into(),
        subject_public_key_info: spki.into(),
        name_constraints: None,
    });
    Ok(roots)
}

fn dn(name: String) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}

/// One dedicated identity per exact inbound scope; private key is never
/// displayed or accepted from an invitation. The file is create-only.
pub struct Identity {
    scope: Scope,
    pkcs8: Zeroizing<Vec<u8>>,
    public: [u8; 32],
}

impl Identity {
    fn from_key(scope: Scope, pkcs8: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        if !valid_scope(&scope) {
            return Err(Error::Scope);
        }
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| Error::Key)?;
        let public = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::Key)?;
        Ok(Self {
            scope,
            pkcs8,
            public,
        })
    }

    pub fn generate(scope: Scope) -> Result<Self, Error> {
        if !valid_scope(&scope) {
            return Err(Error::Scope);
        }
        let generated =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| Error::Key)?;
        Self::from_key(scope, Zeroizing::new(generated.as_ref().to_vec()))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn save_new(&self, path: &Path) -> Result<(), Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*self.pkcs8));
        let raw = Zeroizing::new(format!(
            "{KEY_FILE_PREFIX}\n{}\n{}\n{}\n",
            self.scope.inbound,
            self.scope.endpoint,
            encoded.as_str()
        ));
        config::guarded_trust_write(path, &raw, None).map_err(storage_error)
    }

    pub fn load(path: &Path, expected: &Scope) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) || !valid_scope(expected) {
            return Err(Error::Storage);
        }
        let raw = crate::bounded_input::read(path, KEY_FILE_MAX, true, true)
            .map_err(|_| Error::Storage)?;
        let text = std::str::from_utf8(&raw).map_err(|_| Error::Key)?;
        let mut lines = text.split('\n');
        if lines.next() != Some(KEY_FILE_PREFIX)
            || lines.next() != Some(expected.inbound.as_str())
            || lines.next() != Some(expected.endpoint.as_str())
        {
            return Err(Error::Scope);
        }
        let encoded = lines.next().ok_or(Error::Key)?;
        if lines.next() != Some("") || lines.next().is_some() {
            return Err(Error::Key);
        }
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Error::Key)?);
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*decoded));
        if canonical.as_str() != encoded {
            return Err(Error::Key);
        }
        Self::from_key(expected.clone(), decoded)
    }

    pub fn sign_descriptor(&self, descriptor: &Descriptor) -> Result<String, Error> {
        if descriptor.scope != self.scope {
            return Err(Error::Scope);
        }
        let pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8).map_err(|_| Error::Key)?;
        descriptor::sign(descriptor, &pair).map_err(|_| Error::Descriptor)
    }

    fn issuer(&self, branch: Branch) -> Result<(rcgen::Certificate, rcgen::KeyPair), Error> {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.pkcs8.as_slice());
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .map_err(|_| Error::Key)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(issuer_name(&self.scope, branch)?);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).map_err(|_| Error::Certificate)?;

        // Verify the library-generated issuer matches the independently
        // reconstructible anchor, refusing any encoding drift.
        let expected = pinned_roots(&self.scope, self.public, branch)?;
        let mut actual = RootCertStore::empty();
        actual
            .add(cert.der().clone())
            .map_err(|_| Error::Certificate)?;
        let expected = &expected.roots[0];
        let actual = &actual.roots[0];
        if expected.subject.as_ref() != actual.subject.as_ref()
            || expected.subject_public_key_info.as_ref() != actual.subject_public_key_info.as_ref()
            || actual.name_constraints.is_some()
        {
            return Err(Error::Certificate);
        }
        Ok((cert, key))
    }

    /// Generate a fresh leaf for one bounded TLS generation. No copied
    /// reference certificate or operator-provided TLS certificate is used.
    /// The leaf private key is separate from the long-lived identity.
    fn leaf(
        &self,
        name: &str,
        branch: Branch,
        now: OffsetDateTime,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Error> {
        if !config::valid_dns(name) {
            return Err(Error::Scope);
        }
        let (issuer, issuer_key) = self.issuer(branch)?;
        let leaf_key =
            rcgen::KeyPair::generate_for(&PKCS_ED25519).map_err(|_| Error::Certificate)?;
        let mut params =
            CertificateParams::new(vec![name.to_owned()]).map_err(|_| Error::Certificate)?;
        params.distinguished_name = dn("Theia TLS v1".to_owned());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = now
            .checked_sub(Duration::seconds(CLOCK_SKEW))
            .ok_or(Error::Clock)?;
        params.not_after = now
            .checked_add(Duration::seconds(LEAF_LIFETIME))
            .ok_or(Error::Clock)?;
        let cert = params
            .signed_by(&leaf_key, &issuer, &issuer_key)
            .map_err(|_| Error::Certificate)?;
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        Ok((cert.der().clone(), key.into()))
    }

    pub fn server_tls(&self, name: &str, branch: Branch) -> Result<ServerConfig, Error> {
        let resolver = Arc::new(RenewingLeaf::new(self, name, branch)?);
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Error::Tls)?
                .with_no_client_auth()
                .with_cert_resolver(resolver);
        config.alpn_protocols = vec![branch.alpn().to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        Ok(config)
    }

    #[cfg(test)]
    fn server_tls_at(
        &self,
        name: &str,
        branch: Branch,
        now: OffsetDateTime,
    ) -> Result<ServerConfig, Error> {
        let (leaf, key) = self.leaf(name, branch, now)?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Error::Tls)?
                .with_no_client_auth()
                .with_single_cert(vec![leaf], key)
                .map_err(|_| Error::Tls)?;
        config.alpn_protocols = vec![branch.alpn().to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        Ok(config)
    }

    pub fn quic_server(&self, name: &str) -> Result<quinn::ServerConfig, Error> {
        let tls = self.server_tls(name, Branch::H3)?;
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| Error::Tls)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(crate::quic_transport::transport_config());
        config.migration(false);
        Ok(config)
    }
}

/// Cache a short-lived leaf per immutable identity, name and branch.
/// Existing sessions retain their negotiated keys; renewal affects only
/// new full handshakes. The resolver never chooses a different signer.
struct CachedLeaf {
    issued_at: OffsetDateTime,
    key: Arc<rustls::sign::CertifiedKey>,
}

struct RenewingLeaf {
    identity: Identity,
    name: String,
    branch: Branch,
    leaf: Mutex<CachedLeaf>,
}

impl fmt::Debug for RenewingLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenewingLeaf")
            .field("branch", &self.branch)
            .finish_non_exhaustive()
    }
}

impl RenewingLeaf {
    fn issue(
        identity: &Identity,
        name: &str,
        branch: Branch,
        now: OffsetDateTime,
    ) -> Result<CachedLeaf, Error> {
        let (cert, private) = identity.leaf(name, branch, now)?;
        let provider = rustls::crypto::ring::default_provider();
        let key = rustls::sign::CertifiedKey::from_der(vec![cert], private, &provider)
            .map_err(|_| Error::Tls)?;
        Ok(CachedLeaf {
            issued_at: now,
            key: Arc::new(key),
        })
    }

    fn new(identity: &Identity, name: &str, branch: Branch) -> Result<Self, Error> {
        let leaf = Self::issue(identity, name, branch, OffsetDateTime::now_utc())?;
        Ok(Self {
            identity: Identity {
                scope: identity.scope.clone(),
                pkcs8: Zeroizing::new(identity.pkcs8.to_vec()),
                public: identity.public,
            },
            name: name.to_owned(),
            branch,
            leaf: Mutex::new(leaf),
        })
    }

    fn certificate_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<Arc<rustls::sign::CertifiedKey>, Error> {
        let mut leaf = self.leaf.lock().map_err(|_| Error::Tls)?;
        if now < leaf.issued_at {
            // Do not extend a validity period on clock rollback.
            return Err(Error::Clock);
        }
        if now - leaf.issued_at >= Duration::seconds(LEAF_RENEWAL) {
            *leaf = Self::issue(&self.identity, &self.name, self.branch, now)?;
        }
        Ok(Arc::clone(&leaf.key))
    }
}

impl rustls::server::ResolvesServerCert for RenewingLeaf {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if !hello
            .server_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(&self.name))
            || !hello
                .alpn()
                .is_some_and(|mut offered| offered.any(|value| value == self.branch.alpn()))
        {
            return None;
        }
        self.certificate_at(OffsetDateTime::now_utc()).ok()
    }
}

/// Independent trust, reconstructed only from the enrolled key and scope.
/// Do not append public/system roots or accept a root from the peer.
pub fn client_tls(scope: &Scope, public: [u8; 32], branch: Branch) -> Result<ClientConfig, Error> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Tls)?
            .with_root_certificates(pinned_roots(scope, public, branch)?)
            .with_no_client_auth();
    config.alpn_protocols = vec![branch.alpn().to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Connection-local admission input, derived exclusively from a verified
/// descriptor and independently provisioned secret. Debug must not print
/// either secret material or the admission field.
struct AdmissionInput {
    scope: Scope,
    public: [u8; 32],
    reference: String,
    branch: Branch,
    not_before: u64,
    not_after: u64,
    secret: Arc<crate::reality_admission::Secret>,
}

impl fmt::Debug for AdmissionInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionInput").field("branch", &self.branch).finish_non_exhaustive()
    }
}

impl AdmissionInput {
    fn new(value: &descriptor::Verified, branch: Branch,
        secret: Arc<crate::reality_admission::Secret>) -> Result<Self, Error> {
        let now = crate::reference_health::unix_now().map_err(|_| Error::Clock)?;
        value.check_time(now).map_err(|_| Error::Descriptor)?;
        let d = value.descriptor();
        let reference = d.references.get(usize::from(d.active_reference)).ok_or(Error::Descriptor)?;
        if branch == Branch::H3 && (!d.h3 || !reference.h3 || !value.effective_modes().h3) {
            return Err(Error::Descriptor);
        }
        if branch == Branch::H2 && !value.effective_modes().h2 {
            return Err(Error::Descriptor);
        }
        Ok(Self { scope: d.scope.clone(), public: value.signer(), reference: reference.server_name.clone(),
            branch, not_before: d.not_before, not_after: d.not_after, secret })
    }

    fn now(&self) -> Result<u64, rustls::Error> {
        let now = crate::reference_health::unix_now().map_err(|_| Self::refused())?;
        if now < self.not_before || now >= self.not_after { return Err(Self::refused()); }
        Ok(now)
    }

    fn context(&self) -> crate::reality_admission::Context<'_> {
        crate::reality_admission::Context {
            scope: &self.scope, identity: self.public, reference: &self.reference, branch: self.branch,
        }
    }

    fn refused() -> rustls::Error {
        rustls::Error::General("initial handshake refused".into())
    }
}

impl rustls::client::ClientHelloRandom for AdmissionInput {
    fn random(&self, handshake: &[u8]) -> Result<[u8;32], rustls::Error> {
        let mut hello = handshake.to_vec();
        crate::reality_admission::seal(&self.secret, &self.context(), &mut hello, self.now()?)
            .map_err(|_| Self::refused())?;
        hello.get(6..38).ok_or_else(Self::refused)?.try_into().map_err(|_| Self::refused())
    }
}

struct AdmissionCheck {
    input: AdmissionInput,
    guard: Arc<crate::reality_admission::ReplayGuard>,
}
impl fmt::Debug for AdmissionCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionCheck").finish_non_exhaustive()
    }
}
impl rustls::server::ClientHelloCheck for AdmissionCheck {
    fn check(&self, handshake: &[u8]) -> Result<(), rustls::Error> {
        self.guard.admit(&self.input.secret, &self.input.context(), handshake, self.input.now()?)
            .map_err(|_| AdmissionInput::refused())
    }
}

/// Construct the admitted TLS client. Its connection name must be the
/// signed reference SNI, and trust remains the independent Theia root.
pub fn admitted_client_tls(value: &descriptor::Verified, branch: Branch,
    secret: Arc<crate::reality_admission::Secret>) -> Result<ClientConfig, Error> {
    let input = AdmissionInput::new(value, branch, secret)?;
    let mut tls = client_tls(&input.scope, input.public, branch)?;
    tls.client_hello_random = Some(Arc::new(input));
    Ok(tls)
}

/// A checked TLS server for controlled transport tests. Failure aborts TLS,
/// so this is not a substitute for the external reference relay.
pub fn checked_server_tls(identity: &Identity, value: &descriptor::Verified, branch: Branch,
    secret: Arc<crate::reality_admission::Secret>, guard: Arc<crate::reality_admission::ReplayGuard>)
    -> Result<ServerConfig, Error> {
    let input = AdmissionInput::new(value, branch, secret)?;
    if identity.scope() != &input.scope || identity.public_key() != input.public {
        return Err(Error::Key);
    }
    let mut tls = identity.server_tls(&input.reference, branch)?;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.client_hello_check = Some(Arc::new(AdmissionCheck { input, guard }));
    Ok(tls)
}

pub fn admitted_quic_client(value: &descriptor::Verified,
    secret: Arc<crate::reality_admission::Secret>) -> Result<quinn::ClientConfig, Error> {
    let tls = admitted_client_tls(value, Branch::H3, secret)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Error::Tls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(crate::quic_transport::transport_config());
    Ok(config)
}

/// Controlled QUIC counterpart of checked_server_tls. It must not be
/// exposed as a production external inbound until datagram admission
/// and reference relay occur before endpoint acceptance.
pub fn checked_quic_server(identity: &Identity, value: &descriptor::Verified,
    secret: Arc<crate::reality_admission::Secret>, guard: Arc<crate::reality_admission::ReplayGuard>)
    -> Result<quinn::ServerConfig, Error> {
    let tls = checked_server_tls(identity, value, Branch::H3, secret, guard)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| Error::Tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(crate::quic_transport::transport_config());
    config.migration(false);
    Ok(config)
}

pub fn quic_client(scope: &Scope, public: [u8; 32]) -> Result<quinn::ClientConfig, Error> {
    let tls = client_tls(scope, public, Branch::H3)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Error::Tls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(crate::quic_transport::transport_config());
    Ok(config)
}

fn storage_error(error: WriteFailure) -> Error {
    match error {
        WriteFailure::BeforeReplace(_) => Error::Storage,
        WriteFailure::AfterReplace(_) => Error::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::time::Duration as StdDuration;
    use tokio::{
        net::{TcpListener, TcpStream},
        time::timeout,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn scope() -> Scope {
        Scope {
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
        }
    }

    #[test]
    fn renewable_leaf_is_cached_then_replaced_without_changing_identity() {
        let identity = Identity::generate(scope()).unwrap();
        let resolver = RenewingLeaf::new(&identity, "edge.example.org", Branch::H2).unwrap();
        let issued = resolver.leaf.lock().unwrap().issued_at;
        let initial = resolver.certificate_at(issued).unwrap();
        let cached = resolver
            .certificate_at(issued + Duration::seconds(LEAF_RENEWAL - 1))
            .unwrap();
        assert!(Arc::ptr_eq(&initial, &cached));
        let renewed_at = issued + Duration::seconds(LEAF_RENEWAL);
        let renewed = resolver.certificate_at(renewed_at).unwrap();
        assert!(!Arc::ptr_eq(&initial, &renewed));
        assert_ne!(initial.cert[0], renewed.cert[0]);
        assert_eq!(resolver.identity.public_key(), identity.public_key());
        assert!(resolver.certificate_at(issued).is_err());
        assert!(Arc::ptr_eq(
            &renewed,
            &resolver.certificate_at(renewed_at).unwrap()
        ));
    }

    #[test]
    fn anchor_encoding_matches_library_generated_issuer_and_separates_scope() {
        let identity = Identity::generate(scope()).unwrap();
        identity.issuer(Branch::H2).unwrap();
        identity.issuer(Branch::H3).unwrap();
        let h2 = pinned_roots(identity.scope(), identity.public_key(), Branch::H2).unwrap();
        let h3 = pinned_roots(identity.scope(), identity.public_key(), Branch::H3).unwrap();
        assert_ne!(h2.roots[0].subject.as_ref(), h3.roots[0].subject.as_ref());
        let mut foreign = scope();
        foreign.inbound = "other".into();
        let other = pinned_roots(&foreign, identity.public_key(), Branch::H2).unwrap();
        assert_ne!(
            h2.roots[0].subject.as_ref(),
            other.roots[0].subject.as_ref()
        );
        assert!(client_tls(&scope(), [0; 32], Branch::H2).is_err());
    }

    async fn tcp_attempt(server: ServerConfig, client: ClientConfig, name: &'static str) -> bool {
        timeout(StdDuration::from_secs(5), async {
            let acceptor = TlsAcceptor::from(Arc::new(server));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let worker = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                acceptor.accept(tcp).await.is_ok()
            });
            let connector = TlsConnector::from(Arc::new(client));
            let tcp = TcpStream::connect(address).await.unwrap();
            let result = connector
                .connect(ServerName::try_from(name).unwrap(), tcp)
                .await;
            let success = result.is_ok();
            if let Ok(stream) = &result {
                assert_eq!(
                    stream.get_ref().1.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
                assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            }
            assert_eq!(worker.await.unwrap(), success);
            success
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_full_tls_handshake_requires_independent_key_scope_name_and_validity() {
        let identity = Identity::generate(scope()).unwrap();
        let public = identity.public_key();
        let name = "edge.example.org";
        let server = || identity.server_tls(name, Branch::H2).unwrap();
        let client = || client_tls(&scope(), public, Branch::H2).unwrap();
        assert!(tcp_attempt(server(), client(), name).await);
        let other = Identity::generate(scope()).unwrap();
        assert!(
            !tcp_attempt(
                server(),
                client_tls(&scope(), other.public_key(), Branch::H2).unwrap(),
                name
            )
            .await
        );
        let mut foreign = scope();
        foreign.inbound = "different".into();
        assert!(
            !tcp_attempt(
                server(),
                client_tls(&foreign, public, Branch::H2).unwrap(),
                name
            )
            .await
        );
        assert!(!tcp_attempt(server(), client(), "wrong.example.org").await);
        let expired = OffsetDateTime::now_utc() - Duration::seconds(LEAF_LIFETIME + 600);
        let old_server = identity.server_tls_at(name, Branch::H2, expired).unwrap();
        assert!(!tcp_attempt(old_server, client(), name).await);
        let h3_leaf = identity
            .leaf(name, Branch::H3, OffsetDateTime::now_utc())
            .unwrap();
        let mut wrong_branch =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![h3_leaf.0], h3_leaf.1)
                .unwrap();
        wrong_branch.alpn_protocols = vec![b"h2".to_vec()];
        assert!(!tcp_attempt(wrong_branch, client(), name).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h3_full_quic_handshake_accepts_only_the_independent_identity() {
        timeout(StdDuration::from_secs(15), async {
            let identity = Identity::generate(scope()).unwrap();
            let wrong = Identity::generate(scope()).unwrap();
            let endpoint = quinn::Endpoint::server(
                identity.quic_server("edge.example.org").unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let remote = endpoint.local_addr().unwrap();
            let worker = tokio::spawn(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = crate::quic_transport::accept(incoming).await.unwrap();
                let _ = connection.closed().await;
            });
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(quic_client(&scope(), identity.public_key()).unwrap());
            let connection = crate::quic_transport::connect(&client, remote, "edge.example.org")
                .await
                .unwrap();
            connection.close(0u32.into(), b"test done");
            worker.await.unwrap();

            let endpoint = quinn::Endpoint::server(
                identity.quic_server("edge.example.org").unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let remote = endpoint.local_addr().unwrap();
            let worker = tokio::spawn(async move {
                let incoming = endpoint.accept().await.unwrap();
                assert!(crate::quic_transport::accept(incoming).await.is_err());
            });
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(quic_client(&scope(), wrong.public_key()).unwrap());
            assert!(
                crate::quic_transport::connect(&client, remote, "edge.example.org")
                    .await
                    .is_err()
            );
            worker.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn identity_key_is_create_only_and_bound_to_scope_across_restart() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-identity-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("identity");
        let identity = Identity::generate(scope()).unwrap();
        identity.save_new(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let other = Identity::generate(scope()).unwrap();
        assert!(other.save_new(&path).is_err());
        let restored = Identity::load(&path, &scope()).unwrap();
        assert_eq!(restored.public_key(), identity.public_key());
        let mut foreign = scope();
        foreign.inbound = "other".into();
        assert!(matches!(Identity::load(&path, &foreign), Err(Error::Scope)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
