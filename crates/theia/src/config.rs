//! Strict, typed TOML v1 schema and validation. This module has no network or
//! OS proxy side effects. Secret references are checked syntactically, never read.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: usize = 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub field: String,
    pub reason: &'static str,
}

impl ConfigError {
    pub(crate) fn new(field: impl Into<String>, reason: &'static str) -> Self {
        Self {
            field: field.into(),
            reason,
        }
    }
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}
impl std::error::Error for ConfigError {}

type Check = Result<(), ConfigError>;
fn ensure(ok: bool, field: impl Into<String>, reason: &'static str) -> Check {
    if ok {
        Ok(())
    } else {
        Err(ConfigError::new(field, reason))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Config {
    Server(ServerDocument),
    Client(ClientDocument),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerDocument {
    pub schema_version: u32,
    pub server: ServerSettings,
    pub management: Management,
    pub ui: Ui,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDocument {
    pub schema_version: u32,
    pub client: ClientSettings,
    pub management: Management,
    pub ui: Ui,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub enabled: bool,
    pub inbounds: Vec<Inbound>,
    pub users: Vec<User>,
    pub policy: ServerPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub security_mode: crate::security_profile::SecurityMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityBinding>,
    pub allowed_user_ids: Vec<String>,
    pub quic_listen: String,
    pub h2_listen: String,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls_cert: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls_key: String,
}

/// Private local paths and initial owner-confirmed enrollment root.
/// No bearer, key bytes or reference private material is stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityBinding {
    pub health_store: String,
    pub bundle: String,
    pub initial_health_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
}
impl RealityBinding {
    fn valid(&self) -> bool {
        self.initial_health_sha256 != [0; 32]
            && self.identity_sha256 != [0; 32]
            && self.manifest_sha256 != [0; 32]
            && self.health_store != self.bundle
            && [&self.health_store, &self.bundle].into_iter().all(|p| {
                crate::bounded_input::explicit_file_path(Path::new(p))
                    && !p.chars().any(char::is_control)
            })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub token_sha256: String,
    pub disabled: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPolicy {
    pub allow_private_ips: bool,
    pub max_connections_per_user: u32,
    pub max_connections_total: u32,
    pub connect_timeout_ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<crate::routing::Settings>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub active_profile: String,
    #[serde(default)]
    pub ingress_mode: IngressMode,
    pub profiles: Vec<Profile>,
    pub proxy: LocalProxy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    pub server: String,
    pub server_name: String,
    pub auth_token: String,
    pub security_mode: crate::security_profile::SecurityMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_profile: Option<RealityClientBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_mode: Option<XhttpMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<String>,
    pub transport: Transport,
    pub quic_connect_timeout_ms: u32,
    pub quic_negative_cache_ttl_s: u32,
    /// Local consent for this profile, never supplied by an invitation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_dpi: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_dpi_stun: Option<bool>,
}
/// The imported root is immutable even as the separate signed trust
/// history advances. Pin the exact enrollment bytes and independent root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityClientBinding {
    pub enrollment: String,
    pub enrollment_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
}
impl RealityClientBinding {
    fn valid(&self) -> bool {
        self.enrollment_sha256 != [0; 32]
            && self.identity_sha256 != [0; 32]
            && crate::bounded_input::explicit_file_path(Path::new(&self.enrollment))
            && !self.enrollment.chars().any(char::is_control)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Auto,
    H3,
    H2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    Auto,
    StreamOne,
    StreamUp,
}

impl Profile {
    /// Both supported security modes use the same XHTTP selection.
    pub fn effective_xhttp_mode(&self) -> XhttpMode {
        self.xhttp_mode.unwrap_or(XhttpMode::Auto)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProxy {
    pub http_listen: String,
    pub socks5_listen: String,
}

/// Saved ingress selection, not an instruction to change OS settings.
/// Future TUN and packet modes are deliberately rejected by the MVP parser.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    #[default]
    SystemProxy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Management {
    pub ipc: String,
    pub log_level: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    pub language: String,
}

/// Parse a complete UTF-8 document. A generic parser error is intentional:
/// TOML error excerpts may include bearer tokens or other secret values.
pub fn parse(source: &str) -> Result<Config, ConfigError> {
    ensure(
        source.len() <= MAX_BYTES,
        "document",
        "configuration exceeds 1 MiB",
    )?;
    let table: toml::Table = toml::from_str(source)
        .map_err(|_| ConfigError::new("document", "invalid TOML syntax or duplicate key"))?;
    let has_server = table.contains_key("server");
    let has_client = table.contains_key("client");
    ensure(
        has_server ^ has_client,
        "document",
        "exactly one of server or client is required",
    )?;
    // Report only the safe structural field name, never the raw TOML
    // value. Both roles use the same enum and reject retired aliases.
    let (role, records) = if has_server {
        ("server", "inbounds")
    } else {
        ("client", "profiles")
    };
    if let Some(entries) = table
        .get(role)
        .and_then(|section| section.get(records))
        .and_then(toml::Value::as_array)
    {
        for (index, record) in entries.iter().enumerate() {
            if let Some(mode) = record.get("security_mode") {
                ensure(
                    mode.as_str()
                        .and_then(crate::security_profile::SecurityMode::from_product_name)
                        .is_some(),
                    format!("{role}.{records}[{index}].security_mode"),
                    "only own-tls and smart-reality are supported",
                )?;
            }
        }
    }
    let config = if has_server {
        Config::Server(toml::from_str(source).map_err(|_| {
            ConfigError::new(
                "document",
                "invalid server schema, unknown field or field type",
            )
        })?)
    } else {
        Config::Client(toml::from_str(source).map_err(|_| {
            ConfigError::new(
                "document",
                "invalid client schema, unknown field or field type",
            )
        })?)
    };
    config.validate()?;
    Ok(config)
}

pub fn read_file(path: &Path) -> Result<Config, ConfigError> {
    let buf = crate::bounded_input::read(path, MAX_BYTES as u64, false, false)
        .map_err(|_| ConfigError::new("config", "cannot read bounded configuration file"))?;
    let text = std::str::from_utf8(&buf)
        .map_err(|_| ConfigError::new("document", "configuration is not UTF-8"))?;
    parse(text)
}

impl Config {
    pub fn validate(&self) -> Check {
        match self {
            Self::Server(doc) => doc.validate(),
            Self::Client(doc) => doc.validate(),
        }
    }
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        self.validate()?;
        let result = match self {
            Self::Server(doc) => toml::to_string_pretty(doc),
            Self::Client(doc) => toml::to_string_pretty(doc),
        }
        .map_err(|_| ConfigError::new("document", "cannot serialize configuration"))?;
        // Double validation guards against accidental changes in serialization semantics.
        parse(&result)?;
        Ok(result)
    }
}

pub(crate) fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub(crate) fn valid_dns(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
fn valid_file_ref(raw: &str) -> bool {
    let Some(path) = raw.strip_prefix("file:") else {
        return false;
    };
    let path = Path::new(path);
    (path.is_absolute() || path.to_string_lossy().starts_with('/'))
        && !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        && !raw.contains(['\n', '\r', '\0'])
}
pub(crate) fn valid_secret_ref(raw: &str) -> bool {
    if valid_file_ref(raw) {
        return true;
    }
    let Some(var) = raw.strip_prefix("env:") else {
        return false;
    };
    let b = var.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}
fn listen(raw: &str, path: &str) -> Result<SocketAddr, ConfigError> {
    raw.parse::<SocketAddr>()
        .map_err(|_| ConfigError::new(path, "expected IP address and nonzero port"))
        .and_then(|addr| {
            ensure(addr.port() != 0, path, "port must be nonzero")?;
            Ok(addr)
        })
}
fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() {
        return false;
    }
    if a.ip() == b.ip() {
        return true;
    }
    match (a.ip(), b.ip()) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x == Ipv4Addr::UNSPECIFIED || y == Ipv4Addr::UNSPECIFIED,
        (IpAddr::V6(x), IpAddr::V6(y)) => x == Ipv6Addr::UNSPECIFIED || y == Ipv6Addr::UNSPECIFIED,
        (IpAddr::V6(x), IpAddr::V4(_)) | (IpAddr::V4(_), IpAddr::V6(x)) => {
            x == Ipv6Addr::UNSPECIFIED
        }
    }
}
pub(crate) fn validate_shared(schema: u32, m: &Management, ui: &Ui) -> Check {
    ensure(schema == 1, "schema_version", "only version 1 is supported")?;
    ensure(m.ipc == "auto", "management.ipc", "only auto is supported")?;
    ensure(
        matches!(
            m.log_level.as_str(),
            "error" | "warn" | "info" | "debug" | "trace"
        ),
        "management.log_level",
        "unknown log level",
    )?;
    ensure(
        matches!(ui.language.as_str(), "ru" | "en"),
        "ui.language",
        "unknown language",
    )
}

impl ServerDocument {
    fn validate(&self) -> Check {
        validate_shared(self.schema_version, &self.management, &self.ui)?;
        ensure(
            !self.server.users.is_empty(),
            "server.users",
            "at least one user is required",
        )?;
        ensure(
            !self.server.inbounds.is_empty(),
            "server.inbounds",
            "at least one inbound is required",
        )?;
        let mut user_ids = HashSet::new();
        let mut token_digests = HashSet::new();
        for (i, user) in self.server.users.iter().enumerate() {
            let field = format!("server.users[{i}]");
            ensure(valid_id(&user.id), format!("{field}.id"), "invalid user ID")?;
            ensure(
                user_ids.insert(user.id.as_str()),
                format!("{field}.id"),
                "duplicate user ID",
            )?;
            ensure(
                user.token_sha256.len() == 64
                    && user
                        .token_sha256
                        .bytes()
                        .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)),
                format!("{field}.token_sha256"),
                "expected 64 lowercase hex digits",
            )?;
            ensure(
                token_digests.insert(user.token_sha256.as_str()),
                format!("{field}.token_sha256"),
                "duplicate token digest",
            )?;
        }
        let mut inbound_ids = HashSet::new();
        let mut udp_listeners = Vec::new();
        let mut tcp_listeners = Vec::new();
        for (i, inbound) in self.server.inbounds.iter().enumerate() {
            let field = format!("server.inbounds[{i}]");
            ensure(
                valid_id(&inbound.id),
                format!("{field}.id"),
                "invalid inbound ID",
            )?;
            ensure(
                inbound_ids.insert(inbound.id.as_str()),
                format!("{field}.id"),
                "duplicate inbound ID",
            )?;
            ensure(
                !inbound.allowed_user_ids.is_empty(),
                format!("{field}.allowed_user_ids"),
                "explicit grant list must not be empty",
            )?;
            let mut grants = HashSet::new();
            for user_id in &inbound.allowed_user_ids {
                ensure(
                    user_ids.contains(user_id.as_str()),
                    format!("{field}.allowed_user_ids"),
                    "unknown user grant",
                )?;
                ensure(
                    grants.insert(user_id),
                    format!("{field}.allowed_user_ids"),
                    "duplicate user grant",
                )?;
            }
            let udp = listen(&inbound.quic_listen, &format!("{field}.quic_listen"))?;
            let tcp = listen(&inbound.h2_listen, &format!("{field}.h2_listen"))?;
            let reality =
                inbound.security_mode == crate::security_profile::SecurityMode::SmartReality;
            ensure(
                reality || inbound.security_mode.is_plain(),
                format!("{field}.security_mode"),
                "only own TLS and smart-reality are supported",
            )?;
            ensure(
                if reality {
                    inbound.path_prefix.is_none()
                } else {
                    inbound
                        .path_prefix
                        .as_deref()
                        .is_some_and(crate::split_http::valid_prefix)
                },
                format!("{field}.path_prefix"),
                "own TLS requires an explicit /v1/<prefix>; REALITY uses the signed descriptor",
            )?;
            if reality {
                ensure(
                    inbound.reality.as_ref().is_some_and(RealityBinding::valid),
                    format!("{field}.reality"),
                    "approved REALITY bundle and trust root required",
                )?;
                ensure(
                    inbound.tls_cert.is_empty() && inbound.tls_key.is_empty(),
                    format!("{field}.tls_cert"),
                    "own-TLS material prohibited in REALITY",
                )?;
                ensure(
                    tcp == udp,
                    format!("{field}.quic_listen"),
                    "REALITY requires one TCP/UDP listen address and port",
                )?;
                ensure(
                    valid_remote(&format!("{}:{}", inbound.server_name, tcp.port())),
                    format!("{field}.server_name"),
                    "REALITY endpoint host is invalid",
                )?;
            } else {
                ensure(
                    inbound.reality.is_none(),
                    format!("{field}.reality"),
                    "REALITY material prohibited in own TLS",
                )?;
                ensure(
                    valid_dns(&inbound.server_name),
                    format!("{field}.server_name"),
                    "invalid DNS name",
                )?;
                ensure(
                    valid_file_ref(&inbound.tls_cert),
                    format!("{field}.tls_cert"),
                    "expected absolute file: reference",
                )?;
                ensure(
                    valid_file_ref(&inbound.tls_key),
                    format!("{field}.tls_key"),
                    "expected absolute file: reference",
                )?;
            }
            ensure(
                !udp_listeners.iter().any(|x| overlaps(*x, udp)),
                format!("{field}.quic_listen"),
                "UDP listener overlaps another inbound",
            )?;
            ensure(
                !tcp_listeners.iter().any(|x| overlaps(*x, tcp)),
                format!("{field}.h2_listen"),
                "TCP listener overlaps another inbound",
            )?;
            udp_listeners.push(udp);
            tcp_listeners.push(tcp);
        }
        let p = &self.server.policy;
        if let Some(routing) = &p.routing {
            routing.validate().map_err(|_| {
                ConfigError::new("server.policy.routing", "invalid routing settings")
            })?;
        }
        ensure(
            p.max_connections_per_user > 0,
            "server.policy.max_connections_per_user",
            "must be positive",
        )?;
        ensure(
            p.max_connections_total > 0,
            "server.policy.max_connections_total",
            "must be positive",
        )?;
        ensure(
            p.max_connections_per_user <= p.max_connections_total,
            "server.policy.max_connections_per_user",
            "must not exceed total connection cap",
        )?;
        ensure(
            p.connect_timeout_ms > 0,
            "server.policy.connect_timeout_ms",
            "must be positive",
        )
    }
}
pub(crate) fn valid_remote(raw: &str) -> bool {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return addr.port() > 0 && !addr.ip().is_unspecified();
    }
    let Some((name, port)) = raw.rsplit_once(':') else {
        return false;
    };
    valid_dns(name) && port.parse::<u16>().is_ok_and(|p| p != 0)
}
impl ClientDocument {
    fn validate(&self) -> Check {
        validate_shared(self.schema_version, &self.management, &self.ui)?;
        ensure(
            !self.client.profiles.is_empty(),
            "client.profiles",
            "at least one profile is required",
        )?;
        let mut ids = HashSet::new();
        for (i, profile) in self.client.profiles.iter().enumerate() {
            let field = format!("client.profiles[{i}]");
            ensure(
                valid_id(&profile.id),
                format!("{field}.id"),
                "invalid profile ID",
            )?;
            ensure(
                ids.insert(profile.id.as_str()),
                format!("{field}.id"),
                "duplicate profile ID",
            )?;
            ensure(
                valid_remote(&profile.server),
                format!("{field}.server"),
                "invalid host:port or [IPv6]:port",
            )?;
            ensure(
                valid_secret_ref(&profile.auth_token),
                format!("{field}.auth_token"),
                "expected env:NAME or absolute file: reference",
            )?;
            ensure(
                profile.tls_ca.as_ref().is_none_or(|path| {
                    valid_file_ref(path) || crate::own_tls::Anchor::parse(path).is_some()
                }),
                format!("{field}.tls_ca"),
                "expected absolute PEM CA reference or canonical pinned anchor",
            )?;
            ensure(
                if profile.security_mode == crate::security_profile::SecurityMode::SmartReality {
                    profile.path_prefix.is_none()
                } else {
                    profile
                        .path_prefix
                        .as_deref()
                        .is_some_and(crate::split_http::valid_prefix)
                },
                format!("{field}.path_prefix"),
                "own TLS requires an explicit /v1/<prefix>; REALITY uses the signed descriptor",
            )?;
            if profile.security_mode == crate::security_profile::SecurityMode::SmartReality {
                ensure(
                    profile
                        .reality_profile
                        .as_ref()
                        .is_some_and(RealityClientBinding::valid),
                    format!("{field}.reality_profile"),
                    "pinned private REALITY enrollment required",
                )?;
                ensure(
                    profile
                        .server
                        .rsplit_once(':')
                        .is_some_and(|(host, _)| host == profile.server_name),
                    format!("{field}.server_name"),
                    "REALITY server_name is the endpoint host, not reference SNI",
                )?;
                ensure(
                    profile.tls_ca.is_none(),
                    format!("{field}.tls_ca"),
                    "own-TLS CA prohibited in REALITY",
                )?;
            } else {
                ensure(
                    profile.reality_profile.is_none(),
                    format!("{field}.reality_profile"),
                    "REALITY enrollment prohibited in own TLS",
                )?;
                ensure(
                    valid_dns(&profile.server_name),
                    format!("{field}.server_name"),
                    "invalid TLS server name",
                )?;
                ensure(
                    profile.security_mode.is_plain(),
                    format!("{field}.security_mode"),
                    "only own-tls and smart-reality are supported",
                )?;
            }
            ensure(
                (500..=15_000).contains(&profile.quic_connect_timeout_ms),
                format!("{field}.quic_connect_timeout_ms"),
                "must be within 500..=15000",
            )?;
            ensure(
                profile.direct_dpi_stun != Some(true) || profile.direct_dpi == Some(true),
                format!("{field}.direct_dpi_stun"),
                "requires explicit direct_dpi consent",
            )?;
            ensure(
                profile.quic_negative_cache_ttl_s <= 86_400,
                format!("{field}.quic_negative_cache_ttl_s"),
                "must be within 0..=86400",
            )?;
        }
        ensure(
            ids.contains(self.client.active_profile.as_str()),
            "client.active_profile",
            "unknown profile",
        )?;
        validate_proxy(&self.client.proxy, "client.proxy")
    }
}

/// Both client roles must enforce identical listener constraints.
pub(crate) fn validate_proxy(proxy: &LocalProxy, field: &str) -> Check {
    let http_field = format!("{field}.http_listen");
    let socks_field = format!("{field}.socks5_listen");
    let http = listen(&proxy.http_listen, &http_field)?;
    let socks = listen(&proxy.socks5_listen, &socks_field)?;
    for (address, field) in [(http, http_field), (socks, socks_field)] {
        ensure(
            matches!(
                address.ip(),
                IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)
            ),
            field,
            "listener must bind to 127.0.0.1 or [::1]",
        )?;
    }
    ensure(
        http != socks,
        field,
        "HTTP and SOCKS5 listener addresses must differ",
    )
}

/// Distinguish refusal before replacement from uncertain durability after
/// replacement. A credential referenced by a possibly published document must
/// not be deleted by rollback.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteFailure {
    BeforeReplace(ConfigError),
    AfterReplace(ConfigError),
}

impl From<ConfigError> for WriteFailure {
    fn from(error: ConfigError) -> Self {
        Self::BeforeReplace(error)
    }
}

impl WriteFailure {
    fn into_error(self) -> ConfigError {
        match self {
            Self::BeforeReplace(error) | Self::AfterReplace(error) => error,
        }
    }
}

pub(crate) fn editor_bytes(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = crate::bounded_input::read(path, MAX_BYTES as u64, false, false)
        .map_err(|_| ConfigError::new("config", "missing or unsafe configuration file"))?;
    Ok(std::mem::take(&mut *bytes))
}

fn require_unchanged(path: &Path, expected: &[u8]) -> Check {
    ensure(
        editor_bytes(path).is_ok_and(|bytes| bytes == expected),
        "config",
        "file changed externally; reload before saving",
    )
}

// Stable sidecar inode: never unlink it on unlock. OS handle closure releases
// the advisory lock even if a cooperating editor exits without unwinding.
// All callers must use a trusted directory; this is not a lock against
// arbitrary external writers or hostile path replacement.
pub(crate) fn lock_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let name = path
        .file_name()
        .ok_or_else(|| ConfigError::new("config", "destination file name is missing"))?;
    let mut lock = std::ffi::OsString::from(".");
    lock.push(name);
    lock.push(".theia.lock");
    Ok(path.with_file_name(lock))
}

pub(crate) fn editor_lock(path: &Path) -> Result<fs::File, ConfigError> {
    let path = lock_path(path)?;
    let error = || ConfigError::new("config", "editor lock busy or unsafe; retry");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    crate::bounded_input::no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| error())?;
    let meta = file.metadata().map_err(|_| error())?;
    if !crate::bounded_input::regular_file(&meta) || meta.len() != 0 {
        return Err(error());
    }
    file.try_lock().map_err(|_| error())?;
    Ok(file)
}

/// Validate and atomically replace a TOML file, without an editor revision.
/// Callers must supply a trusted destination directory.
pub fn atomic_write(path: &Path, config: &Config) -> Result<(), ConfigError> {
    let data = config.to_toml()?;
    atomic_write_bytes(path, &data, None, false, sync_directory).map_err(WriteFailure::into_error)
}

/// Cooperating editor writes are serialized across threads and processes.
/// Check the original bytes under the lock and again just before rename.
pub(crate) fn guarded_write(
    path: &Path,
    config: &Config,
    expected: &[u8],
) -> Result<Vec<u8>, WriteFailure> {
    guarded_write_with_sync(path, config, expected, sync_directory)
}

fn guarded_write_with_sync(
    path: &Path,
    config: &Config,
    expected: &[u8],
    sync_parent: impl FnOnce(&Path) -> Check,
) -> Result<Vec<u8>, WriteFailure> {
    let data = config.to_toml()?;
    let _lock = editor_lock(path)?;
    require_unchanged(path, expected)?;
    atomic_write_bytes(path, &data, Some(expected), false, sync_parent)?;
    Ok(data.into_bytes())
}

/// Signed trust snapshots share the same cooperating CAS lock and atomic
/// publication as config. None is an explicit create-only operation, never
/// an overwrite. The caller must validate the whole document before use.
/// Linearize a no-op trust update against cooperating writers without
/// replacing the file. The caller must have already checked its contents.
pub(crate) fn guarded_trust_assert(path: &Path, expected: &[u8]) -> Result<(), ConfigError> {
    let _lock = editor_lock(path)?;
    require_unchanged(path, expected)
}

/// Validate and publish a first configuration without replacing any existing file.
pub(crate) fn guarded_create(path: &Path, config: &Config) -> Result<(), WriteFailure> {
    let data = config.to_toml()?;
    let _lock = editor_lock(path)?;
    atomic_write_bytes(path, &data, None, true, sync_directory)
}

pub(crate) fn guarded_trust_write(
    path: &Path,
    data: &str,
    expected: Option<&[u8]>,
) -> Result<(), WriteFailure> {
    let _lock = editor_lock(path)?;
    if let Some(expected) = expected {
        require_unchanged(path, expected)?;
    }
    atomic_write_bytes(path, data, expected, expected.is_none(), sync_directory)
}

fn sync_directory(parent: &Path) -> Check {
    #[cfg(unix)]
    {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ConfigError::new("config", "cannot sync directory"))?;
    }
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

fn atomic_write_bytes(
    path: &Path,
    data: &str,
    expected: Option<&[u8]>,
    create_only: bool,
    sync_parent: impl FnOnce(&Path) -> Check,
) -> Result<(), WriteFailure> {
    ensure(
        data.len() <= MAX_BYTES,
        "document",
        "configuration exceeds 1 MiB",
    )?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| ConfigError::new("config", "destination file name is missing"))?;
    let mut pending = None;
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = std::ffi::OsString::from(".");
        temp_name.push(name);
        temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temp = parent.join(temp_name);
        #[cfg(windows)]
        let opened = crate::client_import::new_private_file(&temp);
        #[cfg(not(windows))]
        let opened = {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&temp)
        };
        match opened {
            Ok(file) => {
                pending = Some((temp, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(
                    ConfigError::new("config", "cannot create temporary config file").into(),
                );
            }
        }
    }
    let (temp, mut file) =
        pending.ok_or_else(|| ConfigError::new("config", "cannot allocate temporary file"))?;
    let result = (|| -> Result<(), WriteFailure> {
        file.write_all(data.as_bytes())
            .map_err(|_| ConfigError::new("config", "cannot write temporary file"))?;
        file.sync_all()
            .map_err(|_| ConfigError::new("config", "cannot sync temporary file"))?;
        drop(file);
        if let Some(expected) = expected {
            require_unchanged(path, expected)?;
        }
        if create_only {
            // Link a complete synced inode without replacing an existing
            // pathname (including a symlink). Unsupported filesystems refuse.
            fs::hard_link(&temp, path)
                .map_err(|_| ConfigError::new("config", "cannot publish new trust snapshot"))?;
            fs::remove_file(&temp).map_err(|_| {
                WriteFailure::AfterReplace(ConfigError::new(
                    "config",
                    "cannot remove published temporary link",
                ))
            })?;
        } else {
            fs::rename(&temp, path).map_err(|_| {
                ConfigError::new("config", "cannot atomically replace configuration")
            })?;
        }
        sync_parent(parent).map_err(WriteFailure::AfterReplace)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// The caller supplies a path; never copy it into diagnostics (it may be secret).
pub fn config_path(path: &str) -> PathBuf {
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> String {
        include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64))
    }
    fn client() -> String {
        include_str!("../../../examples/client.toml").to_owned()
    }
    #[test]
    fn server_and_client_parse_and_round_trip() {
        for source in [server(), client()] {
            let parsed = parse(&source).expect("valid template after digest replacement");
            let serialized = parsed.to_toml().unwrap();
            assert_eq!(parse(&serialized).unwrap(), parsed);
        }
    }
    #[test]
    fn canonical_product_security_names_and_retired_aliases() {
        for source in [server(), client()] {
            let parsed = parse(&source).unwrap();
            let canonical = parsed.to_toml().unwrap();
            assert!(canonical.contains("security_mode = \"own-tls\""));
            assert_eq!(parse(&canonical).unwrap(), parsed);
            for retired in ["plain", "default", "pinned-cert-v1", "browser-h2-btls-v1"] {
                let invalid = canonical.replace(
                    "security_mode = \"own-tls\"",
                    &format!("security_mode = \"{retired}\""),
                );
                assert_ne!(invalid, canonical);
                assert!(parse(&invalid).is_err());
            }
            let old_field =
                canonical.replace("security_mode = \"own-tls\"", "tls_profile = \"default\"");
            assert!(parse(&old_field).is_err());
        }
    }

    #[test]
    fn own_tls_requires_explicit_valid_prefix() {
        for source in [server(), client()] {
            for bad in ["", "/v1/", "/v1/a/b", "/v1/../x", "/v1/a?b", "/v1/a%2fb"] {
                let invalid = source.replace("/v1/theia-example", bad);
                assert!(parse(&invalid).unwrap_err().field.contains("path_prefix"));
            }
            let missing = source
                .lines()
                .filter(|line| !line.starts_with("path_prefix = "))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(parse(&missing).unwrap_err().field.contains("path_prefix"));
        }
    }

    #[test]
    fn server_denies_invalid_ids_digests_and_grants() {
        let original = server();
        for (from, to, expected) in [
            (
                "allowed_user_ids = [\"device-a\"]",
                "allowed_user_ids = []",
                "allowed_user_ids",
            ),
            (
                "allowed_user_ids = [\"device-a\"]",
                "allowed_user_ids = [\"missing\"]",
                "allowed_user_ids",
            ),
            (
                "allowed_user_ids = [\"device-a\"]",
                "allowed_user_ids = [\"device-a\", \"device-a\"]",
                "allowed_user_ids",
            ),
            ("id = \"public\"", "id = \"bad id\"", "id"),
            (
                "token_sha256 = \"",
                "token_sha256 = \"UPPER",
                "token_sha256",
            ),
            (
                "max_connections_total = 1024",
                "max_connections_total = 0",
                "max_connections_total",
            ),
        ] {
            let changed = original.replacen(from, to, 1);
            assert!(
                parse(&changed).unwrap_err().field.contains(expected),
                "{expected}"
            );
        }
    }
    #[test]
    fn own_tls_xhttp_mode_defaults_to_auto_and_is_strict() {
        let original = client();
        let Config::Client(defaults) = parse(&original).unwrap() else {
            panic!("client");
        };
        assert_eq!(
            defaults.client.profiles[0].effective_xhttp_mode(),
            XhttpMode::Auto
        );
        for (raw, mode) in [
            ("auto", XhttpMode::Auto),
            ("stream-one", XhttpMode::StreamOne),
            ("stream-up", XhttpMode::StreamUp),
        ] {
            let explicit = original.replacen(
                "security_mode = \"own-tls\"",
                &format!("security_mode = \"own-tls\"\nxhttp_mode = \"{raw}\""),
                1,
            );
            let accepted = parse(&explicit).unwrap();
            let Config::Client(doc) = &accepted else {
                panic!("client");
            };
            assert_eq!(doc.client.profiles[0].xhttp_mode, Some(mode));
            assert_eq!(parse(&accepted.to_toml().unwrap()).unwrap(), accepted);
            let pinned = explicit.replace(
                "security_mode = \"own-tls\"",
                &format!("security_mode = \"pinned-cert-v1:{}\"", "42".repeat(32)),
            );
            assert!(parse(&pinned).unwrap_err().field.contains("security_mode"));
        }
        let invalid = original.replacen(
            "security_mode = \"own-tls\"",
            "security_mode = \"own-tls\"\nxhttp_mode = \"guess\"",
            1,
        );
        assert!(parse(&invalid).is_err());
    }

    #[test]
    fn local_stun_requires_separate_explicit_consent() {
        let original = client();
        let Config::Client(default) = parse(&original).unwrap() else {
            panic!("client");
        };
        assert_ne!(default.client.profiles[0].direct_dpi_stun, Some(true));
        let stun_only = original.replacen(
            "quic_negative_cache_ttl_s = 900",
            "quic_negative_cache_ttl_s = 900\ndirect_dpi_stun = true",
            1,
        );
        assert_eq!(
            parse(&stun_only).unwrap_err().field,
            "client.profiles[0].direct_dpi_stun"
        );
        let consent = original.replacen(
            "quic_negative_cache_ttl_s = 900",
            "quic_negative_cache_ttl_s = 900\ndirect_dpi = true\ndirect_dpi_stun = true",
            1,
        );
        let accepted = parse(&consent).unwrap();
        let Config::Client(doc) = &accepted else {
            panic!("client");
        };
        assert_eq!(doc.client.profiles[0].direct_dpi_stun, Some(true));
        assert_eq!(parse(&accepted.to_toml().unwrap()).unwrap(), accepted);
    }

    #[test]
    fn ingress_defaults_and_legacy_proxy_keys_are_rejected() {
        let original = client();
        let omitted = original.replace("ingress_mode = \"system_proxy\"\n", "");
        let Config::Client(doc) = parse(&omitted).unwrap() else {
            panic!("client")
        };
        assert_eq!(doc.client.ingress_mode, IngressMode::SystemProxy);
        for mode in ["tun", "packet", "off", "manual", "system-proxy"] {
            let input = original.replace(
                "ingress_mode = \"system_proxy\"",
                &format!("ingress_mode = \"{mode}\""),
            );
            assert!(parse(&input).is_err(), "{mode}");
        }
        for key in [
            "system_proxy = \"off\"",
            "system_proxy = \"manual\"",
            "direct_dpi = true",
            "direct_dpi_stun = true",
        ] {
            let input = original.replace("[client.proxy]", &format!("[client.proxy]\n{key}"));
            assert!(parse(&input).is_err(), "{key}");
        }
    }

    #[test]
    fn rejects_unsafe_client_settings() {
        let original = client();
        for (from, to, expected) in [
            (
                "ingress_mode = \"system_proxy\"",
                "ingress_mode = \"tun\"",
                "document",
            ),
            (
                "http_listen = \"127.0.0.1:7890\"",
                "http_listen = \"0.0.0.0:7890\"",
                "http_listen",
            ),
            (
                "socks5_listen = \"127.0.0.1:7891\"",
                "socks5_listen = \"127.0.0.1:7890\"",
                "client.proxy",
            ),
            (
                "security_mode = \"own-tls\"",
                "security_mode = \"chrome133\"",
                "security_mode",
            ),
            (
                "auth_token = \"env:THEIA_AUTH_TOKEN\"",
                "auth_token = \"literal-secret\"",
                "auth_token",
            ),
            (
                "quic_connect_timeout_ms = 1600",
                "quic_connect_timeout_ms = 499",
                "quic_connect_timeout_ms",
            ),
            (
                "active_profile = \"home\"",
                "active_profile = \"missing\"",
                "active_profile",
            ),
        ] {
            let changed = original.replacen(from, to, 1);
            assert!(
                parse(&changed).unwrap_err().field.contains(expected),
                "{expected}"
            );
        }
    }
    #[test]
    fn retired_security_modes_are_rejected_even_with_experimental_backend() {
        let source = client();
        for mode in [
            "browser-h2-btls-v1".into(),
            format!("pinned-cert-v1:{}", "42".repeat(32)),
            format!("pinned-cert-stream-up-v1:{}", "42".repeat(32)),
        ] {
            for transport in ["h2", "h3", "auto"] {
                let bad = source
                    .replace(
                        "security_mode = \"own-tls\"",
                        &format!("security_mode = \"{mode}\""),
                    )
                    .replace(
                        "transport = \"auto\"",
                        &format!("transport = \"{transport}\""),
                    );
                assert!(parse(&bad).is_err());
            }
        }
        for mode in ["pinned-cert-v1", "pinned-cert-stream-up-v1"] {
            let bad = server().replace(
                "security_mode = \"own-tls\"",
                &format!("security_mode = \"{mode}\""),
            );
            assert!(parse(&bad).is_err());
        }
    }

    #[test]
    fn unknown_keys_versions_and_malformed_input_fail() {
        for src in [
            client().replace("schema_version = 1", "schema_version = 2"),
            client().replace(
                "ingress_mode = \"system_proxy\"",
                "ingress_mode = \"system_proxy\"\nunsafe = true",
            ),
            client().replace(
                "schema_version = 1",
                "schema_version = 1\nschema_version = 1",
            ),
            client().replace("schema_version = 1", "schema_version = \"secret\""),
        ] {
            assert!(parse(&src).is_err());
        }
        assert!(parse(&"x".repeat(MAX_BYTES + 1)).is_err());
    }
    #[test]
    fn wildcards_and_dual_stack_listener_collisions_are_rejected() {
        let original = server();
        let secondary = r#"
[[server.inbounds]]
id = "other"
path_prefix = "/v1/other"
allowed_user_ids = ["device-a"]
quic_listen = "127.0.0.1:443"
h2_listen = "[::]:443"
server_name = "edge.example.org"
tls_cert = "file:/etc/theia/tls/fullchain.pem"
tls_key = "file:/etc/theia/tls/privkey.pem"
"#;
        let source = original.replace(
            "[[server.users]]",
            &format!("{secondary}\n[[server.users]]"),
        );
        assert!(parse(&source).unwrap_err().field.contains("quic_listen"));
        let without_udp_conflict = source.replace(
            "quic_listen = \"127.0.0.1:443\"",
            "quic_listen = \"127.0.0.1:444\"",
        );
        assert!(parse(&without_udp_conflict)
            .unwrap_err()
            .field
            .contains("h2_listen"));
    }
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "theia-config-guard-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn changed_client(port: u16) -> Config {
        let mut config = parse(&client()).unwrap();
        let Config::Client(doc) = &mut config else {
            panic!("client");
        };
        doc.client.proxy.http_listen = format!("127.0.0.1:{port}");
        config
    }

    #[test]
    fn guarded_writes_reject_stale_or_busy_without_touching_bytes() {
        let scratch = Scratch::new();
        let path = scratch.0.join("client.toml");
        let other = scratch.0.join("other.toml");
        let initial = client().into_bytes();
        fs::write(&path, &initial).unwrap();
        fs::write(&other, &initial).unwrap();
        let held = editor_lock(&path).unwrap();
        let candidate = changed_client(7900);

        assert!(matches!(
            guarded_write(&path, &candidate, &initial),
            Err(WriteFailure::BeforeReplace(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), initial);
        assert!(guarded_write(&other, &candidate, &initial).is_ok());
        drop(held);
        let saved = guarded_write(&path, &candidate, &initial).unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(read_file(&path).unwrap(), candidate);
        assert!(matches!(
            guarded_write(&path, &changed_client(7901), &initial),
            Err(WriteFailure::BeforeReplace(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(fs::metadata(lock_path(&path).unwrap()).unwrap().len(), 0);
    }

    #[test]
    fn concurrent_guarded_writers_have_a_single_winner() {
        use std::{sync::Barrier, thread};

        let scratch = Scratch::new();
        let path = scratch.0.join("client.toml");
        let initial = client().into_bytes();
        fs::write(&path, &initial).unwrap();
        let barrier = Barrier::new(2);
        let results = thread::scope(|scope| {
            let handles = [7900, 7901].map(|port| {
                let barrier = &barrier;
                let path = &path;
                let initial = &initial;
                scope.spawn(move || {
                    let candidate = changed_client(port);
                    barrier.wait();
                    guarded_write(path, &candidate, initial)
                })
            });
            handles.map(|handle| handle.join().unwrap())
        });
        let winner = if results[0].is_ok() { 0 } else { 1 };
        assert!(matches!(
            &results[1 - winner],
            Err(WriteFailure::BeforeReplace(_))
        ));
        let saved = results[winner].as_ref().unwrap();
        assert_eq!(fs::read(&path).unwrap().as_slice(), saved.as_slice());
        let expected = changed_client([7900, 7901][winner]);
        assert_eq!(read_file(&path).unwrap(), expected);
    }

    #[test]
    fn injected_post_replace_sync_failure_is_not_rollback() {
        let scratch = Scratch::new();
        let path = scratch.0.join("client.toml");
        let initial = client().into_bytes();
        fs::write(&path, &initial).unwrap();
        let candidate = changed_client(7900);
        let result = guarded_write_with_sync(&path, &candidate, &initial, |_| {
            Err(ConfigError::new(
                "config",
                "injected directory sync failure",
            ))
        });
        assert!(matches!(result, Err(WriteFailure::AfterReplace(_))));
        assert_eq!(read_file(&path).unwrap(), candidate);
        assert!(matches!(
            guarded_write(&path, &changed_client(7901), &initial),
            Err(WriteFailure::BeforeReplace(_))
        ));
        let current = editor_bytes(&path).unwrap();
        assert!(guarded_write(&path, &changed_client(7901), &current).is_ok());
    }

    const LOCK_CHILD: &str = "THEIA_TEST_EDITOR_LOCK_CHILD_PATH";
    const LOCK_BUSY: i32 = 75;
    const LOCK_ACQUIRED: i32 = 76;

    #[test]
    fn child_attempts_editor_lock() {
        let Some(path) = std::env::var_os(LOCK_CHILD) else {
            return;
        };
        match editor_lock(Path::new(&path)) {
            Ok(_held) => std::process::exit(LOCK_ACQUIRED),
            Err(_) => std::process::exit(LOCK_BUSY),
        }
    }

    #[test]
    fn editor_lock_is_shared_across_processes_and_released_on_exit() {
        use std::process::Command;

        let scratch = Scratch::new();
        let path = scratch.0.join("client.toml");
        let attempt = || {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "config::tests::child_attempts_editor_lock"])
                .env(LOCK_CHILD, &path)
                .status()
                .unwrap()
                .code()
        };
        let held = editor_lock(&path).unwrap();
        assert_eq!(attempt(), Some(LOCK_BUSY));
        drop(held);
        assert_eq!(attempt(), Some(LOCK_ACQUIRED));
        assert!(editor_lock(&path).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn editor_rejects_symlinked_document_and_lock() {
        use std::os::unix::fs::symlink;

        let scratch = Scratch::new();
        let original = scratch.0.join("original.toml");
        let path = scratch.0.join("client.toml");
        let initial = client().into_bytes();
        fs::write(&original, &initial).unwrap();
        symlink(&original, &path).unwrap();
        assert!(editor_bytes(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, &initial).unwrap();

        let foreign = scratch.0.join("foreign");
        fs::write(&foreign, b"do not touch").unwrap();
        symlink(&foreign, lock_path(&path).unwrap()).unwrap();
        assert!(matches!(
            guarded_write(&path, &changed_client(7900), &initial),
            Err(WriteFailure::BeforeReplace(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), initial);
        assert_eq!(fs::read(&foreign).unwrap().as_slice(), b"do not touch");
    }

    #[test]
    fn typed_file_reader_rejects_oversized_and_nonregular_documents() {
        let scratch = Scratch::new();
        let path = scratch.0.join("client.toml");
        fs::write(&path, client()).unwrap();
        assert_eq!(read_file(&path).unwrap(), parse(&client()).unwrap());
        assert!(read_file(&scratch.0).is_err());
        fs::write(&path, vec![b'x'; MAX_BYTES + 1]).unwrap();
        assert!(read_file(&path).is_err());
    }

    #[test]
    fn atomic_store_roundtrip_and_invalid_update_preserves_old_file() {
        let path = std::env::temp_dir().join(format!(
            "theia-m12-{}-{}.toml",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let conf = parse(&client()).unwrap();
        atomic_write(&path, &conf).unwrap();
        let previous = fs::read(&path).unwrap();
        assert_eq!(read_file(&path).unwrap(), conf);
        let mut bad = conf.clone();
        if let Config::Client(doc) = &mut bad {
            doc.client.proxy.http_listen = "0.0.0.0:1234".into();
        }
        assert!(atomic_write(&path, &bad).is_err());
        assert_eq!(fs::read(&path).unwrap(), previous);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(path).unwrap();
    }
}
