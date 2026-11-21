//! Strict, typed TOML v1 schema and validation. This module has no network or
//! OS proxy side effects. Secret references are checked syntactically, never read.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
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
    fn new(field: impl Into<String>, reason: &'static str) -> Self {
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
    pub allowed_user_ids: Vec<String>,
    pub quic_listen: String,
    pub h2_listen: String,
    pub server_name: String,
    pub tls_cert: String,
    pub tls_key: String,
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
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub active_profile: String,
    pub profiles: Vec<Profile>,
    pub proxy: LocalProxy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub server: String,
    pub server_name: String,
    pub auth_token: String,
    pub tls_profile: String,
    pub transport: Transport,
    pub quic_connect_timeout_ms: u32,
    pub quic_negative_cache_ttl_s: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Auto,
    H3,
    H2,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProxy {
    pub http_listen: String,
    pub socks5_listen: String,
    pub system_proxy: SystemProxy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemProxy {
    Off,
    Manual,
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
    let config = if has_server {
        Config::Server(toml::from_str(source).map_err(|_| {
            ConfigError::new("document", "invalid server schema, unknown field or field type")
        })?)
    } else {
        Config::Client(toml::from_str(source).map_err(|_| {
            ConfigError::new("document", "invalid client schema, unknown field or field type")
        })?)
    };
    config.validate()?;
    Ok(config)
}

pub fn read_file(path: &Path) -> Result<Config, ConfigError> {
    let file = fs::File::open(path)
        .map_err(|_| ConfigError::new("config", "cannot open configuration file"))?;
    let mut buf = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|_| ConfigError::new("config", "cannot read configuration file"))?;
    ensure(buf.len() <= MAX_BYTES, "document", "configuration exceeds 1 MiB")?;
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

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_dns(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
fn valid_file_ref(raw: &str) -> bool {
    let Some(path) = raw.strip_prefix("file:") else {
        return false;
    };
    let path = Path::new(path);
    path.is_absolute()
        && !path.components().any(|part| matches!(part, std::path::Component::ParentDir))
        && !raw.contains(['\n', '\r', '\0'])
}
fn valid_secret_ref(raw: &str) -> bool {
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
fn validate_shared(schema: u32, m: &Management, ui: &Ui) -> Check {
    ensure(schema == 1, "schema_version", "only version 1 is supported")?;
    ensure(m.ipc == "auto", "management.ipc", "only auto is supported")?;
    ensure(
        matches!(m.log_level.as_str(), "error" | "warn" | "info" | "debug" | "trace"),
        "management.log_level",
        "unknown log level",
    )?;
    ensure(matches!(ui.language.as_str(), "ru" | "en"), "ui.language", "unknown language")
}

impl ServerDocument {
    fn validate(&self) -> Check {
        validate_shared(self.schema_version, &self.management, &self.ui)?;
        ensure(!self.server.users.is_empty(), "server.users", "at least one user is required")?;
        ensure(!self.server.inbounds.is_empty(), "server.inbounds", "at least one inbound is required")?;
        let mut user_ids = HashSet::new();
        let mut token_digests = HashSet::new();
        for (i, user) in self.server.users.iter().enumerate() {
            let field = format!("server.users[{i}]");
            ensure(valid_id(&user.id), format!("{field}.id"), "invalid user ID")?;
            ensure(user_ids.insert(user.id.as_str()), format!("{field}.id"), "duplicate user ID")?;
            ensure(
                user.token_sha256.len() == 64
                    && user.token_sha256.bytes().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)),
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
            ensure(valid_id(&inbound.id), format!("{field}.id"), "invalid inbound ID")?;
            ensure(inbound_ids.insert(inbound.id.as_str()), format!("{field}.id"), "duplicate inbound ID")?;
            ensure(!inbound.allowed_user_ids.is_empty(), format!("{field}.allowed_user_ids"), "explicit grant list must not be empty")?;
            let mut grants = HashSet::new();
            for user_id in &inbound.allowed_user_ids {
                ensure(user_ids.contains(user_id.as_str()), format!("{field}.allowed_user_ids"), "unknown user grant")?;
                ensure(grants.insert(user_id), format!("{field}.allowed_user_ids"), "duplicate user grant")?;
            }
            ensure(valid_dns(&inbound.server_name), format!("{field}.server_name"), "invalid DNS name")?;
            ensure(valid_file_ref(&inbound.tls_cert), format!("{field}.tls_cert"), "expected absolute file: reference")?;
            ensure(valid_file_ref(&inbound.tls_key), format!("{field}.tls_key"), "expected absolute file: reference")?;
            let udp = listen(&inbound.quic_listen, &format!("{field}.quic_listen"))?;
            let tcp = listen(&inbound.h2_listen, &format!("{field}.h2_listen"))?;
            ensure(!udp_listeners.iter().any(|x| overlaps(*x, udp)), format!("{field}.quic_listen"), "UDP listener overlaps another inbound")?;
            ensure(!tcp_listeners.iter().any(|x| overlaps(*x, tcp)), format!("{field}.h2_listen"), "TCP listener overlaps another inbound")?;
            udp_listeners.push(udp);
            tcp_listeners.push(tcp);
        }
        let p = &self.server.policy;
        ensure(p.max_connections_per_user > 0, "server.policy.max_connections_per_user", "must be positive")?;
        ensure(p.max_connections_total > 0, "server.policy.max_connections_total", "must be positive")?;
        ensure(
            p.max_connections_per_user <= p.max_connections_total,
            "server.policy.max_connections_per_user",
            "must not exceed total connection cap",
        )?;
        ensure(p.connect_timeout_ms > 0, "server.policy.connect_timeout_ms", "must be positive")
    }
}
fn valid_remote(raw: &str) -> bool {
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
        ensure(!self.client.profiles.is_empty(), "client.profiles", "at least one profile is required")?;
        let mut ids = HashSet::new();
        for (i, profile) in self.client.profiles.iter().enumerate() {
            let field = format!("client.profiles[{i}]");
            ensure(valid_id(&profile.id), format!("{field}.id"), "invalid profile ID")?;
            ensure(ids.insert(profile.id.as_str()), format!("{field}.id"), "duplicate profile ID")?;
            ensure(valid_remote(&profile.server), format!("{field}.server"), "invalid host:port or [IPv6]:port")?;
            ensure(valid_dns(&profile.server_name), format!("{field}.server_name"), "invalid TLS server name")?;
            ensure(valid_secret_ref(&profile.auth_token), format!("{field}.auth_token"), "expected env:NAME or absolute file: reference")?;
            ensure(profile.tls_profile == "default", format!("{field}.tls_profile"), "unsupported TLS profile (fail closed)")?;
            ensure((500..=15_000).contains(&profile.quic_connect_timeout_ms), format!("{field}.quic_connect_timeout_ms"), "must be within 500..=15000")?;
            ensure(profile.quic_negative_cache_ttl_s <= 86_400, format!("{field}.quic_negative_cache_ttl_s"), "must be within 0..=86400")?;
        }
        ensure(ids.contains(self.client.active_profile.as_str()), "client.active_profile", "unknown profile")?;
        let proxy = &self.client.proxy;
        let http = listen(&proxy.http_listen, "client.proxy.http_listen")?;
        let socks = listen(&proxy.socks5_listen, "client.proxy.socks5_listen")?;
        for (address, field) in [
            (http, "client.proxy.http_listen"),
            (socks, "client.proxy.socks5_listen"),
        ] {
            ensure(
                matches!(address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)),
                field,
                "listener must bind to 127.0.0.1 or [::1]",
            )?;
        }
        ensure(http != socks, "client.proxy", "HTTP and SOCKS5 listener addresses must differ")
    }
}

/// Validate and atomically replace a TOML file. On failure before rename, the
/// previous file remains intact. No live runtime reload is attempted here.
/// Callers must supply a trusted destination directory (no untrusted symlinks).
pub fn atomic_write(path: &Path, config: &Config) -> Result<(), ConfigError> {
    let data = config.to_toml()?;
    ensure(data.len() <= MAX_BYTES, "document", "configuration exceeds 1 MiB")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| ConfigError::new("config", "destination file name is missing"))?;
    let mut pending = None;
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = std::ffi::OsString::from(".");
        temp_name.push(name);
        temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temp = parent.join(temp_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(file) => {
                pending = Some((temp, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ConfigError::new("config", "cannot create temporary config file")),
        }
    }
    let (temp, mut file) = pending.ok_or_else(|| ConfigError::new("config", "cannot allocate temporary file"))?;
    let result = (|| {
        file.write_all(data.as_bytes())
            .map_err(|_| ConfigError::new("config", "cannot write temporary file"))?;
        file.sync_all()
            .map_err(|_| ConfigError::new("config", "cannot sync temporary file"))?;
        drop(file);
        fs::rename(&temp, path)
            .map_err(|_| ConfigError::new("config", "cannot atomically replace configuration"))?;
        #[cfg(unix)]
        {
            if let Ok(directory) = fs::File::open(parent) {
                directory.sync_all().map_err(|_| ConfigError::new("config", "cannot sync directory"))?;
            }
        }
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
        include_str!("../../../examples/server.toml").replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64))
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
    fn server_denies_invalid_ids_digests_and_grants() {
        let original = server();
        for (from, to, expected) in [
            ("allowed_user_ids = [\"device-a\"]", "allowed_user_ids = []", "allowed_user_ids"),
            ("allowed_user_ids = [\"device-a\"]", "allowed_user_ids = [\"missing\"]", "allowed_user_ids"),
            ("allowed_user_ids = [\"device-a\"]", "allowed_user_ids = [\"device-a\", \"device-a\"]", "allowed_user_ids"),
            ("id = \"public\"", "id = \"bad id\"", "id"),
            ("token_sha256 = \"", "token_sha256 = \"UPPER", "token_sha256"),
            ("max_connections_total = 1024", "max_connections_total = 0", "max_connections_total"),
        ] {
            let changed = original.replacen(from, to, 1);
            assert!(parse(&changed).unwrap_err().field.contains(expected), "{expected}");
        }
    }
    #[test]
    fn rejects_unsafe_client_settings() {
        let original = client();
        for (from, to, expected) in [
            ("system_proxy = \"off\"", "system_proxy = \"on\"", "document"),
            ("http_listen = \"127.0.0.1:7890\"", "http_listen = \"0.0.0.0:7890\"", "http_listen"),
            ("socks5_listen = \"127.0.0.1:7891\"", "socks5_listen = \"127.0.0.1:7890\"", "client.proxy"),
            ("tls_profile = \"default\"", "tls_profile = \"chrome133\"", "tls_profile"),
            ("auth_token = \"env:THEIA_AUTH_TOKEN\"", "auth_token = \"literal-secret\"", "auth_token"),
            ("quic_connect_timeout_ms = 1600", "quic_connect_timeout_ms = 499", "quic_connect_timeout_ms"),
            ("active_profile = \"home\"", "active_profile = \"missing\"", "active_profile"),
        ] {
            let changed = original.replacen(from, to, 1);
            assert!(parse(&changed).unwrap_err().field.contains(expected), "{expected}");
        }
    }
    #[test]
    fn unknown_keys_versions_and_malformed_input_fail() {
        for src in [
            client().replace("schema_version = 1", "schema_version = 2"),
            client().replace("system_proxy = \"off\"", "system_proxy = \"off\"\nunsafe = true"),
            client().replace("schema_version = 1", "schema_version = 1\nschema_version = 1"),
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
allowed_user_ids = ["device-a"]
quic_listen = "127.0.0.1:443"
h2_listen = "[::]:443"
server_name = "edge.example.org"
tls_cert = "file:/etc/theia/tls/fullchain.pem"
tls_key = "file:/etc/theia/tls/privkey.pem"
"#;
        let source = original.replace("[[server.users]]", &format!("{secondary}\n[[server.users]]"));
        assert!(parse(&source).unwrap_err().field.contains("quic_listen"));
        let without_udp_conflict = source.replace("quic_listen = \"127.0.0.1:443\"", "quic_listen = \"127.0.0.1:444\"");
        assert!(parse(&without_udp_conflict).unwrap_err().field.contains("h2_listen"));
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
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        fs::remove_file(path).unwrap();
    }
}
