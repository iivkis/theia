//! F-20 standalone configuration, local routing and independent diagnostics.
//! Configuration/preflight are offline. Live diagnostics require a reviewed
//! exact plan, explicit confirmation and a reserved local proxy owner.
pub mod catalog;
pub mod diagnostic;
mod dns;
pub use dns::DnsError;

use crate::{
    config::{self, ConfigError, IngressMode, LocalProxy, Management, Ui},
    net::address::allowed_destination,
    routing::{self, geodata, Action, Classification, Evidence, Policy, Rule},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

const MAX_CONFIG: usize = 1024 * 1024;
const MAX_RESOLVER_BOOTSTRAP: usize = 4;
const MAX_TARGET_ADDRESSES: usize = 64;

fn invalid(field: &str, reason: &'static str) -> ConfigError {
    ConfigError::new(field, reason)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema_version: u32,
    pub anti_dpi: Settings,
    pub management: Management,
    pub ui: Ui,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub id: String,
    pub revision: u64,
    #[serde(default)]
    pub ingress_mode: IngressMode,
    pub proxy: LocalProxy,
    #[serde(default)]
    pub consent: Consent,
    /// Absent until the operator explicitly chooses a resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<Resolver>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geodata: Option<GeoData>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    #[serde(default)]
    pub direct_egress: bool,
    #[serde(default)]
    pub direct_dpi: bool,
    #[serde(default)]
    pub direct_dpi_stun: bool,
}

/// DoH configuration only: exact HTTPS hostname and explicit public IP
/// bootstrap, never a fallback to system DNS. Network transport is separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    pub hostname: String,
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoData {
    pub directory: String,
    pub manifest: geodata::Manifest,
}

fn canonical_host(value: &str) -> bool {
    value.contains('.')
        && routing::domain_name(value).is_ok_and(|name| name == value)
        && ![
            ".local", ".localhost", ".internal", ".onion", ".test", ".invalid", ".example",
        ]
        .iter()
        .any(|suffix| value.ends_with(suffix))
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

impl Resolver {
    fn validate(&self) -> Result<(), ConfigError> {
        if !canonical_host(&self.hostname)
            || self.bootstrap.is_empty()
            || self.bootstrap.len() > MAX_RESOLVER_BOOTSTRAP
        {
            return Err(invalid("anti_dpi.resolver", "invalid HTTPS resolver or bootstrap"));
        }
        let mut seen = std::collections::HashSet::new();
        if self.bootstrap.iter().any(|ip| {
            canonical_ip(*ip) != *ip || !allowed_destination(*ip, false) || !seen.insert(*ip)
        }) {
            return Err(invalid("anti_dpi.resolver.bootstrap", "expected unique public IPs"));
        }
        Ok(())
    }
}

impl Document {
    /// This parser is deliberately separate from server/client documents.
    /// Serde errors are redacted; input can contain accidentally pasted secrets.
    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        if source.len() > MAX_CONFIG {
            return Err(invalid("document", "configuration exceeds 1 MiB"));
        }
        let document: Self = toml::from_str(source)
            .map_err(|_| invalid("document", "invalid standalone schema or unknown field"))?;
        document.validate()?;
        Ok(document)
    }

    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        let bytes = config::editor_bytes(path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("document", "configuration is not UTF-8"))?;
        Self::parse(text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        config::validate_shared(self.schema_version, &self.management, &self.ui)?;
        let settings = &self.anti_dpi;
        if !config::valid_id(&settings.id) || settings.revision == 0 {
            return Err(invalid("anti_dpi", "invalid ID or zero revision"));
        }
        config::validate_proxy(&settings.proxy, "anti_dpi.proxy")?;
        let consent = &settings.consent;
        if (consent.direct_dpi && !consent.direct_egress)
            || (consent.direct_dpi_stun && !consent.direct_dpi)
        {
            return Err(invalid("anti_dpi.consent", "local egress and Anti-DPI consent required"));
        }
        if let Some(resolver) = &settings.resolver {
            resolver.validate()?;
        }
        if settings.rules.iter().any(|rule| rule.action == Action::Allowed) {
            return Err(invalid("anti_dpi.rules", "server routing is not allowed in standalone"));
        }
        let requires_data = Policy::requires_geodata(&settings.rules)
            .map_err(|_| invalid("anti_dpi.rules", "invalid routing selectors or limits"))?;
        match &settings.geodata {
            Some(data)
                if crate::bounded_input::explicit_file_path(Path::new(&data.directory))
                    && !data.directory.chars().any(char::is_control)
                    && data.manifest.release.len() == 14
                    && data.manifest.release.bytes().all(|b| b.is_ascii_digit())
                    && data.manifest.geosite_sha256 != [0; 32]
                    && data.manifest.geoip_sha256 != [0; 32] => {}
            None if !requires_data => {}
            _ => return Err(invalid("anti_dpi.geodata", "verified DAT selection required")),
        }
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        self.validate()?;
        let text = toml::to_string_pretty(self)
            .map_err(|_| invalid("document", "cannot serialize standalone configuration"))?;
        Self::parse(&text)?;
        Ok(text)
    }

    /// Compile the exact selected DAT pair, not a mutable active pointer.
    /// This is offline preflight, never evidence of live resolver or proxy readiness.
    pub fn prepare(&self) -> Result<PreparedPolicy, ConfigError> {
        let text = self.to_toml()?;
        let settings = &self.anti_dpi;
        let policy = match &settings.geodata {
            Some(data) => geodata::Store::new(PathBuf::from(&data.directory))
                .and_then(|store| store.load_pinned(&data.manifest, &settings.rules))
                .and_then(|pair| pair.compile(&settings.rules))
                .map_err(|_| invalid("anti_dpi.geodata", "pinned DAT verification failed"))?,
            None => Policy::compile(&settings.rules, &[], &[])
                .map_err(|_| invalid("anti_dpi.rules", "cannot compile routing policy"))?,
        };
        let mut hash = Sha256::new();
        hash.update(b"theia/standalone/config/v1\0");
        hash.update(text.as_bytes());
        Ok(PreparedPolicy {
            id: settings.id.clone(),
            revision: settings.revision,
            digest: hash.finalize().into(),
            policy,
        })
    }

    /// Validate a cooperating editor replacement. A rollback must use a
    /// new revision; a different role or ID cannot replace this document.
    pub fn accepts_replacement(&self, next: &Self) -> Result<(), ConfigError> {
        self.validate()?;
        next.validate()?;
        if self.anti_dpi.id != next.anti_dpi.id
            || (self != next && next.anti_dpi.revision <= self.anti_dpi.revision)
        {
            return Err(invalid("anti_dpi.revision", "replacement requires same ID and newer revision"));
        }
        Ok(())
    }

    /// Create-only or exact-byte CAS save using the existing atomic writer.
    /// Does not publish the runtime policy or authorize any network action.
    pub fn save(&self, path: &Path, expected: Option<&[u8]>) -> Result<(), SaveError> {
        let text = self.to_toml().map_err(SaveError::BeforeReplace)?;
        if let Some(bytes) = expected {
            let previous = std::str::from_utf8(bytes)
                .map_err(|_| invalid("document", "configuration is not UTF-8"))
                .and_then(Self::parse)
                .map_err(SaveError::BeforeReplace)?;
            previous.accepts_replacement(self).map_err(SaveError::BeforeReplace)?;
            if previous == *self {
                return config::guarded_trust_assert(path, bytes).map_err(SaveError::BeforeReplace);
            }
        }
        config::guarded_trust_write(path, &text, expected).map_err(|error| match error {
            config::WriteFailure::BeforeReplace(e) => SaveError::BeforeReplace(e),
            config::WriteFailure::AfterReplace(e) => SaveError::AfterReplace(e),
        })
    }
}

/// Never collapse uncertainty after a file replacement into a safe refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum SaveError {
    BeforeReplace(ConfigError),
    AfterReplace(ConfigError),
}

/// Classification alone does not grant dial/send permissions. The runtime
/// must check consent, live generation, DNS pins and accepted strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Modify,
    Drop,
    Unresolved,
}

#[derive(Debug)]
pub struct PreparedPolicy {
    id: String,
    revision: u64,
    digest: [u8; 32],
    policy: Policy,
}

fn local_decision(classification: Classification) -> Decision {
    match classification {
        Classification::Default | Classification::Matched(Action::Direct) => Decision::Pass,
        Classification::Matched(Action::DirectDpi) => Decision::Modify,
        Classification::Matched(Action::Blocked | Action::Allowed) => Decision::Drop,
        Classification::Unresolved => Decision::Unresolved,
    }
}

impl PreparedPolicy {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Domain-only preflight can conclusively deny an operation before DNS.
    /// Pass/Modify is not dial authorization until all addresses are checked.
    pub fn classify_domain(&self, name: &str) -> Decision {
        if !canonical_host(name) {
            return Decision::Drop;
        }
        self.policy
            .classify(Evidence::Known(name), Evidence::Unknown)
            .map_or(Decision::Drop, local_decision)
    }

    /// An IP literal has unknown domain provenance, not a proven absence.
    pub fn classify_literal(&self, ip: IpAddr) -> Decision {
        let ip = canonical_ip(ip);
        if !allowed_destination(ip, false) {
            return Decision::Drop;
        }
        match self.policy
            .classify(Evidence::Unknown, Evidence::Known(ip))
            .map_or(Decision::Drop, local_decision)
        {
            Decision::Unresolved => Decision::Drop,
            decision => decision,
        }
    }

    /// Evaluate every DNS answer before any dial. A single denied, unknown,
    /// or differently routed address rejects the whole answer set.
    pub fn classify_resolved(&self, name: &str, addresses: &[IpAddr]) -> Decision {
        if !canonical_host(name)
            || addresses.is_empty()
            || addresses.len() > MAX_TARGET_ADDRESSES
            || self.classify_domain(name) == Decision::Drop
        {
            return Decision::Drop;
        }
        let mut selected = None;
        for &ip in addresses {
            let ip = canonical_ip(ip);
            if !allowed_destination(ip, false) {
                return Decision::Drop;
            }
            let decision = self
                .policy
                .classify(Evidence::Known(name), Evidence::Known(ip))
                .map_or(Decision::Drop, local_decision);
            if matches!(decision, Decision::Drop | Decision::Unresolved)
                || selected.is_some_and(|previous| previous != decision)
            {
                return Decision::Drop;
            }
            selected = Some(decision);
        }
        selected.unwrap_or(Decision::Drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Document {
        Document::parse(include_str!("../../../examples/anti-dpi.toml")).unwrap()
    }

    fn rule(action: Action, domains: &[&str], ips: &[&str]) -> Rule {
        Rule {
            name: "test".into(),
            action,
            domains: domains.iter().map(|s| (*s).into()).collect(),
            ips: ips.iter().map(|s| (*s).into()).collect(),
            applications: vec![],
        }
    }

    #[test]
    fn strict_role_and_consent_and_round_trip() {
        let document = example();
        assert_eq!(Document::parse(&document.to_toml().unwrap()).unwrap(), document);
        assert!(Document::parse(include_str!("../../../examples/client.toml")).is_err());
        let source = include_str!("../../../examples/anti-dpi.toml");
        assert!(Document::parse(&source.replace("system_proxy", "tun")).is_err());
        assert!(Document::parse(&source.replace("system_proxy", "packet")).is_err());
        let mut invalid_document = document.clone();
        invalid_document.anti_dpi.consent.direct_dpi_stun = true;
        assert!(invalid_document.validate().is_err());
        invalid_document.anti_dpi.consent.direct_dpi = true;
        assert!(invalid_document.validate().is_err());
        invalid_document.anti_dpi.consent.direct_egress = true;
        assert!(invalid_document.validate().is_ok());
        invalid_document.anti_dpi.proxy.http_listen = "0.0.0.0:8080".into();
        assert!(invalid_document.validate().is_err());
        assert!(Document::parse(&format!("{source}\n[client]\nsecret='not-a-real-secret'")).is_err());
    }

    #[test]
    fn server_redirect_and_unpinned_categories_are_refused() {
        let mut document = example();
        document.anti_dpi.rules = vec![rule(Action::Allowed, &["example.com"], &[])];
        assert!(document.validate().is_err());
        document.anti_dpi.rules = vec![rule(Action::DirectDpi, &["geosite:TEST"], &[])];
        assert!(document.prepare().is_err());
    }

    #[test]
    fn local_default_unknown_and_ordered_or_semantics() {
        let mut document = example();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let empty = document.prepare().unwrap();
        assert_eq!(empty.classify_resolved("example.com", &[ip]), Decision::Pass);
        assert_eq!(empty.classify_literal(ip), Decision::Pass);
        document.anti_dpi.rules = vec![
            rule(Action::DirectDpi, &["full:example.com"], &[]),
            rule(Action::Direct, &[], &["1.1.1.1/32"]),
        ];
        let policy = document.prepare().unwrap();
        assert_eq!(policy.classify_literal(ip), Decision::Drop);
        assert_eq!(policy.classify_resolved("example.com", &[ip]), Decision::Modify);
        assert_eq!(policy.classify_resolved("other.example.com", &[ip]), Decision::Pass);
        document.anti_dpi.rules[0].ips.push("1.1.1.1/32".into());
        assert_eq!(document.prepare().unwrap().classify_literal(ip), Decision::Modify);
    }

    #[test]
    fn deny_and_mixed_answers_fail_closed() {
        let mut document = example();
        document.anti_dpi.rules = vec![
            rule(Action::DirectDpi, &[], &["1.1.1.1/32"]),
            rule(Action::Blocked, &["full:blocked.example.com"], &[]),
        ];
        let policy = document.prepare().unwrap();
        let first = "1.1.1.1".parse().unwrap();
        let second = "8.8.8.8".parse().unwrap();
        let private = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(policy.classify_resolved("example.com", &[first, second]), Decision::Drop);
        assert_eq!(policy.classify_resolved("example.com", &[first, private]), Decision::Drop);
        assert_eq!(policy.classify_resolved("example.com", &[]), Decision::Drop);
        assert_eq!(policy.classify_resolved("example.com", &[first; 65]), Decision::Drop);
        assert_eq!(policy.classify_resolved("blocked.example.com", &[second]), Decision::Drop);
        assert_eq!(policy.classify_resolved("example.com", &[first]), Decision::Modify);
        assert_eq!(policy.classify_literal(private), Decision::Drop);
    }

    #[test]
    fn resolver_is_explicit_public_and_unique() {
        let mut document = example();
        assert!(document.anti_dpi.resolver.is_none());
        let mut resolver = Resolver {
            hostname: "dns.example.com".into(),
            bootstrap: vec!["1.1.1.1".parse().unwrap()],
        };
        document.anti_dpi.resolver = Some(resolver.clone());
        assert!(document.validate().is_ok());
        resolver.bootstrap.push("::ffff:127.0.0.1".parse().unwrap());
        document.anti_dpi.resolver = Some(resolver.clone());
        assert!(document.validate().is_err());
        resolver.bootstrap = vec!["1.1.1.1".parse().unwrap(); 2];
        document.anti_dpi.resolver = Some(resolver);
        assert!(document.validate().is_err());
    }

    #[test]
    fn revisions_and_guarded_save_preserve_role_and_reject_stale_bytes() {
        let document = example();
        let mut next = document.clone();
        next.anti_dpi.rules.push(rule(Action::DirectDpi, &["example.com"], &[]));
        assert!(document.accepts_replacement(&next).is_err());
        next.anti_dpi.revision += 1;
        assert!(document.accepts_replacement(&next).is_ok());
        assert_ne!(document.prepare().unwrap().digest(), next.prepare().unwrap().digest());
        let mut other = next.clone();
        other.anti_dpi.id = "different".into();
        assert!(document.accepts_replacement(&other).is_err());

        let directory = std::env::temp_dir().join(format!(
            "theia-f20-save-{}", std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("anti-dpi.toml");
        document.save(&path, None).unwrap();
        assert!(document.save(&path, None).is_err());
        let old = std::fs::read(&path).unwrap();
        next.save(&path, Some(&old)).unwrap();
        assert!(next.save(&path, Some(&old)).is_err());
        assert_eq!(Document::read(&path).unwrap(), next);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
