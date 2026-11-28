//! Offline historical catalogue and separately persisted diagnostic overlay.
//! Catalogue entries are not routing rules, permission to probe, or live verdicts.
use super::{canonical_host, invalid, SaveError, MAX_CONFIG};
use crate::{config::{self, ConfigError}, routing};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fmt::Write, path::Path};

const BUILTIN: &str = include_str!("catalog.tsv");
pub const VERSION: &str = "ru-ooni-2024-v1";
pub const SOURCE: &str = "https://ooni.org/post/2024-russia-report/";
pub const DATA_SOURCE: &str = "https://ooni.org/post/2024-russia-report/2024-09-01-russia-blocked-confirmed-media-domains.csv";
pub const MAX_DOMAINS: usize = 256;
pub const MAX_JOB_DOMAINS: usize = 64;
pub const MAX_JOB_CELLS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub source: &'static str,
    pub last_confirmed_day: String,
    pub confirmed_networks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub hostname: String,
    pub provenance: Option<Provenance>,
    pub excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    pub schema_version: u32,
    #[serde(default)]
    pub custom: Vec<String>,
    #[serde(default)]
    pub excluded: Vec<String>,
}

impl Default for Overlay {
    fn default() -> Self {
        Self { schema_version: 1, custom: Vec::new(), excluded: Vec::new() }
    }
}

fn normalize(value: &str) -> Result<String, ConfigError> {
    let host = routing::domain_name(value)
        .map_err(|_| invalid("catalog.hostname", "expected DNS hostname, not a URL or IP"))?;
    if !canonical_host(&host) {
        return Err(invalid("catalog.hostname", "expected public canonical DNS hostname"));
    }
    Ok(host)
}

fn normalized_set(values: &[String]) -> Result<BTreeSet<String>, ConfigError> {
    if values.len() > MAX_DOMAINS {
        return Err(invalid("catalog.overlay", "too many entries"));
    }
    values.iter().map(|value| normalize(value)).collect()
}

impl Overlay {
    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        if source.len() > MAX_CONFIG {
            return Err(invalid("catalog.overlay", "overlay exceeds 1 MiB"));
        }
        let mut overlay: Self = toml::from_str(source)
            .map_err(|_| invalid("catalog.overlay", "invalid overlay schema or unknown field"))?;
        if overlay.schema_version != 1 {
            return Err(invalid("catalog.overlay", "unsupported schema"));
        }
        overlay.custom = normalized_set(&overlay.custom)?.into_iter().collect();
        overlay.excluded = normalized_set(&overlay.excluded)?.into_iter().collect();
        Catalog::build(&overlay)?;
        Ok(overlay)
    }

    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        let bytes = config::editor_bytes(path)?;
        Self::parse(std::str::from_utf8(&bytes)
            .map_err(|_| invalid("catalog.overlay", "overlay is not UTF-8"))?)
    }

    pub fn save(&self, path: &Path, expected: Option<&[u8]>) -> Result<(), SaveError> {
        Catalog::build(self).map_err(SaveError::BeforeReplace)?;
        let text = toml::to_string_pretty(self)
            .map_err(|_| SaveError::BeforeReplace(invalid("catalog.overlay", "serialization failed")))?;
        Self::parse(&text).map_err(SaveError::BeforeReplace)?;
        if let Some(bytes) = expected {
            let previous = std::str::from_utf8(bytes)
                .map_err(|_| invalid("catalog.overlay", "overlay is not UTF-8"))
                .and_then(Self::parse)
                .map_err(SaveError::BeforeReplace)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    entries: Vec<Entry>,
    builtin_count: usize,
}

impl Catalog {
    pub fn build(overlay: &Overlay) -> Result<Self, ConfigError> {
        if overlay.schema_version != 1 {
            return Err(invalid("catalog.overlay", "unsupported schema"));
        }
        let custom = normalized_set(&overlay.custom)?;
        let excluded = normalized_set(&overlay.excluded)?;
        let mut entries = BTreeMap::new();
        for line in BUILTIN.lines().filter(|line| !line.starts_with('#') && !line.is_empty()) {
            let mut fields = line.split('\t');
            let (Some(host), Some(day), Some(networks), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(invalid("catalog.builtin", "invalid embedded record"));
            };
            let networks: u32 = networks.parse()
                .map_err(|_| invalid("catalog.builtin", "invalid network count"))?;
            if !canonical_host(host) || day.len() != 10 || networks == 0 ||
                entries.insert(host.to_owned(), Some(Provenance {
                    source: SOURCE, last_confirmed_day: day.to_owned(), confirmed_networks: networks,
                })).is_some() {
                return Err(invalid("catalog.builtin", "invalid or duplicate embedded record"));
            }
        }
        let builtin_count = entries.len();
        if !(50..=MAX_JOB_DOMAINS).contains(&builtin_count) {
            return Err(invalid("catalog.builtin", "embedded inventory outside required limits"));
        }
        for host in custom {
            entries.entry(host).or_insert(None);
        }
        if entries.len() > MAX_DOMAINS {
            return Err(invalid("catalog.overlay", "combined catalogue exceeds limit"));
        }
        Ok(Self {
            entries: entries.into_iter().map(|(hostname, provenance)| Entry {
                excluded: excluded.contains(&hostname), hostname, provenance,
            }).collect(),
            builtin_count,
        })
    }

    pub fn entries(&self) -> &[Entry] { &self.entries }
    pub fn builtin_count(&self) -> usize { self.builtin_count }

    /// Hash of the immutable catalogue content, independent of user choices.
    pub fn builtin_digest() -> [u8; 32] { Sha256::digest(BUILTIN.as_bytes()).into() }

    /// An offline, bounded selection. No socket or strategy admission is implied.
    pub fn select<'a>(&'a self, hosts: &[String], strategy_count: usize)
        -> Result<Vec<&'a Entry>, ConfigError>
    {
        if hosts.is_empty() || hosts.len() > MAX_JOB_DOMAINS || strategy_count == 0 ||
            hosts.len().checked_mul(strategy_count).is_none_or(|n| n > MAX_JOB_CELLS) {
            return Err(invalid("catalog.selection", "invalid diagnostic matrix dimensions"));
        }
        let selected = normalized_set(hosts)?;
        if selected.len() != hosts.len() {
            return Err(invalid("catalog.selection", "duplicate target"));
        }
        selected.iter().map(|host| self.entries.iter()
            .find(|entry| entry.hostname == *host && !entry.excluded)
            .ok_or_else(|| invalid("catalog.selection", "unknown or excluded target"))).collect()
    }

    pub fn render(&self) -> String {
        let mut out = format!("{} built-in={} total={}\nHistorical observations, not current reachability. No network checks performed.\n", VERSION, self.builtin_count, self.entries.len());
        let _ = write!(out, "sha256=");
        for byte in Self::builtin_digest() { let _ = write!(out, "{byte:02x}"); }
        out.push('\n');
        for entry in &self.entries {
            let _ = write!(out, "{}\t{}\t", entry.hostname, if entry.excluded { "excluded" } else { "enabled" });
            if let Some(p) = &entry.provenance {
                let _ = writeln!(out, "{}\t{}\t{}", p.last_confirmed_day, p.confirmed_networks, p.source);
            } else {
                out.push_str("user-supplied; no block evidence\n");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_history_and_user_overlay_are_separate() {
        let overlay = Overlay { custom: vec!["MEDUZA.IO.".into(), "custom.example.com".into()],
            excluded: vec!["meduza.io".into()], ..Overlay::default() };
        let catalog = Catalog::build(&overlay).unwrap();
        assert_eq!(catalog.builtin_count(), 60);
        assert_eq!(catalog.entries().len(), 61);
        let entry = catalog.entries().iter().find(|e| e.hostname == "meduza.io").unwrap();
        assert!(entry.excluded && entry.provenance.is_some());
        assert_eq!(catalog.entries().iter().filter(|e| e.provenance.is_some()).count(), 60);
        assert!(catalog.select(&["meduza.io".into()], 1).is_err());
        assert!(catalog.select(&["custom.example.com".into()], 1).is_ok());
    }

    #[test]
    fn reject_invalid_or_oversized_selections_and_overlays() {
        let catalog = Catalog::build(&Overlay::default()).unwrap();
        for host in ["https://example.com", "127.0.0.1", "foo.local", "foo.onion", "foo.invalid"] {
            assert!(Catalog::build(&Overlay { custom: vec![host.into()], ..Overlay::default() }).is_err());
        }
        assert!(catalog.select(&["meduza.io".into()], 513).is_err());
        assert!(catalog.select(&["meduza.io".into(), "MEDUZA.IO".into()], 1).is_err());
        let hosts: Vec<_> = catalog.entries().iter().map(|e| e.hostname.clone()).collect();
        assert_eq!(catalog.select(&hosts, 8).unwrap().len(), 60);
        assert!(catalog.select(&hosts, 9).is_err());
        assert!(Catalog::build(&Overlay { custom: (0..256).map(|i| format!("h{i}.example.com")).collect(), ..Overlay::default() }).is_err());
        assert!(Overlay::parse("schema_version=2").is_err());
        assert!(Overlay::parse("schema_version=1\nunknown=true").is_err());
    }
}
