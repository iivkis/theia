//! Typed server routing configuration. Data updates are candidates until
//! their exact digests and a new monotonic revision are selected in TOML.
use super::{geodata, snapshot, Policy, RoutingError, Rule};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geodata_directory: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datasets: Option<geodata::Manifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Routing(RoutingError),
    Data(geodata::Error),
    Snapshot(snapshot::SnapshotError),
}
impl From<RoutingError> for Error {
    fn from(error: RoutingError) -> Self { Self::Routing(error) }
}
impl From<geodata::Error> for Error {
    fn from(error: geodata::Error) -> Self { Self::Data(error) }
}
impl From<snapshot::SnapshotError> for Error {
    fn from(error: snapshot::SnapshotError) -> Self { Self::Snapshot(error) }
}

impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        // Revision 1 is the implicit empty baseline. An explicitly emptied
        // policy must retain its revision, not reset to that baseline.
        if self.revision < 2 {
            return Err(Error::Invalid);
        }
        Policy::validate_rules(&self.rules)?;
        let (_, site_codes, ip_codes) = super::compile_selectors(&self.rules)?;
        let requires_data = !site_codes.is_empty() || !ip_codes.is_empty();
        match (&self.geodata_directory, &self.datasets) {
            (Some(directory), Some(manifest)) if crate::bounded_input::explicit_file_path(Path::new(directory))
                && !directory.chars().any(char::is_control)
                && manifest.release.len() == 14
                && manifest.release.bytes().all(|b| b.is_ascii_digit())
                && manifest.geosite_sha256 != [0; 32]
                && manifest.geoip_sha256 != [0; 32] => Ok(()),
            (None, None) if !requires_data => Ok(()),
            _ => Err(Error::Invalid),
        }
    }

    pub fn prepare(&self, inbound_scope: &str) -> Result<(snapshot::Snapshot, Vec<u8>), Error> {
        self.validate()?;
        match (&self.geodata_directory, &self.datasets) {
            (Some(directory), Some(manifest)) => {
                let pair = geodata::Store::new(PathBuf::from(directory))?.load_pinned(manifest, &self.rules)?;
                Ok(snapshot::Snapshot::build(inbound_scope, self.revision, &self.rules, pair.geosite(), pair.geoip())?)
            }
            (None, None) => Ok(snapshot::Snapshot::build(inbound_scope, self.revision, &self.rules, &[], &[])?),
            _ => Err(Error::Invalid),
        }
    }

    /// A validated replacement must be prepared before publication. No
    /// lower revision or same-revision different settings can be activated.
    pub fn accepts_replacement(&self, next: &Self) -> Result<(), Error> {
        next.validate()?;
        if self == next || next.revision > self.revision { Ok(()) } else { Err(Error::Invalid) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Action;
    fn settings() -> Settings {
        Settings {
            revision: 2,
            geodata_directory: None,
            datasets: None,
            rules: vec![Rule {
                name: "example".into(),
                action: Action::Direct,
                domains: vec!["example.org".into()],
                ips: vec![],
            }],
        }
    }
    #[test]
    fn typed_settings_and_empty_revision() {
        let original = settings();
        let text = toml::to_string(&original).unwrap();
        let decoded: Settings = toml::from_str(&text).unwrap();
        assert_eq!(decoded, original);
        let (snapshot, _) = original.prepare("inbound").unwrap();
        assert_eq!(snapshot.manifest().revision, 2);
        let mut next = original.clone();
        next.rules.clear();
        assert!(original.accepts_replacement(&next).is_err());
        next.revision += 1;
        assert!(original.accepts_replacement(&next).is_ok());
        next.revision = 1;
        assert!(next.validate().is_err());
    }
    #[test]
    fn missing_data_or_invalid_selectors_rejected() {
        let mut value = settings();
        value.rules[0].domains = vec!["geosite:google".into()];
        assert!(value.validate().is_err());
        value.rules[0].domains = vec!["bad..domain".into()];
        assert!(value.validate().is_err());
        value.rules[0].domains.clear();
        assert!(value.validate().is_err());
    }
}
