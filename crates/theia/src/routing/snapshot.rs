//! Bounded, versioned routing snapshots for an already authenticated channel.
//! Transport, durable trust state and publication are separate runtime steps.
use super::{entry_code, Field, Policy, RoutingError, Rule, Wire};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MAGIC: &[u8; 8] = b"THEIAR01";
const HEADER: usize = 20;
const MAX_MANIFEST: usize = 1024 * 1024;
pub const MAX_SNAPSHOT: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub inbound_id: String,
    pub revision: u64,
    /// Digest of the full upstream file, not just the selected categories.
    pub geosite_source_sha256: [u8; 32],
    pub geoip_source_sha256: [u8; 32],
    pub geosite_payload_sha256: [u8; 32],
    pub geoip_payload_sha256: [u8; 32],
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Snapshot {
    manifest: Manifest,
    policy: Policy,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    Invalid,
    Scope,
    Integrity,
    Limit,
    Rollback,
    Equivocation,
    Routing(RoutingError),
}
impl From<RoutingError> for SnapshotError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}
impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "routing snapshot: {self:?}")
    }
}
impl std::error::Error for SnapshotError {}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn scope_valid(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 64
        && scope
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn select_dat(data: &[u8], wanted: &HashSet<&str>) -> Result<Vec<u8>, SnapshotError> {
    let mut wire = Wire(data);
    let mut output = Vec::new();
    while !wire.0.is_empty() {
        let original = wire.0;
        let Some((tag, value)) = wire.next()? else {
            break;
        };
        if tag != 1 {
            continue;
        }
        let Field::Bytes(entry) = value else {
            return Err(SnapshotError::Invalid);
        };
        let code = entry_code(entry)?;
        if wanted.contains(code.as_str()) {
            let consumed = original.len() - wire.0.len();
            if output.len().saturating_add(consumed) > MAX_SNAPSHOT {
                return Err(SnapshotError::Limit);
            }
            output.extend_from_slice(&original[..consumed]);
        }
    }
    Ok(output)
}

fn length_word(value: usize) -> Result<[u8; 4], SnapshotError> {
    Ok(u32::try_from(value)
        .map_err(|_| SnapshotError::Limit)?
        .to_be_bytes())
}

impl Snapshot {
    /// Server prepares exact source bytes only after their external SHA-256
    /// checks have passed. No paths, credentials, or URLs are in the payload.
    /// Only categories used by the validated rules are transferred.
    pub fn build(
        inbound_id: &str,
        revision: u64,
        rules: &[Rule],
        geosite: &[u8],
        geoip: &[u8],
    ) -> Result<(Self, Vec<u8>), SnapshotError> {
        if !scope_valid(inbound_id) || revision == 0 {
            return Err(SnapshotError::Invalid);
        }
        let policy = Policy::compile(rules, geosite, geoip)?;
        let site_codes = policy.sites.keys().map(String::as_str).collect();
        let ip_codes = policy.ips.keys().map(String::as_str).collect();
        let site = select_dat(geosite, &site_codes)?;
        let ip = select_dat(geoip, &ip_codes)?;
        let manifest = Manifest {
            inbound_id: inbound_id.to_owned(),
            revision,
            geosite_source_sha256: hash(geosite),
            geoip_source_sha256: hash(geoip),
            geosite_payload_sha256: hash(&site),
            geoip_payload_sha256: hash(&ip),
            rules: rules.to_vec(),
        };
        let text = toml::to_string(&manifest).map_err(|_| SnapshotError::Invalid)?;
        let len = HEADER
            .saturating_add(text.len())
            .saturating_add(site.len())
            .saturating_add(ip.len());
        if text.len() > MAX_MANIFEST || len > MAX_SNAPSHOT {
            return Err(SnapshotError::Limit);
        }
        let mut wire = Vec::with_capacity(len);
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&length_word(text.len())?);
        wire.extend_from_slice(&length_word(site.len())?);
        wire.extend_from_slice(&length_word(ip.len())?);
        wire.extend_from_slice(text.as_bytes());
        wire.extend_from_slice(&site);
        wire.extend_from_slice(&ip);
        let digest = hash(&wire);
        Ok((
            Self {
                manifest,
                policy,
                digest,
            },
            wire,
        ))
    }

    /// Call only after authenticating the server and checking the profile
    /// trust anchor. A checksum alone does not establish authority.
    pub fn decode(wire: &[u8], expected_inbound: &str) -> Result<Self, SnapshotError> {
        if wire.len() > MAX_SNAPSHOT {
            return Err(SnapshotError::Limit);
        }
        if wire.len() < HEADER || &wire[..8] != MAGIC {
            return Err(SnapshotError::Invalid);
        }
        let read_len = |offset: usize| -> Result<usize, SnapshotError> {
            let bytes = <[u8; 4]>::try_from(&wire[offset..offset + 4])
                .map_err(|_| SnapshotError::Invalid)?;
            usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| SnapshotError::Limit)
        };
        let text_len = read_len(8)?;
        let site_len = read_len(12)?;
        let ip_len = read_len(16)?;
        if text_len == 0 || text_len > MAX_MANIFEST {
            return Err(SnapshotError::Limit);
        }
        let site_start = HEADER.checked_add(text_len).ok_or(SnapshotError::Limit)?;
        let ip_start = site_start
            .checked_add(site_len)
            .ok_or(SnapshotError::Limit)?;
        let end = ip_start.checked_add(ip_len).ok_or(SnapshotError::Limit)?;
        if end != wire.len() {
            return Err(SnapshotError::Invalid);
        }
        let text =
            std::str::from_utf8(&wire[HEADER..site_start]).map_err(|_| SnapshotError::Invalid)?;
        let manifest: Manifest = toml::from_str(text).map_err(|_| SnapshotError::Invalid)?;
        if manifest.revision == 0 || !scope_valid(&manifest.inbound_id) {
            return Err(SnapshotError::Invalid);
        }
        if manifest.inbound_id != expected_inbound {
            return Err(SnapshotError::Scope);
        }
        let site = &wire[site_start..ip_start];
        let ip = &wire[ip_start..end];
        if hash(site) != manifest.geosite_payload_sha256
            || hash(ip) != manifest.geoip_payload_sha256
        {
            return Err(SnapshotError::Integrity);
        }
        let policy = Policy::compile(&manifest.rules, site, ip)?;
        let site_codes = policy.sites.keys().map(String::as_str).collect();
        let ip_codes = policy.ips.keys().map(String::as_str).collect();
        if select_dat(site, &site_codes)? != site || select_dat(ip, &ip_codes)? != ip {
            return Err(SnapshotError::Invalid);
        }
        Ok(Self {
            manifest,
            policy,
            digest: hash(wire),
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Per-profile durable state must bind this checkpoint to the pinned
    /// server identity and inbound before reuse; caller owns atomic storage.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            revision: self.manifest.revision,
            digest: self.digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub digest: [u8; 32],
}
impl Checkpoint {
    pub fn accepts(&self, next: &Snapshot) -> Result<(), SnapshotError> {
        if self.revision == 0 {
            return Err(SnapshotError::Invalid);
        }
        if next.manifest.revision < self.revision {
            return Err(SnapshotError::Rollback);
        }
        if next.manifest.revision == self.revision && next.digest != self.digest {
            return Err(SnapshotError::Equivocation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Action;

    fn field(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 128);
        let mut bytes = vec![tag * 8 + 2, value.len() as u8];
        bytes.extend_from_slice(value);
        bytes
    }
    fn site(code: &str, host: &str) -> Vec<u8> {
        let mut domain = vec![8, 2];
        domain.extend(field(2, host.as_bytes()));
        let mut entry = field(1, code.as_bytes());
        entry.extend(field(2, &domain));
        field(1, &entry)
    }
    fn rule() -> Rule {
        Rule {
            name: "Example".into(),
            action: Action::Direct,
            domains: vec!["geosite:TEST".into()],
            ips: vec![],
        }
    }

    #[test]
    fn only_used_categories_and_exact_scope() {
        let mut data = site("TEST", "example.com");
        data.extend(site("UNUSED", "unused.example"));
        let (server, wire) = Snapshot::build("inbound", 2, &[rule()], &data, &[]).unwrap();
        let client = Snapshot::decode(&wire, "inbound").unwrap();
        assert_eq!(server.digest(), client.digest());
        assert_eq!(client.manifest().geosite_source_sha256, hash(&data));
        assert_eq!(
            client.manifest().geosite_payload_sha256,
            hash(&site("TEST", "example.com"))
        );
        assert_eq!(
            client
                .policy()
                .matching_action(Some("www.example.com"), None)
                .unwrap(),
            Some(Action::Direct)
        );
        assert_eq!(
            client
                .policy()
                .matching_action(Some("unused.example"), None)
                .unwrap(),
            None
        );
        assert!(matches!(
            Snapshot::decode(&wire, "another"),
            Err(SnapshotError::Scope)
        ));
    }

    #[test]
    fn direct_dpi_is_distinct_and_round_trips_with_geosite() {
        let data = site("TEST", "example.com");
        let mut dpi = rule();
        dpi.action = Action::DirectDpi;
        let text = toml::to_string(&dpi).unwrap();
        assert!(text.contains("direct_via_client_anti_dpi"));
        assert_eq!(toml::from_str::<Rule>(&text).unwrap(), dpi);
        assert!(toml::from_str::<Rule>(&text.replace("direct_via_client_anti_dpi", "direct_dpi")).is_err());
        let (server, wire) = Snapshot::build("inbound", 2, &[dpi], &data, &[]).unwrap();
        let client = Snapshot::decode(&wire, "inbound").unwrap();
        assert_eq!(server.digest(), client.digest());
        assert_eq!(
            client.policy().domain_decision("www.example.com").unwrap(),
            Some(Action::DirectDpi)
        );
        assert!(Action::DirectDpi.permits_server_egress());
        assert!(Action::Allowed.permits_server_egress());
        assert!(!Action::Direct.permits_server_egress());
        assert!(!Action::Blocked.permits_server_egress());
        let (original, _) = Snapshot::build("inbound", 2, &[rule()], &data, &[]).unwrap();
        assert_eq!(
            original.checkpoint().accepts(&client),
            Err(SnapshotError::Equivocation)
        );
    }

    #[test]
    fn revision_guards_and_corruption() {
        let data = site("TEST", "example.com");
        let (old, wire) = Snapshot::build("inbound", 2, &[rule()], &data, &[]).unwrap();
        let checkpoint = old.checkpoint();
        assert_eq!(
            checkpoint.accepts(&Snapshot::decode(&wire, "inbound").unwrap()),
            Ok(())
        );
        let (lower, _) = Snapshot::build("inbound", 1, &[rule()], &data, &[]).unwrap();
        assert_eq!(checkpoint.accepts(&lower), Err(SnapshotError::Rollback));
        let (different, _) = Snapshot::build("inbound", 2, &[], &data, &[]).unwrap();
        assert_eq!(
            checkpoint.accepts(&different),
            Err(SnapshotError::Equivocation)
        );
        let (higher, _) = Snapshot::build("inbound", 3, &[], &data, &[]).unwrap();
        assert_eq!(checkpoint.accepts(&higher), Ok(()));
        let mut corrupted = wire.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(matches!(
            Snapshot::decode(&corrupted, "inbound"),
            Err(SnapshotError::Integrity)
        ));
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(matches!(
            Snapshot::decode(&trailing, "inbound"),
            Err(SnapshotError::Invalid)
        ));
        assert!(matches!(
            Snapshot::decode(&wire[..wire.len() - 1], "inbound"),
            Err(SnapshotError::Invalid)
        ));
        assert!(Snapshot::build("inbound", 0, &[], &[], &[]).is_err());
    }
}
