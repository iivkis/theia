//! Durable local generation high-water mark. It protects against replacing
//! the publication or health file alone with an older valid snapshot. It
//! does not defend against a privileged actor rolling back the whole disk.
#![forbid(unsafe_code)]

use crate::{
    config::{self, WriteFailure},
    reality_bootstrap::{self as bootstrap, Error},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const FILE: &str = "generation-floor.toml";
const MAX: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stamp {
    pub manifest: [u8; 32],
    pub generation: u64,
    pub publication: [u8; 32],
    pub health_revision: u64,
    pub health: [u8; 32],
}

impl Stamp {
    fn validate(&self) -> Result<(), Error> {
        if self.generation == 0
            || self.health_revision == 0
            || [self.manifest, self.publication, self.health].contains(&[0; 32])
        {
            return Err(Error::Format);
        }
        Ok(())
    }

    fn advances(&self, next: Self) -> Result<bool, Error> {
        next.validate()?;
        if next.manifest != self.manifest
            || next.generation < self.generation
            || next.health_revision < self.health_revision
            || (next.generation == self.generation && next.publication != self.publication)
            || (next.health_revision == self.health_revision && next.health != self.health)
        {
            return Err(Error::Approval);
        }
        Ok(*self != next)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    schema_version: u16,
    accepted_at: u64,
    stamp: Stamp,
}

impl Floor {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 || self.accepted_at == 0 {
            return Err(Error::Format);
        }
        self.stamp.validate()
    }
    fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let raw = toml::to_string(self).map_err(|_| Error::Format)?;
        if raw.len() > MAX {
            return Err(Error::Format);
        }
        Ok(raw)
    }
    fn permits(&self, stamp: Stamp, now: u64) -> Result<bool, Error> {
        self.validate()?;
        if now < self.accepted_at {
            return Err(Error::Clock);
        }
        self.stamp.advances(stamp)
    }
}

fn read(directory: &Path) -> Result<(zeroize::Zeroizing<String>, Floor), Error> {
    let raw = bootstrap::read_text(&directory.join(FILE), MAX, true)?;
    let floor: Floor = toml::from_str(&raw).map_err(|_| Error::Format)?;
    floor.validate()?;
    Ok((raw, floor))
}

/// Called only as part of create-only provisioning before manifest write.
/// No manager or recovery path recreates a missing checkpoint.
pub(crate) fn initialize(directory: &Path, stamp: Stamp, now: u64) -> Result<(), Error> {
    if stamp.generation != 1 {
        return Err(Error::Approval);
    }
    let floor = Floor {
        schema_version: 1,
        accepted_at: now,
        stamp,
    };
    bootstrap::create_text(&directory.join(FILE), &floor.encode()?)
}

pub(crate) fn verify(directory: &Path, stamp: Stamp, now: u64) -> Result<(), Error> {
    let (_, floor) = read(directory)?;
    floor.permits(stamp, now)?;
    Ok(())
}

/// Read/validate/replace with the shared exact-byte CAS. Only an advance
/// writes a file. A competing write is refused and must be re-read.
pub(crate) fn accept(directory: &Path, stamp: Stamp, now: u64) -> Result<(), Error> {
    let (raw, previous) = read(directory)?;
    if !previous.permits(stamp, now)? {
        return config::guarded_trust_assert(&directory.join(FILE), raw.as_bytes())
            .map_err(|_| Error::Storage);
    }
    let next = Floor {
        schema_version: 1,
        accepted_at: now,
        stamp,
    };
    config::guarded_trust_write(&directory.join(FILE), &next.encode()?, Some(raw.as_bytes()))
        .map_err(|error| match error {
            WriteFailure::BeforeReplace(_) => Error::Storage,
            WriteFailure::AfterReplace(_) => Error::Indeterminate,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn initial() -> Stamp {
        Stamp {
            manifest: [1; 32],
            generation: 1,
            publication: [2; 32],
            health_revision: 1,
            health: [3; 32],
        }
    }

    #[test]
    fn independent_floors_reject_equal_revision_equivocation_and_clock_rollback() {
        let a = initial();
        let floor = Floor {
            schema_version: 1,
            accepted_at: 100,
            stamp: a,
        };
        assert_eq!(floor.permits(a, 100), Ok(false));
        assert_eq!(floor.permits(a, 99), Err(Error::Clock));
        assert_eq!(
            floor.permits(
                Stamp {
                    health: [4; 32],
                    ..a
                },
                100
            ),
            Err(Error::Approval)
        );
        assert_eq!(
            floor.permits(
                Stamp {
                    publication: [4; 32],
                    ..a
                },
                100
            ),
            Err(Error::Approval)
        );
        assert_eq!(
            floor.permits(
                Stamp {
                    manifest: [4; 32],
                    ..a
                },
                100
            ),
            Err(Error::Approval)
        );
        assert_eq!(
            floor.permits(
                Stamp {
                    generation: 2,
                    publication: [4; 32],
                    ..a
                },
                100
            ),
            Ok(true)
        );
        let advanced = Stamp {
            generation: 2,
            publication: [4; 32],
            health_revision: 2,
            health: [5; 32],
            ..a
        };
        assert_eq!(
            advanced.advances(Stamp {
                generation: 3,
                publication: [6; 32],
                ..a
            }),
            Err(Error::Approval)
        );
        assert_eq!(advanced.advances(a), Err(Error::Approval));
    }

    #[test]
    fn missing_floor_is_not_recreated_and_unchanged_candidate_does_not_write() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-floor-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let first = initial();
        assert_eq!(accept(&dir, first, 100), Err(Error::Storage));
        initialize(&dir, first, 100).unwrap();
        assert!(initialize(&dir, first, 100).is_err());
        let raw = std::fs::read(dir.join(FILE)).unwrap();
        accept(&dir, first, 101).unwrap();
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), raw);
        let next = Stamp {
            generation: 2,
            publication: [4; 32],
            ..first
        };
        accept(&dir, next, 102).unwrap();
        assert!(config::guarded_trust_assert(&dir.join(FILE), &raw).is_err());
        assert!(verify(&dir, first, 103).is_err());
        assert_eq!(accept(&dir, next, 101), Err(Error::Clock));
        accept(&dir, next, 103).unwrap();
        std::fs::remove_file(dir.join(FILE)).unwrap();
        assert_eq!(accept(&dir, next, 104), Err(Error::Storage));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
