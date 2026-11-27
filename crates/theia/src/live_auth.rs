//! M4.2b1a: staged in-process authorization snapshots shared across all
//! H2/H3 server inbound contexts. No IPC Apply or live reload is exposed.
//!
//! A request takes exactly one immutable snapshot. The CAS publication changes
//! new authorizations for every inbound at once, never existing session permits,
//! network listeners, peer budgets, or user/global quota semaphores.
use crate::{
    config::{Config, Inbound, ServerDocument, ServerPolicy, User},
    reload_preflight::{assess_reload, ReloadCheckError},
    routing::{exchange::Published, Settings},
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, RwLock},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveAuthError {
    InvalidCandidate,
    RequiresRestart,
    StaleRevision,
    ForeignStage,
    Unavailable,
    RevisionExhausted,
}

impl fmt::Display for LiveAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCandidate => "invalid authorization candidate",
            Self::RequiresRestart => "candidate changes restart-only settings",
            Self::StaleRevision => "authorization revision changed before commit",
            Self::ForeignStage => "staged update belongs to another running server",
            Self::Unavailable => "authorization snapshot unavailable",
            Self::RevisionExhausted => "authorization revision exhausted",
        };
        f.write_str(message)
    }
}
impl std::error::Error for LiveAuthError {}

/// Fully owned, immutable snapshot. No token bytes, only configured digests.
pub(crate) struct AuthSnapshot {
    pub(crate) revision: u64,
    pub(crate) users: Vec<User>,
    pub(crate) grants: HashMap<String, HashSet<String>>,
    pub(crate) routing: HashMap<String, Arc<Published>>,
    routing_settings: Option<Settings>,
}

impl AuthSnapshot {
    fn for_document(
        doc: &ServerDocument,
        revision: u64,
        previous: Option<&Self>,
    ) -> Result<Self, LiveAuthError> {
        let settings = &doc.server.policy.routing;
        if let Some(old) = previous {
            Settings::transition(old.routing_settings.as_ref(), settings.as_ref())
                .map_err(|_| LiveAuthError::InvalidCandidate)?;
        }
        let mut routing = HashMap::new();
        for inbound in &doc.server.inbounds {
            let reused = previous
                .filter(|old| &old.routing_settings == settings)
                .and_then(|old| old.routing.get(&inbound.id))
                .filter(|p| p.snapshot.manifest().inbound_id == Published::scope(inbound));
            let publication = match reused {
                Some(p) => p.clone(),
                None => Arc::new(
                    Published::prepare(inbound, &doc.server.policy)
                        .map_err(|_| LiveAuthError::InvalidCandidate)?,
                ),
            };
            routing.insert(inbound.id.clone(), publication);
        }
        Ok(Self {
            routing,
            routing_settings: settings.clone(),
            revision,
            users: doc.server.users.clone(),
            grants: doc
                .server
                .inbounds
                .iter()
                .map(|inbound| {
                    (
                        inbound.id.clone(),
                        inbound.allowed_user_ids.iter().cloned().collect(),
                    )
                })
                .collect(),
        })
    }

    fn for_inbound(
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
        scope: Option<&str>,
    ) -> Self {
        let publication =
            Published::for_scope(scope.unwrap_or_else(|| Published::scope(inbound)), policy);
        Self {
            routing_settings: policy.routing.clone(),
            routing: publication
                .ok()
                .map(|p| HashMap::from([(inbound.id.clone(), Arc::new(p))]))
                .unwrap_or_default(),
            revision: 1,
            users: users.to_vec(),
            grants: HashMap::from([(
                inbound.id.clone(),
                inbound.allowed_user_ids.iter().cloned().collect(),
            )]),
        }
    }
}

/// Short synchronous RwLock for one Arc load/replace only. It is NEVER held
/// during token hashing, network I/O, quota acquisition, PEM or TOML reads.
pub(crate) struct AuthCell {
    current: RwLock<Arc<AuthSnapshot>>,
}

impl AuthCell {
    pub(crate) fn isolated(
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
        scope: Option<&str>,
    ) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(Arc::new(AuthSnapshot::for_inbound(
                inbound, users, policy, scope,
            ))),
        })
    }

    pub(crate) fn load(&self) -> Result<Arc<AuthSnapshot>, LiveAuthError> {
        self.current
            .read()
            .map(|guard| Arc::clone(&guard))
            .map_err(|_| LiveAuthError::Unavailable)
    }
}

/// One authority for the initial running config and every future candidate.
/// The full baseline is immutable and used by ADR-0039 compatibility checks.
pub struct LiveAuthorization {
    baseline: ServerDocument,
    shared: Arc<AuthCell>,
}

/// Move-only preparation bound to one server's specific AuthCell. Constructed
/// only from a fully validated candidate; dropping it is a no-op.
pub struct StagedAuthorization {
    owner: Arc<AuthCell>,
    expected_revision: u64,
    snapshot: Arc<AuthSnapshot>,
}

impl LiveAuthorization {
    pub fn new(baseline: ServerDocument) -> Result<Self, LiveAuthError> {
        Self::new_at_revision(baseline, 1)
    }

    /// A real listener generation restart increments the monotonic CAS
    /// revision, so a pre-cutover management request cannot be replayed.
    pub(crate) fn new_at_revision(
        baseline: ServerDocument,
        revision: u64,
    ) -> Result<Self, LiveAuthError> {
        if revision == 0 {
            return Err(LiveAuthError::InvalidCandidate);
        }
        Config::Server(baseline.clone())
            .validate()
            .map_err(|_| LiveAuthError::InvalidCandidate)?;
        if !baseline.server.enabled {
            return Err(LiveAuthError::InvalidCandidate);
        }
        let initial = AuthSnapshot::for_document(&baseline, revision, None)?;
        Ok(Self {
            baseline,
            shared: Arc::new(AuthCell {
                current: RwLock::new(Arc::new(initial)),
            }),
        })
    }

    /// After an auth-only CAS, update the structural baseline without
    /// replacing the shared AuthCell or invalidating existing sessions.
    pub(crate) fn with_new_baseline(&self, baseline: ServerDocument) -> Self {
        Self {
            baseline,
            shared: Arc::clone(&self.shared),
        }
    }

    /// Rebase a TLS-only rotation onto the SAME AuthCell shared by existing
    /// H2/H3 contexts. The caller must independently prove that ONLY TLS PEM
    /// identity may change, never routing, quotas or user inventory.
    /// Staging is pure and cannot leak another revision to readers.
    pub(crate) fn prepare_tls_rebase(
        &self,
        candidate: &ServerDocument,
        expected_revision: u64,
    ) -> Result<(Self, StagedAuthorization), LiveAuthError> {
        if self.revision()? != expected_revision {
            return Err(LiveAuthError::StaleRevision);
        }
        Config::Server(candidate.clone())
            .validate()
            .map_err(|_| LiveAuthError::InvalidCandidate)?;
        if !candidate.server.enabled {
            return Err(LiveAuthError::InvalidCandidate);
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or(LiveAuthError::RevisionExhausted)?;
        let rebased = Self {
            baseline: candidate.clone(),
            shared: Arc::clone(&self.shared),
        };
        let stage = StagedAuthorization {
            owner: Arc::clone(&self.shared),
            expected_revision,
            snapshot: Arc::new(AuthSnapshot::for_document(
                candidate,
                next,
                Some(self.shared.load()?.as_ref()),
            )?),
        };
        Ok((rebased, stage))
    }

    /// Stop NEW H2/H3 authorization requests on the retiring generation.
    /// Already authenticated stream permits remain held until natural drain
    /// or the bounded grace deadline. This is NOT hard tunnel revocation.
    pub(crate) fn close_new_admission(&self) -> Result<(), LiveAuthError> {
        let mut guard = self
            .shared
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let previous = &**guard;
        let mut users = previous.users.clone();
        for user in &mut users {
            user.disabled = true;
        }
        *guard = Arc::new(AuthSnapshot {
            revision: previous.revision,
            users,
            grants: HashMap::new(),
            routing: previous.routing.clone(),
            routing_settings: previous.routing_settings.clone(),
        });
        Ok(())
    }

    pub(crate) fn shared(&self) -> Arc<AuthCell> {
        Arc::clone(&self.shared)
    }

    /// One immutable authorization snapshot; never return token digests.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn access_observation(&self, inbound: &str, user: &str) -> Result<(u64, u8), LiveAuthError> {
        let snapshot = self.shared.load()?;
        let state = match snapshot.grants.get(inbound) {
            None => 0,
            Some(grants) => match snapshot.users.iter().find(|entry| entry.id == user) {
                Some(entry) if entry.disabled => 2,
                Some(_) if grants.contains(user) => 3,
                _ => 1,
            },
        };
        Ok((snapshot.revision, state))
    }

    pub fn revision(&self) -> Result<u64, LiveAuthError> {
        Ok(self.shared.load()?.revision)
    }

    /// Given a candidate and an expected active revision, validate and build
    /// the *entire* next snapshot without modifying running auth. No caller
    /// can bypass the same structural compatibility as reload --check.
    ///
    /// This is NOT a disk/TLS identity check. Before a future IPC Apply, the
    /// candidate PEM bytes must be revalidated with the actual TLS identity
    /// snapshot from server startup. This API is currently in-process only.
    pub fn stage(
        &self,
        candidate: &ServerDocument,
        expected_revision: u64,
    ) -> Result<StagedAuthorization, LiveAuthError> {
        if self.revision()? != expected_revision {
            return Err(LiveAuthError::StaleRevision);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(LiveAuthError::RevisionExhausted)?;
        assess_reload(&self.baseline, candidate).map_err(|error| match error {
            ReloadCheckError::InvalidConfig => LiveAuthError::InvalidCandidate,
            ReloadCheckError::RequiresRestart | ReloadCheckError::IdentityDrift => {
                LiveAuthError::RequiresRestart
            }
        })?;
        let snapshot = Arc::new(AuthSnapshot::for_document(
            candidate,
            next_revision,
            Some(self.shared.load()?.as_ref()),
        )?);
        Ok(StagedAuthorization {
            owner: Arc::clone(&self.shared),
            expected_revision,
            snapshot,
        })
    }

    /// Linearization point. All inbound/H2/H3 contexts load from the single
    /// RwLock. Two valid stages against one revision cannot both commit.
    pub fn publish(&self, staged: StagedAuthorization) -> Result<u64, LiveAuthError> {
        self.publish_with(staged, || Ok(()))
    }

    /// A bounded durable configuration CAS may precede the infallible Arc swap.
    /// No candidate data parsing, downloading or compilation under this lock.
    pub(crate) fn publish_with(
        &self,
        staged: StagedAuthorization,
        persist: impl FnOnce() -> Result<(), LiveAuthError>,
    ) -> Result<u64, LiveAuthError> {
        if !Arc::ptr_eq(&self.shared, &staged.owner) {
            return Err(LiveAuthError::ForeignStage);
        }
        let mut guard = self
            .shared
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if guard.revision != staged.expected_revision {
            return Err(LiveAuthError::StaleRevision);
        }
        let revision = staged.snapshot.revision;
        persist()?;
        *guard = staged.snapshot;
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Management, ServerPolicy, ServerSettings, Ui};

    #[test]
    fn in_memory_stage_does_not_publish_until_committed() {
        let doc = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "alpha".into(),
                    path_prefix: Some("/v1/theia-example".into()),
                    allowed_user_ids: vec!["alice".into()],
                    h2_listen: "127.0.0.1:4443".into(),
                    quic_listen: "127.0.0.1:4443".into(),
                    server_name: "a.example.org".into(),
                    tls_cert: "file:/tmp/cert".into(),
                    security_mode: Default::default(),
                    reality: None,
                    tls_key: "file:/tmp/key".into(),
                }],
                users: vec![User {
                    id: "alice".into(),
                    token_sha256: "a".repeat(64),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    routing: None,
                    allow_private_ips: false,
                    max_connections_per_user: 1,
                    max_connections_total: 2,
                    connect_timeout_ms: 1000,
                },
            },
            management: Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: Ui {
                language: "ru".into(),
            },
        };
        let live = LiveAuthorization::new(doc.clone()).unwrap();
        assert_eq!(live.revision(), Ok(1));
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            assert_eq!(live.access_observation("alpha", "alice"), Ok((1, 3)));
            assert_eq!(live.access_observation("alpha", "missing"), Ok((1, 1)));
            assert_eq!(live.access_observation("missing", "alice"), Ok((1, 0)));
        }
        let mut routed = doc.clone();
        routed.server.policy.routing = Some(crate::routing::Settings {
            revision: 2,
            geodata_directory: None,
            rules: vec![],
            datasets: None,
        });
        let (_, staged_routing) = live.prepare_tls_rebase(&routed, 1).unwrap();
        assert_eq!(
            live.shared().load().unwrap().routing["alpha"]
                .snapshot
                .manifest()
                .revision,
            1
        );
        drop(staged_routing);
        let (_, failed) = live.prepare_tls_rebase(&routed, 1).unwrap();
        assert_eq!(
            live.publish_with(failed, || Err(LiveAuthError::Unavailable)),
            Err(LiveAuthError::Unavailable)
        );
        assert_eq!(live.revision(), Ok(1));
        assert_eq!(
            live.shared().load().unwrap().routing["alpha"]
                .snapshot
                .manifest()
                .revision,
            1
        );
        let isolated = LiveAuthorization::new(doc.clone()).unwrap();
        let (_, publication) = isolated.prepare_tls_rebase(&routed, 1).unwrap();
        assert_eq!(isolated.publish(publication), Ok(2));
        assert_eq!(
            isolated.shared().load().unwrap().routing["alpha"]
                .snapshot
                .manifest()
                .revision,
            2
        );
        assert!(isolated.prepare_tls_rebase(&doc, 2).is_err());
        let mut changed = doc;
        changed.server.users[0].disabled = true;
        let staged = live.stage(&changed, 1).unwrap();
        assert!(!live.shared().load().unwrap().users[0].disabled);
        drop(staged);
        assert_eq!(live.revision(), Ok(1));
        let committed = live.stage(&changed, 1).unwrap();
        assert_eq!(live.publish(committed), Ok(2));
        assert!(live.shared().load().unwrap().users[0].disabled);

        // No wrap to zero and no ambiguous successful commit receipt at the
        // revision boundary; the loaded state must remain unchanged.
        {
            let mut guard = live.shared.current.write().unwrap();
            *guard = Arc::new(AuthSnapshot::for_document(&changed, u64::MAX, None).unwrap());
        }
        assert!(matches!(
            live.stage(&changed, u64::MAX),
            Err(LiveAuthError::RevisionExhausted)
        ));
        assert_eq!(live.revision(), Ok(u64::MAX));
    }
}
