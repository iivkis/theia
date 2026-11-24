//! M4.1c typed, bounded, selectable inbound/profile configuration forms.
//!
//! A user-provided configuration file is explicit. Never print its contents,
//! secret references, token hashes or path in diagnostics. All writes go
//! through the existing strict validator and atomic store.
use crate::{
    client_import::{self, PrivateBearer},
    config::{self, Config, Transport, User, XhttpMode},
    invite::Invitation,
    Role,
};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_INPUT: usize = 255;

fn xhttp_value(mode: Option<XhttpMode>) -> String {
    match mode {
        None => "legacy",
        Some(XhttpMode::Auto) => "auto",
        Some(XhttpMode::StreamOne) => "stream-one",
        Some(XhttpMode::StreamUp) => "stream-up",
    }
    .to_owned()
}

pub(crate) struct PinnedModeReview {
    source: [u8; 32],
    inbound: String,
    name: String,
    endpoint: String,
    pin: crate::security_profile::CertificatePin,
    mode: crate::security_profile::SecurityMode,
}

impl PinnedModeReview {
    pub(crate) fn body(&self) -> String {
        let (mode, profile) = if self.mode.is_stream_up() {
            ("pinned-cert-stream-up-v1", self.pin.stream_up_profile())
        } else {
            ("pinned-cert-v1", self.pin.profile())
        };
        format!("Собственный inbound: {}\nEndpoint: {}\nSNI: {}\nsecurity_mode = {mode}\nКлиентский tls_profile = {profile}\n\nСохранить режим только в TOML. Старые приглашения несовместимы; новый theia://v1 сохраняет точный режим и pin. Нужна отдельная перезагрузка сервера; CA/SAN остаются обязательными.\nНе полноценный REALITY. y: сохранить; n/Esc: отмена", self.inbound, self.endpoint, self.name)
    }
}

pub struct Editor {
    role: Role,
    path: PathBuf,
    source: Vec<u8>,
    original: Config,
    draft: Config,
    issued: Option<Invitation>,
    issued_ready: bool,
    write_uncertain: bool,
    selected_record: usize,
    selected_field: usize,
    pub input: String,
    pub editing: bool,
    pub error: Option<String>,
    pub notice: &'static str,
}

impl Editor {
    pub fn load(role: Role, path: &Path) -> Result<Self, &'static str> {
        let source = config::editor_bytes(path).map_err(|_| "cannot read config file")?;
        let utf8 = std::str::from_utf8(&source).map_err(|_| "configuration is not UTF-8")?;
        let parsed = config::parse(utf8).map_err(|_| "configuration failed validation")?;
        if !role_matches(role, &parsed) {
            return Err("configuration role does not match selected panel");
        }
        let selected_record = match &parsed {
            Config::Server(_) => 0,
            Config::Client(doc) => doc
                .client
                .profiles
                .iter()
                .position(|p| p.id == doc.client.active_profile)
                .unwrap_or(0),
        };
        Ok(Self {
            role,
            path: path.to_owned(),
            source,
            original: parsed.clone(),
            draft: parsed,
            issued: None,
            issued_ready: false,
            write_uncertain: false,
            selected_record,
            selected_field: 0,
            input: String::new(),
            editing: false,
            error: None,
            notice: "Загружено. Изменения не применяются к runtime.",
        })
    }

    /// F-14: commit a completely new client profile from a reviewed invitation.
    /// The source's bearer is never written to TOML; the file is protected by
    /// a fresh owner-only directory and private ACL/mode on both platforms.
    /// Caller must explicitly review ID/endpoint/SNI/transport and CA trust.
    pub fn import_invitation(
        &mut self,
        invite: &Invitation,
        ca_ref: Option<&str>,
        public_ref: Option<&str>,
    ) -> Result<(), &'static str> {
        let result = self.try_import_invitation(invite, ca_ref, public_ref, config::guarded_write);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn try_import_invitation(
        &mut self,
        invite: &Invitation,
        ca_ref: Option<&str>,
        public_ref: Option<&str>,
        write: impl FnOnce(&Path, &Config, &[u8]) -> Result<Vec<u8>, config::WriteFailure>,
    ) -> Result<(), &'static str> {
        if self.role != Role::Client || self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard all changes before importing");
        }
        let Config::Client(document) = &self.draft else {
            return Err("Client config required");
        };
        if document.client.profiles.iter().any(|p| p.id == invite.id) {
            return Err("An existing profile ID cannot be overwritten");
        }
        let ca = client_import::checked_ca_ref(ca_ref)
            .map_err(|_| "Explicit TLS CA reference is invalid or unreadable")?;
        // Only a NEW secret is ever written. A secretless public invitation
        // demands a separately supplied env: reference, never a default.
        let secret = if let Some(bytes) = invite.token_bytes() {
            let token = Zeroizing::new(bytes);
            Some(
                PrivateBearer::create(&self.path, &token)
                    .map_err(|_| "Cannot create protected bearer credential")?,
            )
        } else {
            None
        };
        let credential = match secret.as_ref() {
            Some(saved) => saved
                .reference()
                .map_err(|_| "Cannot build protected bearer reference")?,
            None => {
                let supplied =
                    public_ref.ok_or("Public invite requires explicit env: credential")?;
                if !client_import::valid_explicit_reference(supplied) {
                    return Err("Public invite requires a valid explicit env: reference");
                }
                supplied.to_owned()
            }
        };
        let profile = invite
            .to_profile(&credential, ca)
            .map_err(|_| "Invalid imported client profile")?;
        let has_trust = profile.tls_ca.is_some();
        let mut candidate = self.draft.clone();
        let Config::Client(candidate_doc) = &mut candidate else {
            return Err("Client config required");
        };
        candidate_doc.client.profiles.push(profile);
        candidate
            .validate()
            .map_err(|_| "Imported profile did not pass full document validation")?;
        self.commit_credential_candidate(candidate, secret, write)?;
        let Config::Client(updated) = &self.draft else {
            return Err("Client config required");
        };
        self.selected_record = updated.client.profiles.len() - 1;
        self.error = None;
        self.notice = if has_trust {
            "Профиль импортирован. TLS trust выбран, но соединение НЕ проверено и НЕ запущено."
        } else {
            "Профиль импортирован БЕЗ CA; запуск заблокирован до отдельного TLS trust."
        };
        Ok(())
    }

    fn commit_credential_candidate(
        &mut self,
        candidate: Config,
        mut secret: Option<PrivateBearer>,
        write: impl FnOnce(&Path, &Config, &[u8]) -> Result<Vec<u8>, config::WriteFailure>,
    ) -> Result<(), &'static str> {
        self.draft = candidate;
        if !self.save_with(write) {
            let uncertain = self.write_uncertain;
            if uncertain {
                // Do not delete a credential if replacement may have occurred,
                // even when the file cannot be read back or was edited again.
                if let Some(saved) = secret.as_mut() {
                    saved.commit();
                }
            }
            self.discard();
            return if uncertain {
                self.notice = "Состояние записи неизвестно: откройте редактор заново.";
                Err("TOML replacement may have completed; reload before using")
            } else {
                Err("Profile was not saved; guarded rollback completed")
            };
        }
        if let Some(saved) = secret.as_mut() {
            saved.commit();
        }
        Ok(())
    }

    /// A credential-only replacement is separate from ordinary import.
    /// It must not change the saved endpoint, TLS identity, trust or transport.
    fn refresh_target(&self, invite: &Invitation) -> Result<usize, &'static str> {
        if self.role != Role::Client || self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard all changes before credential replacement");
        }
        if !invite.has_token() {
            return Err("Credential replacement requires a confidential invitation");
        }
        let Config::Client(document) = &self.draft else {
            return Err("Client config required");
        };
        let index = document
            .client
            .profiles
            .iter()
            .position(|profile| profile.id == invite.id)
            .ok_or("Existing profile required")?;
        let profile = &document.client.profiles[index];
        if profile.server != invite.endpoint
            || profile.server_name != invite.server_name
            || profile.tls_profile != invite.tls_profile()
            || profile.xhttp_mode.is_some_and(|mode| mode != config::XhttpMode::StreamOne)
            || (invite.transport != Transport::Auto && profile.transport != invite.transport)
        {
            return Err("Invitation does not match saved profile identity and transport");
        }
        Ok(index)
    }

    pub(crate) fn can_refresh_credential(&self, invite: &Invitation) -> bool {
        self.refresh_target(invite).is_ok()
    }

    pub fn refresh_credential(&mut self, invite: &Invitation) -> Result<(), &'static str> {
        let result = self.refresh_credential_with(invite, config::guarded_write);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn refresh_credential_with(
        &mut self,
        invite: &Invitation,
        write: impl FnOnce(&Path, &Config, &[u8]) -> Result<Vec<u8>, config::WriteFailure>,
    ) -> Result<(), &'static str> {
        let index = self.refresh_target(invite)?;
        let bytes = invite
            .token_bytes()
            .ok_or("Confidential invitation required")?;
        let token = Zeroizing::new(bytes);
        let secret = PrivateBearer::create(&self.path, &token)
            .map_err(|_| "Cannot create protected bearer credential")?;
        let reference = secret
            .reference()
            .map_err(|_| "Cannot build protected bearer reference")?;
        let mut candidate = self.draft.clone();
        let Config::Client(document) = &mut candidate else {
            return Err("Client config required");
        };
        document.client.profiles[index].auth_token = reference;
        candidate
            .validate()
            .map_err(|_| "Updated profile did not pass full document validation")?;
        self.commit_credential_candidate(candidate, Some(secret), write)?;
        self.selected_record = index;
        self.error = None;
        self.notice = "Credential сохранён. Старый файл не удалён; runtime не обновлён.";
        Ok(())
    }

    /// Issue a new user with a cryptographically random 32-byte bearer.
    /// A saved digest is not a bearer and cannot be re-exported later.
    /// No invitation is revealable until the file write succeeds.
    pub fn issue_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        let result = self.try_issue_user(user_id);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn try_issue_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        if self.role != Role::Server || self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard edits and pending issuance first");
        }
        let Config::Server(doc) = &self.draft else {
            return Err("Server configuration required");
        };
        if user_id.is_empty()
            || user_id.len() > 64
            || !user_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err("User ID must use 1..64 ASCII letters, digits, - or _");
        }
        if doc.server.users.iter().any(|u| u.id == user_id) {
            return Err("User ID already exists");
        }
        let inbound_id = self.selected_record_id().to_owned();
        // Reject unusable auto invitations before consuming random input or
        // changing the draft (e.g., different H2/H3 public port numbers).
        Invitation::public_from_server(&self.draft, &inbound_id)
            .map_err(|_| "Selected inbound cannot issue auto invitations")?;

        let mut token = Zeroizing::new([0u8; 32]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut token[..])
            .map_err(|_| "Secure random generator unavailable")?;
        let digest = format!("{:x}", Sha256::digest(&token[..]));
        let mut candidate = self.draft.clone();
        let Config::Server(candidate_doc) = &mut candidate else {
            return Err("Server configuration required");
        };
        let Some(inbound) = candidate_doc.server.inbounds.get_mut(self.selected_record) else {
            return Err("Inbound missing");
        };
        inbound.allowed_user_ids.push(user_id.to_owned());
        candidate_doc.server.users.push(User {
            id: user_id.to_owned(),
            token_sha256: digest,
            disabled: false,
        });
        candidate
            .validate()
            .map_err(|_| "New user or grants did not pass validation")?;
        let invitation = Invitation::issued_from_server(&candidate, &inbound_id, user_id, &token)
            .map_err(|_| "Cannot issue invitation for selected inbound")?;
        // Commit draft only when all validations and permission checks succeed.
        self.draft = candidate;
        self.issued = Some(invitation);
        self.issued_ready = false;
        self.error = None;
        self.notice = "Новый пользователь: сохранить TOML перед выдачей ссылки.";
        Ok(())
    }

    /// M4.4b2b1: replace an existing enabled user's bearer without changing
    /// its identity, global enabled state or inbound grants. The replacement
    /// is revealed once only after a guarded durable save; it is not live
    /// until a separate explicit revisioned auth-only CAS Apply.
    pub fn rotate_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        let result = self.try_rotate_user(user_id, false);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    /// Explicit recovery of a disabled account always issues a fresh bearer.
    /// Preserve every existing grant; never revive the previous digest.
    pub fn reenable_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        let result = self.try_rotate_user(user_id, true);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn try_rotate_user(&mut self, user_id: &str, reenable: bool) -> Result<(), &'static str> {
        if self.role != Role::Server || self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard edits and pending issuance first");
        }
        let Config::Server(doc) = &self.draft else {
            return Err("Server configuration required");
        };
        let Some(inbound) = doc.server.inbounds.get(self.selected_record) else {
            return Err("Inbound missing");
        };
        if !inbound.allowed_user_ids.iter().any(|id| id == user_id) {
            return Err("User is not granted on the selected inbound");
        }
        let Some(user) = doc.server.users.iter().find(|user| user.id == user_id) else {
            return Err("User does not exist");
        };
        if user.disabled != reenable {
            return Err(if reenable {
                "Only a disabled user can be re-enabled"
            } else {
                "Disabled users require a separate explicit re-enable flow"
            });
        }
        let previous_digest = user.token_sha256.clone();
        let inbound_id = inbound.id.clone();
        Invitation::public_from_server(&self.draft, &inbound_id)
            .map_err(|_| "Selected inbound cannot issue auto invitations")?;

        let mut token = Zeroizing::new([0u8; 32]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut token[..])
            .map_err(|_| "Secure random generator unavailable")?;
        let digest = format!("{:x}", Sha256::digest(&token[..]));
        if digest == previous_digest {
            return Err("Replacement token must differ from current token");
        }
        let mut candidate = self.draft.clone();
        let Config::Server(candidate_doc) = &mut candidate else {
            return Err("Server configuration required");
        };
        let Some(user) = candidate_doc
            .server
            .users
            .iter_mut()
            .find(|user| user.id == user_id)
        else {
            return Err("User does not exist");
        };
        user.token_sha256 = digest;
        user.disabled = false;
        candidate
            .validate()
            .map_err(|_| "Rotated user did not pass configuration validation")?;
        let invitation = Invitation::issued_from_server(&candidate, &inbound_id, user_id, &token)
            .map_err(|_| "Cannot issue replacement invitation for selected inbound")?;
        self.draft = candidate;
        self.issued = Some(invitation);
        self.issued_ready = false;
        self.error = None;
        self.notice = if reenable {
            "Пользователь восстановлен с новым токеном в черновике. Runtime не обновлён."
        } else {
            "Токен заменён в черновике. Сохранение не обновляет runtime."
        };
        Ok(())
    }

    /// M4.4b2a: disable an existing bearer without attempting to recover
    /// or rotate its secret. The selected inbound must explicitly grant this
    /// user; the confirmation UI warns that disable is global to all inbounds.
    /// This changes only the local draft, never the running server.
    pub fn disable_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        let result = self.try_disable_user(user_id);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn try_disable_user(&mut self, user_id: &str) -> Result<(), &'static str> {
        if self.role != Role::Server || self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard edits and pending issuance first");
        }
        let Config::Server(doc) = &self.draft else {
            return Err("Server configuration required");
        };
        let Some(inbound) = doc.server.inbounds.get(self.selected_record) else {
            return Err("Inbound missing");
        };
        if !inbound.allowed_user_ids.iter().any(|id| id == user_id) {
            return Err("User is not granted on the selected inbound");
        }
        let Some(user) = doc.server.users.iter().find(|user| user.id == user_id) else {
            return Err("User does not exist");
        };
        if user.disabled {
            return Err("User is already disabled");
        }
        let mut candidate = self.draft.clone();
        let Config::Server(candidate_doc) = &mut candidate else {
            return Err("Server configuration required");
        };
        let Some(user) = candidate_doc
            .server
            .users
            .iter_mut()
            .find(|user| user.id == user_id)
        else {
            return Err("User does not exist");
        };
        user.disabled = true;
        candidate
            .validate()
            .map_err(|_| "Disabled user did not pass configuration validation")?;
        self.draft = candidate;
        self.error = None;
        self.notice = "Пользователь отключён в черновике. Сохранение не обновляет runtime.";
        Ok(())
    }

    pub fn issued_ready(&self) -> bool {
        self.issued.is_some() && self.issued_ready && !self.dirty()
    }

    /// Exactly one successful retrieval, only after a durable store.
    pub fn take_issued(&mut self) -> Option<Invitation> {
        if !self.issued_ready() {
            return None;
        }
        self.issued_ready = false;
        let invite = self.issued.take()?;
        if !config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.source) {
            self.error = Some("Saved configuration changed; issuance refused".into());
            return None;
        }
        // The saved TOML alone does not bind external certificate bytes.
        // Consume the one-time offer if its exact pin/mode is no longer current.
        if invite.tls_profile() != "default"
            && !Invitation::public_from_server(&self.original, &invite.id)
                .is_ok_and(|current| current.tls_profile() == invite.tls_profile())
        {
            self.error = Some("Saved certificate or TLS profile changed; issuance refused".into());
            return None;
        }
        Some(invite)
    }

    /// Export only saved public profile metadata. This never accesses a
    /// bearer file, environment secret or server digest for issuance.
    pub fn public_share(&self) -> Result<String, &'static str> {
        if self.editing || self.dirty() || self.issued.is_some() {
            return Err("Finish or discard changes and pending issuance first");
        }
        if !config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.source) {
            return Err("Saved configuration changed; reload before sharing");
        }
        let invite = match &self.original {
            Config::Server(_) => {
                Invitation::public_from_server(&self.original, self.selected_record_id())
            }
            Config::Client(doc) => {
                let profile = doc
                    .client
                    .profiles
                    .get(self.selected_record)
                    .ok_or("Selected profile missing")?;
                Invitation::public_from_profile(profile)
            }
        }
        .map_err(|_| "Selected record cannot be shared without preserving its TLS profile")?;
        invite.encode().map_err(|_| "Public invitation unavailable")
    }

    /// Consume the confirmed one-time offer, without rendering the URI.
    /// A stale saved document or failed export does not make the token
    /// available for another attempt.
    pub fn export_issued_file(&mut self) -> Result<PathBuf, &'static str> {
        if self.role != Role::Server {
            return Err("Server issuance required");
        }
        let invite = self.take_issued().ok_or("No saved invitation available")?;
        client_import::export_invitation_file(&self.path, &invite)
            .map_err(|_| "Protected export failed; issue or rotate again")
    }

    pub fn clear_issued(&mut self) {
        self.issued = None;
        self.issued_ready = false;
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn record_count(&self) -> usize {
        match &self.draft {
            Config::Server(doc) => doc.server.inbounds.len(),
            Config::Client(doc) => doc.client.profiles.len(),
        }
    }

    pub fn selected_record_id(&self) -> &str {
        match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .map_or("", |inbound| inbound.id.as_str()),
            Config::Client(doc) => doc
                .client
                .profiles
                .get(self.selected_record)
                .map_or("", |profile| profile.id.as_str()),
        }
    }

    /// Preview only the operator's saved local identity. The third-party
    /// candidate review cannot authorize this separate configuration change.
    pub(crate) fn review_pinned_mode(
        &self,
        stream_up: bool,
    ) -> Result<PinnedModeReview, &'static str> {
        if self.editing
            || self.dirty()
            || self.issued.is_some()
            || !config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.source)
        {
            return Err("Save/reload clean server config first");
        }
        let Config::Server(doc) = &self.original else {
            return Err("Server required");
        };
        if !doc.server.enabled {
            return Err("Server disabled");
        }
        let inbound = doc
            .server
            .inbounds
            .get(self.selected_record)
            .ok_or("Inbound missing")?;
        let tcp: std::net::SocketAddr =
            inbound.h2_listen.parse().map_err(|_| "Invalid TCP bind")?;
        let udp: std::net::SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| "Invalid UDP bind")?;
        if tcp.port() != udp.port() || tcp.port() == 0 {
            return Err("H2/H3 ports must agree");
        }
        let pin = crate::server::configured_certificate_pin(inbound)
            .map_err(|_| "Cannot verify saved certificate/key")?;
        Ok(PinnedModeReview {
            source: self.saved_sha256(),
            inbound: inbound.id.clone(),
            name: inbound.server_name.clone(),
            endpoint: format!("{}:{}", inbound.server_name, tcp.port()),
            pin,
            mode: if stream_up {
                crate::security_profile::SecurityMode::PinnedCertStreamUpV1
            } else {
                crate::security_profile::SecurityMode::PinnedCertV1
            },
        })
    }

    pub(crate) fn apply_pinned_mode(
        &mut self,
        review: &PinnedModeReview,
    ) -> Result<(), &'static str> {
        let current = self.review_pinned_mode(review.mode.is_stream_up())?;
        if current.source != review.source
            || current.inbound != review.inbound
            || current.name != review.name
            || current.endpoint != review.endpoint
            || current.pin != review.pin
        {
            return Err("Configuration or certificate changed; review again");
        }
        let Config::Server(doc) = &mut self.draft else {
            return Err("Server required");
        };
        let inbound = doc
            .server
            .inbounds
            .get_mut(self.selected_record)
            .ok_or("Inbound missing")?;
        inbound.security_mode = review.mode;
        if !self.save() {
            // Preserve uncertain-write protection; never assert rollback of a
            // committed file if the guarded writer cannot establish outcome.
            if !self.write_uncertain {
                self.draft = self.original.clone();
            }
            return Err("Guarded save failed; inspect/reload configuration");
        }
        Ok(())
    }

    /// Validated server SNI for the currently selected inbound only.
    /// No token, private key, client credential or implicit DNS resolution.
    pub fn selected_server_name(&self) -> Option<&str> {
        let Config::Server(doc) = &self.draft else {
            return None;
        };
        doc.server
            .inbounds
            .get(self.selected_record)
            .map(|inbound| inbound.server_name.as_str())
    }

    pub fn selected_record_is_active(&self) -> bool {
        match &self.draft {
            Config::Client(doc) => doc.client.active_profile == self.selected_record_id(),
            Config::Server(_) => false,
        }
    }

    pub fn selection_summary(&self) -> String {
        match self.role {
            Role::Server => format!(
                "Inbound {}/{}: {}",
                self.selected_record + 1,
                self.record_count(),
                self.selected_record_id(),
            ),
            Role::Client => format!(
                "Профиль {}/{}: {}{}",
                self.selected_record + 1,
                self.record_count(),
                self.selected_record_id(),
                if self.selected_record_is_active() {
                    " [активный]"
                } else {
                    " [неактивный]"
                },
            ),
        }
    }

    pub fn field_count(&self) -> usize {
        match self.role {
            Role::Server => 3,
            Role::Client => 4,
        }
    }

    /// Record and field focus never change the typed configuration.
    pub fn select_record(&mut self, forward: bool) {
        if self.editing || self.issued.is_some() {
            return;
        }
        let count = self.record_count();
        if count == 0 {
            return;
        }
        self.selected_record = if forward {
            (self.selected_record + 1) % count
        } else {
            (self.selected_record + count - 1) % count
        };
        self.selected_field = 0;
        self.error = None;
    }

    pub fn select_field(&mut self, forward: bool) {
        if self.editing || self.issued.is_some() {
            return;
        }
        self.selected_field = if forward {
            (self.selected_field + 1) % self.field_count()
        } else {
            (self.selected_field + self.field_count() - 1) % self.field_count()
        };
        self.error = None;
    }

    pub fn field_name(&self) -> String {
        let suffix = match self.role {
            Role::Server => ["server_name", "h2_listen", "quic_listen"][self.selected_field],
            Role::Client => ["server", "server_name", "transport", "xhttp_mode"][self.selected_field],
        };
        let records = match self.role {
            Role::Server => "server.inbounds",
            Role::Client => "client.profiles",
        };
        format!("{records}[{}].{suffix}", self.selected_record)
    }

    pub fn field_value(&self) -> String {
        match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .map(|inbound| match self.selected_field {
                    0 => inbound.server_name.clone(),
                    1 => inbound.h2_listen.clone(),
                    _ => inbound.quic_listen.clone(),
                })
                .unwrap_or_default(),
            Config::Client(doc) => doc
                .client
                .profiles
                .get(self.selected_record)
                .map(|profile| match self.selected_field {
                    0 => profile.server.clone(),
                    1 => profile.server_name.clone(),
                    2 => match profile.transport {
                        Transport::Auto => "auto".to_owned(),
                        Transport::H2 => "h2".to_owned(),
                        Transport::H3 => "h3".to_owned(),
                    },
                    _ => xhttp_value(profile.xhttp_mode),
                })
                .unwrap_or_default(),
        }
    }

    /// Render only the explicitly whitelisted non-secret fields.
    /// Never include token refs, TLS key refs, grants, or config file paths.
    pub fn fields_overview(&self) -> String {
        let labels: &[&str] = match self.role {
            Role::Server => &["TLS DNS", "H2 TCP", "H3 UDP"],
            Role::Client => &["Endpoint", "TLS SNI", "Transport", "XHTTP"],
        };
        let values: Vec<String> = match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .map(|inbound| {
                    vec![
                        inbound.server_name.clone(),
                        inbound.h2_listen.clone(),
                        inbound.quic_listen.clone(),
                    ]
                })
                .unwrap_or_default(),
            Config::Client(doc) => doc
                .client
                .profiles
                .get(self.selected_record)
                .map(|p| {
                    vec![
                        p.server.clone(),
                        p.server_name.clone(),
                        match p.transport {
                            Transport::Auto => "auto".to_owned(),
                            Transport::H2 => "h2".to_owned(),
                            Transport::H3 => "h3".to_owned(),
                        },
                        xhttp_value(p.xhttp_mode),
                    ]
                })
                .unwrap_or_default(),
        };
        let mut output = String::new();
        for (index, (label, value)) in labels.iter().zip(values).enumerate() {
            let marker = if self.selected_field == index {
                '>'
            } else {
                ' '
            };
            let value = if self.editing && self.selected_field == index {
                self.input.as_str()
            } else {
                value.as_str()
            };
            output.push_str(&format!("{marker} {}: {value}\n", label));
        }
        output
    }

    pub(crate) fn write_uncertain(&self) -> bool {
        self.write_uncertain
    }

    pub fn dirty(&self) -> bool {
        self.write_uncertain || self.draft != self.original
    }

    /// An exact digest of the bytes last loaded or durably saved by this
    /// editor. It is NOT the dirty draft or a bearer credential. The running
    /// Linux server must verify the same bytes before accepting TUI Apply.
    pub(crate) fn saved_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.source).into()
    }

    #[cfg(windows)]
    pub(crate) fn saved_path(&self) -> &Path {
        &self.path
    }

    pub fn begin(&mut self) {
        if self.write_uncertain {
            self.error = Some("config: uncertain previous write; reload editor".into());
            return;
        }
        if self.issued.is_some() {
            self.error = Some("Завершите одноразовую выдачу ссылки.".into());
            return;
        }
        if self.record_count() == 0 {
            self.error = Some("Нет записей для редактирования".into());
            return;
        }
        self.input = self.field_value();
        self.editing = true;
        self.error = None;
    }

    pub fn insert(&mut self, ch: char) {
        if self.editing && ch.is_ascii_graphic() && self.input.len() < MAX_INPUT {
            self.input.push(ch);
        }
    }

    pub fn backspace(&mut self) {
        if self.editing {
            self.input.pop();
        }
    }

    pub fn cancel(&mut self) {
        self.input.clear();
        self.editing = false;
        self.error = None;
    }

    /// Every field edit validates the *whole* typed document, including
    /// overlapping inbound TCP/UDP binds and client TLS/profile constraints.
    pub fn accept(&mut self) -> bool {
        if !self.editing {
            return false;
        }
        let mut candidate = self.draft.clone();
        let field = self.field_name();
        match &mut candidate {
            Config::Server(doc) => {
                let Some(inbound) = doc.server.inbounds.get_mut(self.selected_record) else {
                    self.error = Some("server.inbounds: selected record missing".into());
                    return false;
                };
                match self.selected_field {
                    0 => inbound.server_name.clone_from(&self.input),
                    1 => inbound.h2_listen.clone_from(&self.input),
                    _ => inbound.quic_listen.clone_from(&self.input),
                }
            }
            Config::Client(doc) => {
                let Some(profile) = doc.client.profiles.get_mut(self.selected_record) else {
                    self.error = Some("client.profiles: selected record missing".into());
                    return false;
                };
                match self.selected_field {
                    0 => profile.server.clone_from(&self.input),
                    1 => profile.server_name.clone_from(&self.input),
                    2 => {
                        profile.transport = match self.input.as_str() {
                            "auto" => Transport::Auto,
                            "h2" => Transport::H2,
                            "h3" => Transport::H3,
                            _ => {
                                self.error = Some(format!("{field}: expected auto, h2 or h3"));
                                return false;
                            }
                        };
                    }
                    _ => {
                        profile.xhttp_mode = match self.input.as_str() {
                            "legacy" => None,
                            "auto" => Some(XhttpMode::Auto),
                            "stream-one" => Some(XhttpMode::StreamOne),
                            "stream-up" => Some(XhttpMode::StreamUp),
                            _ => {
                                self.error = Some(format!(
                                    "{field}: expected auto, stream-one, stream-up or legacy"
                                ));
                                return false;
                            }
                        };
                    }
                }
            }
        }
        if let Err(error) = candidate.validate() {
            self.error = Some(error.to_string());
            return false;
        }
        self.draft = candidate;
        self.cancel();
        self.notice = if self.dirty() {
            "Не сохранено. Ctrl+S: проверить и сохранить."
        } else {
            "Изменений нет."
        };
        true
    }

    pub fn discard(&mut self) {
        self.draft = self.original.clone();
        self.clear_issued();
        self.cancel();
        self.notice = "Изменения отменены.";
    }

    /// Refuse externally modified files and failed validation; never apply/reload.
    pub fn save(&mut self) -> bool {
        self.save_with(config::guarded_write)
    }

    fn save_with(
        &mut self,
        write: impl FnOnce(&Path, &Config, &[u8]) -> Result<Vec<u8>, config::WriteFailure>,
    ) -> bool {
        if self.write_uncertain {
            self.error = Some("config: uncertain previous write; reload editor".into());
            return false;
        }
        if self.editing {
            self.error = Some("Завершите редактирование поля клавишей Enter.".into());
            return false;
        }
        if !self.dirty() {
            self.notice = "Изменений нет.";
            self.error = None;
            return true;
        }
        if let Err(error) = self.draft.validate() {
            self.error = Some(error.to_string());
            return false;
        }
        match write(&self.path, &self.draft, &self.source) {
            Ok(bytes) => self.source = bytes,
            Err(config::WriteFailure::BeforeReplace(error)) => {
                self.error = Some(error.to_string());
                return false;
            }
            Err(config::WriteFailure::AfterReplace(error)) => {
                self.write_uncertain = true;
                self.clear_issued();
                self.error = Some(error.to_string());
                self.notice = "Состояние записи неизвестно: откройте редактор заново.";
                return false;
            }
        }
        self.original = self.draft.clone();
        self.error = None;
        self.notice = "Сохранено в TOML; runtime ещё не обновлён.";
        self.issued_ready = self.issued.is_some();
        true
    }
}

fn role_matches(role: Role, doc: &Config) -> bool {
    matches!(
        (role, doc),
        (Role::Server, Config::Server(_)) | (Role::Client, Config::Client(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn write(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "theia-tui-editor-{}-{}.toml",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&path, contents).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            if let Ok(lock) = config::lock_path(&self.0) {
                let _ = fs::remove_file(lock);
            }
        }
    }

    fn server_source() -> String {
        include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest([0x42; 32])),
        )
    }

    fn two_inbounds() -> String {
        let Config::Server(mut doc) = config::parse(&server_source()).unwrap() else {
            panic!("server fixture");
        };
        let mut second = doc.server.inbounds[0].clone();
        second.id = "backup".into();
        second.h2_listen = "0.0.0.0:8443".into();
        second.quic_listen = "0.0.0.0:8443".into();
        doc.server.inbounds.push(second);
        Config::Server(doc).to_toml().unwrap()
    }

    fn two_profiles() -> String {
        let Config::Client(mut doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture");
        };
        let mut second = doc.client.profiles[0].clone();
        second.id = "work".into();
        second.server = "work.example.org:443".into();
        second.server_name = "work.example.org".into();
        doc.client.profiles.push(second);
        Config::Client(doc).to_toml().unwrap()
    }

    fn uncertain_failure() -> config::WriteFailure {
        config::WriteFailure::AfterReplace(config::ConfigError {
            field: "config".into(),
            reason: "injected directory sync failure",
        })
    }

    #[test]
    fn pinned_mode_review_refuses_drift_and_saves_only_explicit_local_mode() {
        use crate::security_profile::{CertificatePin, SecurityMode};
        let generated =
            rcgen::generate_simple_self_signed(vec!["edge.example.org".into()]).unwrap();
        let certificate = Temp::write(&generated.cert.pem());
        let key = Temp::write(&generated.key_pair.serialize_pem());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key.0, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let Config::Server(mut doc) = config::parse(&server_source()).unwrap() else {
            panic!("server fixture");
        };
        doc.server.inbounds[0].tls_cert = format!("file:{}", certificate.0.display());
        doc.server.inbounds[0].tls_key = format!("file:{}", key.0.display());
        let source = Config::Server(doc.clone()).to_toml().unwrap();
        let file = Temp::write(&source);
        let mut editor = Editor::load(Role::Server, &file.0).unwrap();
        let review = editor.review_pinned_mode(false).unwrap();
        assert!(review.pin == CertificatePin::from_der(generated.cert.der().as_ref()));
        assert!(review.body().contains("pinned-cert-v1:"));
        assert_eq!(fs::read_to_string(&file.0).unwrap(), source);
        fs::write(&file.0, format!("{source}\n# external edit")).unwrap();
        assert!(editor.apply_pinned_mode(&review).is_err());
        assert!(fs::read_to_string(&file.0)
            .unwrap()
            .contains("external edit"));
        fs::write(&file.0, &source).unwrap();

        fs::write(&certificate.0, "invalid certificate").unwrap();
        assert!(editor.apply_pinned_mode(&review).is_err());
        assert_eq!(fs::read_to_string(&file.0).unwrap(), source);
        fs::write(&certificate.0, generated.cert.pem()).unwrap();

        editor.apply_pinned_mode(&review).unwrap();
        assert!(!editor.dirty());
        let Config::Server(saved) = config::read_file(&file.0).unwrap() else {
            panic!("saved server");
        };
        assert_eq!(
            saved.server.inbounds[0].security_mode,
            SecurityMode::PinnedCertV1
        );
        let mut expected = doc.clone();
        expected.server.inbounds[0].security_mode = SecurityMode::PinnedCertV1;
        assert_eq!(saved, expected);
        let public = Invitation::decode(&editor.public_share().unwrap()).unwrap();
        assert_eq!(public.tls_profile(), review.pin.profile());
        assert!(!public.has_token());
        assert!(crate::reload_preflight::assess_reload(&doc, &saved).is_err());
        assert!(!crate::restart_guard::same_port_tls_only(&doc, &saved));
        assert!(editor.apply_pinned_mode(&review).is_err());
        let split = editor.review_pinned_mode(true).unwrap();
        assert!(split.body().contains("pinned-cert-stream-up-v1:"));
        editor.apply_pinned_mode(&split).unwrap();
        let Config::Server(saved) = config::read_file(&file.0).unwrap() else {
            panic!("saved server");
        };
        assert_eq!(
            saved.server.inbounds[0].security_mode,
            SecurityMode::PinnedCertStreamUpV1
        );
        let public = Invitation::decode(&editor.public_share().unwrap()).unwrap();
        assert_eq!(public.tls_profile(), split.pin.stream_up_profile());
        assert!(!public.has_token());
    }

    #[test]
    fn pinned_invitation_issue_import_refresh_and_certificate_drift() {
        use crate::security_profile::{CertificatePin, SecurityMode};

        let generated =
            rcgen::generate_simple_self_signed(vec!["edge.example.org".into()]).unwrap();
        let certificate = Temp::write(&generated.cert.pem());
        let key = Temp::write(&generated.key_pair.serialize_pem());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key.0, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pin = CertificatePin::from_der(generated.cert.der().as_ref());
        for (mode, profile) in [
            (SecurityMode::PinnedCertV1, pin.profile()),
            (SecurityMode::PinnedCertStreamUpV1, pin.stream_up_profile()),
        ] {
            let Config::Server(mut doc) = config::parse(&server_source()).unwrap() else {
                panic!("server fixture");
            };
            let inbound = &mut doc.server.inbounds[0];
            inbound.tls_cert = format!("file:{}", certificate.0.display());
            inbound.tls_key = format!("file:{}", key.0.display());
            inbound.security_mode = mode;
            let source = Temp::write(&Config::Server(doc).to_toml().unwrap());
            let mut issuer = Editor::load(Role::Server, &source.0).unwrap();
            issuer.issue_user("new-device").unwrap();
            assert!(issuer.take_issued().is_none());
            assert!(issuer.save());
            let issued = issuer.take_issued().unwrap();
            let link = Zeroizing::new(issued.encode().unwrap());
            assert!(link.starts_with("theia://v1/"));
            assert_eq!(issued.tls_profile(), profile);
            assert!(issuer.take_issued().is_none());

            let client_file = Temp::write(include_str!("../../../examples/client.toml"));
            let mut client = Editor::load(Role::Client, &client_file.0).unwrap();
            let received = client_import::read_source(&link).unwrap();
            let ca = format!("file:{}", certificate.0.display());
            client
                .import_invitation(&received, Some(&ca), None)
                .unwrap();
            let Config::Client(saved) = config::read_file(&client_file.0).unwrap() else {
                panic!("client fixture");
            };
            assert_eq!(saved.client.active_profile, "home");
            let imported = &saved.client.profiles[1];
            assert_eq!(imported.tls_profile, profile);
            assert_eq!(imported.tls_ca.as_deref(), Some(ca.as_str()));
            let old_secret = PathBuf::from(imported.auth_token.strip_prefix("file:").unwrap());

            // Refresh only the bearer, never a pin, CA or carrier.
            let plain = Invitation::issued_from_server(
                &config::parse(&server_source()).unwrap(),
                "public",
                "device-a",
                &[0x42; 32],
            )
            .unwrap();
            assert!(!client.can_refresh_credential(&plain));
            issuer.rotate_user("new-device").unwrap();
            assert!(issuer.save());
            let rotated = issuer.take_issued().unwrap();
            assert!(client.can_refresh_credential(&rotated));
            client.refresh_credential(&rotated).unwrap();
            let Config::Client(updated) = config::read_file(&client_file.0).unwrap() else {
                panic!("client fixture");
            };
            let updated = &updated.client.profiles[1];
            assert_eq!(updated.tls_profile, imported.tls_profile);
            assert_eq!(updated.tls_ca, imported.tls_ca);
            assert_eq!(updated.transport, imported.transport);
            let new_secret = PathBuf::from(updated.auth_token.strip_prefix("file:").unwrap());
            assert_ne!(new_secret, old_secret);
            assert!(old_secret.is_file());
            remove_fixture_secret(&old_secret);
            remove_fixture_secret(&new_secret);

            // Changed/unreadable external cert after save consumes the offer.
            issuer.rotate_user("new-device").unwrap();
            assert!(issuer.save());
            fs::write(&certificate.0, "invalid certificate").unwrap();
            assert!(issuer.take_issued().is_none());
            assert!(issuer.public_share().is_err());
            fs::write(&certificate.0, generated.cert.pem()).unwrap();
            assert!(issuer.take_issued().is_none());
        }
    }

    #[test]
    fn uncertain_server_save_suppresses_issuance_and_requires_reopen() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.issue_user("new-device").unwrap();
        assert!(!editor.save_with(|path, candidate, expected| {
            config::guarded_write(path, candidate, expected)?;
            Err(uncertain_failure())
        }));
        assert!(editor.dirty());
        assert!(!editor.issued_ready());
        assert!(editor.take_issued().is_none());
        assert!(fs::read_to_string(&temp.0).unwrap().contains("new-device"));
        editor.discard();
        assert!(editor.dirty());
        assert!(!editor.save());
        assert!(editor.issue_user("another").is_err());
        let mut reopened = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(!reopened.dirty());
        assert!(reopened.take_issued().is_none());
        assert!(reopened.issue_user("new-device").is_err());
    }

    #[test]
    fn uncertain_client_import_retains_potentially_referenced_secret() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();

        let result = editor.try_import_invitation(&invite, None, None, |path, doc, expected| {
            config::guarded_write(path, doc, expected)?;
            Err(uncertain_failure())
        });
        assert!(result.is_err());
        assert!(editor.dirty());
        assert!(!editor.save());
        assert!(editor.import_invitation(&invite, None, None).is_err());

        let Config::Client(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(doc.client.active_profile, "home");
        assert_eq!(doc.client.profiles.len(), 2);
        let reference = &doc.client.profiles[1].auth_token;
        let secret = Path::new(reference.strip_prefix("file:").unwrap());
        assert_eq!(
            fs::read_to_string(secret).unwrap(),
            URL_SAFE_NO_PAD.encode([0x42; 32])
        );
        let mut reopened = Editor::load(Role::Client, &temp.0).unwrap();
        assert!(!reopened.dirty());
        assert!(reopened.import_invitation(&invite, None, None).is_err());
        fs::remove_file(secret).unwrap();
        fs::remove_dir(secret.parent().unwrap()).unwrap();
    }

    #[test]
    fn uncertain_import_retains_secret_even_when_readback_is_unavailable() {
        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let mut retained = None;

        let result = editor.try_import_invitation(&invite, None, None, |path, doc, expected| {
            config::guarded_write(path, doc, expected)?;
            let Config::Client(doc) = doc else {
                panic!("client");
            };
            let reference = &doc.client.profiles[1].auth_token;
            retained = Some(PathBuf::from(reference.strip_prefix("file:").unwrap()));
            fs::remove_file(path).unwrap();
            Err(uncertain_failure())
        });
        assert!(result.is_err());
        assert!(editor.dirty());
        let retained = retained.unwrap();
        assert!(retained.is_file());
        assert!(!temp.0.exists());
        fs::remove_file(&retained).unwrap();
        fs::remove_dir(retained.parent().unwrap()).unwrap();
    }

    #[test]
    fn pre_replace_import_refusal_rolls_back_only_new_credential() {
        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let initial = include_str!("../../../examples/client.toml");
        let temp = Temp::write(initial);
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let mut discarded = None;

        let result = editor.try_import_invitation(&invite, None, None, |_, doc, _| {
            let Config::Client(doc) = doc else {
                panic!("client");
            };
            let reference = &doc.client.profiles[1].auth_token;
            let secret = PathBuf::from(reference.strip_prefix("file:").unwrap());
            assert!(secret.is_file());
            discarded = Some(secret);
            Err(config::WriteFailure::BeforeReplace(config::ConfigError {
                field: "config".into(),
                reason: "injected pre-replacement refusal",
            }))
        });
        assert!(result.is_err());
        assert!(!editor.dirty());
        let discarded = discarded.unwrap();
        assert!(!discarded.exists());
        assert!(!discarded.parent().unwrap().exists());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), initial);
    }

    #[test]
    fn protected_export_consumes_offer_and_imports_exact_issued_bearer() {
        let server = Temp::write(&server_source());
        let mut issuer = Editor::load(Role::Server, &server.0).unwrap();
        assert!(issuer.export_issued_file().is_err());
        issuer.issue_user("export-device").unwrap();
        assert!(issuer.export_issued_file().is_err());
        assert!(issuer.save());
        let path = issuer.export_issued_file().unwrap();
        assert!(path.is_absolute());
        assert!(issuer.export_issued_file().is_err());
        assert!(issuer.take_issued().is_none());

        let invite = client_import::read_source(path.to_str().unwrap()).unwrap();
        let token = Zeroizing::new(invite.token_bytes().unwrap());
        let Config::Server(doc) = config::read_file(&server.0).unwrap() else {
            panic!("server");
        };
        let user = doc
            .server
            .users
            .iter()
            .find(|u| u.id == "export-device")
            .unwrap();
        assert_eq!(user.token_sha256, format!("{:x}", Sha256::digest(*token)));
        let client = Temp::write(include_str!("../../../examples/client.toml"));
        let mut importer = Editor::load(Role::Client, &client.0).unwrap();
        importer.import_invitation(&invite, None, None).unwrap();
        let Config::Client(doc) = config::read_file(&client.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(doc.client.active_profile, "home");
        let reference = &doc.client.profiles[1].auth_token;
        let secret = Path::new(reference.strip_prefix("file:").unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let directory = path.parent().unwrap();
            let mode = fs::metadata(directory).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        fs::remove_file(secret).unwrap();
        fs::remove_dir(secret.parent().unwrap()).unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn rotation_export_is_new_bearer_and_preserves_existing_grants() {
        let server = Temp::write(&server_source());
        let initial = config::read_file(&server.0).unwrap();
        let mut editor = Editor::load(Role::Server, &server.0).unwrap();
        editor.rotate_user("device-a").unwrap();
        assert!(editor.save());
        let first = editor.export_issued_file().unwrap();
        let invite = client_import::read_source(first.to_str().unwrap()).unwrap();
        let token = Zeroizing::new(invite.token_bytes().unwrap());
        assert!(*token != [0x42; 32]);

        let Config::Server(before) = initial else {
            panic!("server");
        };
        let Config::Server(after) = config::read_file(&server.0).unwrap() else {
            panic!("server");
        };
        assert_eq!(before.server.inbounds, after.server.inbounds);
        assert_eq!(
            after.server.users[0].token_sha256,
            format!("{:x}", Sha256::digest(*token))
        );
        assert!(!after.server.users[0].disabled);
        assert!(editor.export_issued_file().is_err());
        editor.rotate_user("device-a").unwrap();
        assert!(editor.save());
        let second = editor.export_issued_file().unwrap();
        assert_ne!(first, second);
        let old = client_import::read_source(first.to_str().unwrap()).unwrap();
        assert!(old.token_bytes() == Some(*token));
        let newer = client_import::read_source(second.to_str().unwrap()).unwrap();
        assert!(newer.token_bytes() != Some(*token));
        for path in [first, second] {
            fs::remove_file(&path).unwrap();
            fs::remove_dir(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn public_share_uses_saved_selected_record_without_credentials_or_writes() {
        let server = Temp::write(&server_source());
        let mut issuer = Editor::load(Role::Server, &server.0).unwrap();
        let original = fs::read(&server.0).unwrap();
        let link = issuer.public_share().unwrap();
        let invite = Invitation::decode(&link).unwrap();
        assert!(!invite.has_token());
        assert_eq!(invite.id, "public");
        assert!(issuer.take_issued().is_none());
        assert_eq!(fs::read(&server.0).unwrap(), original);
        issuer.issue_user("pending-device").unwrap();
        assert!(issuer.public_share().is_err());
        issuer.discard();
        assert!(issuer.public_share().is_ok());
        let mut external = original;
        external.extend_from_slice(b"\n# changed\n");
        fs::write(&server.0, external).unwrap();
        assert!(issuer.public_share().is_err());

        let client = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &client.0).unwrap();
        let before = fs::read(&client.0).unwrap();
        let link = editor.public_share().unwrap();
        let invite = Invitation::decode(&link).unwrap();
        assert!(!invite.has_token());
        assert_eq!(invite.id, "home");
        assert_eq!(fs::read(&client.0).unwrap(), before);
        editor.begin();
        assert!(editor.public_share().is_err());
    }

    #[cfg(feature = "experimental-btls-h2")]
    #[test]
    fn public_share_refuses_named_tls_profile_without_downgrade() {
        let source = include_str!("../../../examples/client.toml");
        let Config::Client(mut doc) = config::parse(source).unwrap() else {
            panic!("client");
        };
        doc.client.profiles[0].transport = Transport::H2;
        doc.client.profiles[0].tls_profile = "browser-h2-btls-v1".into();
        let temp = Temp::write(&Config::Client(doc).to_toml().unwrap());
        let editor = Editor::load(Role::Client, &temp.0).unwrap();
        assert!(editor.public_share().is_err());
    }

    #[test]
    fn public_share_refuses_unrepresentable_port_pair() {
        let server = config::parse(&server_source()).unwrap();
        let Config::Server(mut server) = server else {
            panic!("server");
        };
        server.server.inbounds[0].quic_listen = "0.0.0.0:444".into();
        let source = Config::Server(server).to_toml().unwrap();
        let temp = Temp::write(&source);
        let editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.public_share().is_err());
    }

    #[test]
    fn stale_saved_issuance_cannot_be_revealed_directly() {
        let server = Temp::write(&server_source());
        let mut issuer = Editor::load(Role::Server, &server.0).unwrap();
        issuer.issue_user("reveal-device").unwrap();
        assert!(issuer.save());
        let current = fs::read_to_string(&server.0).unwrap();
        fs::write(&server.0, format!("# changed externally\n{current}")).unwrap();
        assert!(issuer.take_issued().is_none());
        assert!(!issuer.issued_ready());
        assert!(issuer.export_issued_file().is_err());
    }

    #[test]
    fn stale_saved_issuance_cannot_be_exported_or_revealed_after_refusal() {
        let server = Temp::write(&server_source());
        let mut issuer = Editor::load(Role::Server, &server.0).unwrap();
        issuer.issue_user("export-device").unwrap();
        assert!(issuer.save());
        let current = fs::read_to_string(&server.0).unwrap();
        fs::write(&server.0, format!("# changed externally\n{current}")).unwrap();
        assert!(issuer.export_issued_file().is_err());
        assert!(issuer.take_issued().is_none());
        assert!(issuer.export_issued_file().is_err());
    }

    fn refresh_fixture(token: [u8; 32]) -> Invitation {
        let source = include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest(token)),
        );
        let server = config::parse(&source).unwrap();
        Invitation::issued_from_server(&server, "public", "device-a", &token).unwrap()
    }

    fn saved_secret(config: &Config) -> PathBuf {
        let Config::Client(doc) = config else {
            panic!("client");
        };
        let reference = &doc.client.profiles[1].auth_token;
        PathBuf::from(reference.strip_prefix("file:").unwrap())
    }

    fn remove_fixture_secret(path: &Path) {
        fs::remove_file(path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn credential_replacement_changes_only_reference_and_preserves_old_file() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let initial = refresh_fixture([0x42; 32]);
        editor.import_invitation(&initial, None, None).unwrap();
        let mut before = config::read_file(&temp.0).unwrap();
        let Config::Client(doc) = &mut before else {
            panic!("client");
        };
        // Simulate operator-selected existing transport and trust reference.
        doc.client.profiles[1].transport = Transport::H2;
        let trust = "file:/existing-ca.pem".to_owned();
        doc.client.profiles[1].tls_ca = Some(trust);
        doc.client.active_profile = "public".into();
        config::atomic_write(&temp.0, &before).unwrap();
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let old = saved_secret(&before);
        let replacement = refresh_fixture([0x43; 32]);
        assert!(editor.can_refresh_credential(&replacement));
        assert!(editor.import_invitation(&replacement, None, None).is_err());
        editor.refresh_credential(&replacement).unwrap();
        let after = config::read_file(&temp.0).unwrap();
        let new = saved_secret(&after);
        assert_ne!(old, new);
        assert_eq!(
            fs::read_to_string(&old).unwrap(),
            URL_SAFE_NO_PAD.encode([0x42; 32])
        );
        assert_eq!(
            fs::read_to_string(&new).unwrap(),
            URL_SAFE_NO_PAD.encode([0x43; 32])
        );
        let Config::Client(doc) = &mut before else {
            panic!("client");
        };
        doc.client.profiles[1].auth_token = format!("file:{}", new.display());
        assert_eq!(after, before);
        remove_fixture_secret(&old);
        remove_fixture_secret(&new);
    }

    #[test]
    fn credential_replacement_refuses_wrong_identity_public_and_stale_documents() {
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let initial = refresh_fixture([0x42; 32]);
        assert!(editor.refresh_credential(&initial).is_err());
        editor.import_invitation(&initial, None, None).unwrap();
        let before = fs::read(&temp.0).unwrap();
        let old = saved_secret(&config::read_file(&temp.0).unwrap());
        let server = config::parse(&server_source()).unwrap();
        let public = Invitation::public_from_server(&server, "public").unwrap();
        assert!(editor.refresh_credential(&public).is_err());
        let mut wrong = refresh_fixture([0x43; 32]);
        wrong.server_name = "other.example.org".into();
        assert!(editor.refresh_credential(&wrong).is_err());
        wrong.server_name = initial.server_name.clone();
        wrong.endpoint = "other.example.org:443".into();
        assert!(editor.refresh_credential(&wrong).is_err());
        wrong.endpoint = initial.endpoint.clone();
        wrong.transport = Transport::H3;
        assert!(editor.refresh_credential(&wrong).is_err());
        assert_eq!(fs::read(&temp.0).unwrap(), before);
        let mut changed = before;
        changed.extend_from_slice(b"\n# external edit\n");
        fs::write(&temp.0, &changed).unwrap();
        assert!(editor.refresh_credential(&initial).is_err());
        assert_eq!(fs::read(&temp.0).unwrap(), changed);
        assert!(old.is_file());
        remove_fixture_secret(&old);
    }

    #[test]
    fn credential_replacement_rolls_back_or_retains_only_new_file_at_commit_boundary() {
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        editor
            .import_invitation(&refresh_fixture([0x42; 32]), None, None)
            .unwrap();
        let initial = config::read_file(&temp.0).unwrap();
        let old = saved_secret(&initial);
        let replacement = refresh_fixture([0x43; 32]);
        let mut discarded = None;
        let result = editor.refresh_credential_with(&replacement, |_, doc, _| {
            discarded = Some(saved_secret(doc));
            Err(config::WriteFailure::BeforeReplace(config::ConfigError {
                field: "config".into(),
                reason: "injected pre-replacement refusal",
            }))
        });
        assert!(result.is_err());
        assert!(!editor.dirty());
        assert!(!discarded.unwrap().exists());
        assert_eq!(config::read_file(&temp.0).unwrap(), initial);
        assert!(old.is_file());

        let result = editor.refresh_credential_with(&replacement, |path, doc, expected| {
            config::guarded_write(path, doc, expected)?;
            Err(uncertain_failure())
        });
        assert!(result.is_err());
        assert!(editor.dirty());
        assert!(!editor.save());
        assert!(editor.refresh_credential(&replacement).is_err());
        let new = saved_secret(&config::read_file(&temp.0).unwrap());
        assert_ne!(old, new);
        assert!(old.is_file());
        assert!(new.is_file());
        remove_fixture_secret(&old);
        remove_fixture_secret(&new);
    }

    #[test]
    fn imported_secret_is_protected_and_new_profile_never_becomes_active() {
        use crate::{client_import::read_source, invite::Invitation};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let raw = invite.encode().unwrap();
        assert!(read_source(&raw).unwrap().has_token());
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        assert!(!editor.dirty());
        assert!(editor.import_invitation(&invite, None, None).is_ok());
        assert!(!editor.dirty());
        let saved = fs::read_to_string(&temp.0).unwrap();
        assert!(!saved.contains(&raw));
        assert!(!saved.contains(&URL_SAFE_NO_PAD.encode([0x42; 32])));
        let Config::Client(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(doc.client.active_profile, "home");
        assert_eq!(doc.client.profiles.len(), 2);
        let imported = &doc.client.profiles[1];
        assert_eq!(imported.id, "public");
        assert_eq!(imported.server, "edge.example.org:443");
        assert_eq!(imported.server_name, "edge.example.org");
        assert!(imported.tls_ca.is_none(), "trust is not granted by URI");
        assert!(imported.auth_token.starts_with("file:"));
        let secret_path = Path::new(imported.auth_token.strip_prefix("file:").unwrap());
        assert!(secret_path.is_absolute());
        assert_eq!(
            fs::read_to_string(secret_path).unwrap(),
            URL_SAFE_NO_PAD.encode([0x42; 32])
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(secret_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(secret_path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        fs::remove_file(secret_path).unwrap();
        fs::remove_dir(secret_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn public_import_requires_explicit_reference_and_rejects_duplicates_or_dirty_draft() {
        use crate::invite::Invitation;
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let Config::Client(original) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        let duplicate = Invitation::public_from_profile(&original.client.profiles[0]).unwrap();
        assert!(editor
            .import_invitation(&duplicate, None, Some("env:THEIA_OTHER"))
            .is_err());

        let mut second = original.client.profiles[0].clone();
        second.id = "remote".into();
        second.server = "remote.example.org:443".into();
        let public = Invitation::public_from_profile(&second).unwrap();
        assert!(editor.import_invitation(&public, None, None).is_err());
        assert!(editor
            .import_invitation(&public, None, Some("file:unsafe"))
            .is_err());
        assert!(!editor.dirty());
        editor.begin();
        assert!(editor
            .import_invitation(&public, None, Some("env:REMOTE_AUTH"))
            .is_err());
        editor.cancel();
        assert!(editor
            .import_invitation(&public, None, Some("env:REMOTE_AUTH"))
            .is_ok());
        let Config::Client(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(saved.client.active_profile, "home");
        assert_eq!(saved.client.profiles.len(), 2);
        assert_eq!(saved.client.profiles[1].auth_token, "env:REMOTE_AUTH");
        assert!(!fs::read_to_string(&temp.0).unwrap().contains("theia://v1/"));
    }

    #[test]
    fn import_refuses_external_edit_and_rolls_back_new_bearer() {
        use crate::invite::Invitation;
        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        let changed = format!(
            "# external writer\n{}",
            include_str!("../../../examples/client.toml")
        );
        fs::write(&temp.0, &changed).unwrap();
        assert!(editor.import_invitation(&invite, None, None).is_err());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), changed);
        assert!(!editor.dirty());

        let other = Temp::write(&server_source());
        let mut server_editor = Editor::load(Role::Server, &other.0).unwrap();
        assert!(server_editor
            .import_invitation(&invite, None, None)
            .is_err());
    }

    #[test]
    fn import_requires_independent_valid_ca_file_and_never_trusts_uri_ca() {
        use crate::invite::Invitation;
        let cert = rcgen::generate_simple_self_signed(vec!["edge.example.org".into()]).unwrap();
        let ca = Temp::write(&cert.cert.pem());
        let ca_ref = format!("file:{}", ca.0.display());
        let server = config::parse(&server_source()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        assert!(editor
            .import_invitation(&invite, Some("file:relative"), None)
            .is_err());
        assert!(editor
            .import_invitation(&invite, Some(&ca_ref), None)
            .is_ok());
        let Config::Client(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(
            doc.client.profiles[1].tls_ca.as_deref(),
            Some(ca_ref.as_str())
        );
        let secret_file = Path::new(
            doc.client.profiles[1]
                .auth_token
                .strip_prefix("file:")
                .unwrap(),
        );
        fs::remove_file(secret_file).unwrap();
        fs::remove_dir(secret_file.parent().unwrap()).unwrap();
    }

    #[test]
    fn new_user_is_scoped_to_selected_inbound_and_link_is_one_time_after_save() {
        use crate::invite::Invitation;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.select_record(true);
        assert_eq!(editor.selected_record_id(), "backup");
        assert!(editor.issue_user("new-device").is_ok());
        assert!(editor.dirty());
        assert!(!editor.issued_ready());
        assert!(editor.take_issued().is_none());
        editor.begin();
        assert!(!editor.editing);
        let before = fs::read_to_string(&temp.0).unwrap();
        assert!(!before.contains("new-device"));
        assert!(editor.save());
        assert!(editor.issued_ready());
        let invitation = editor.take_issued().unwrap();
        assert!(editor.take_issued().is_none());
        let raw_token = invitation.token_bytes().unwrap();
        let link = invitation.encode().unwrap();
        assert!(Invitation::decode(&link).unwrap().has_token());
        let stored = fs::read_to_string(&temp.0).unwrap();
        assert!(!stored.contains(&URL_SAFE_NO_PAD.encode(raw_token)));
        let Config::Server(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert_eq!(doc.server.inbounds[0].allowed_user_ids, ["device-a"]);
        assert_eq!(
            doc.server.inbounds[1].allowed_user_ids,
            ["device-a", "new-device"]
        );
        assert_eq!(doc.server.users.len(), 2);
        assert_eq!(doc.server.users[1].id, "new-device");
        assert_eq!(
            doc.server.users[1].token_sha256,
            format!("{:x}", Sha256::digest(raw_token))
        );
        assert!(!doc.server.users[1].disabled);
    }

    #[test]
    fn invalid_duplicate_or_dirty_issuance_is_rejected_without_modifying_draft() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        for id in ["", "bad id", "device-a", "bad\nname"] {
            assert!(editor.issue_user(id).is_err(), "{id:?}");
            assert!(!editor.dirty());
        }
        editor.begin();
        editor.input = "new.example.org".into();
        assert!(editor.accept());
        assert!(editor.issue_user("new-device").is_err());
        editor.discard();
        assert!(!editor.dirty());
        assert!(editor.issue_user("new-device").is_ok());
        assert!(editor.issue_user("another").is_err());
        editor.discard();
        assert!(editor.take_issued().is_none());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), server_source());
    }

    #[test]
    fn external_change_blocks_issued_link_until_successful_write() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.issue_user("new-device").is_ok());
        fs::write(
            &temp.0,
            "# changed externally\n".to_string() + &server_source(),
        )
        .unwrap();
        assert!(!editor.save());
        assert!(!editor.issued_ready());
        assert!(editor.take_issued().is_none());
        editor.discard();
        assert_eq!(config::read_file(&temp.0).unwrap().validate(), Ok(()));
    }

    #[test]
    fn new_user_gets_independent_random_token_and_existing_token_is_never_exported() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.issue_user("new-device").is_ok());
        assert!(editor.save());
        let first = editor.take_issued().unwrap().token_bytes().unwrap();
        assert!(editor.issue_user("next-device").is_ok());
        assert!(editor.save());
        let second = editor.take_issued().unwrap().token_bytes().unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0; 32]);
        assert_ne!(second, [0; 32]);
        assert!(editor.issue_user("device-a").is_err());
    }

    #[test]
    fn rotation_changes_only_existing_users_digest_and_reveals_after_durable_save() {
        use crate::invite::Invitation;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.select_record(true);
        let Config::Server(original) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        let before = original.server.users[0].token_sha256.clone();
        let grants = original
            .server
            .inbounds
            .iter()
            .map(|inbound| inbound.allowed_user_ids.clone())
            .collect::<Vec<_>>();
        assert!(editor.rotate_user("device-a").is_ok());
        assert!(editor.dirty());
        assert!(!editor.issued_ready());
        assert!(editor.take_issued().is_none());
        assert_eq!(
            config::read_file(&temp.0).unwrap(),
            Config::Server(original.clone())
        );
        assert!(editor.save());
        assert!(editor.issued_ready());
        let invite = editor.take_issued().expect("one-time replacement token");
        assert!(editor.take_issued().is_none());
        assert!(Invitation::decode(&invite.encode().unwrap())
            .unwrap()
            .has_token());
        let token = invite.token_bytes().unwrap();
        assert_ne!(token, [0x42; 32]);
        let stored = fs::read_to_string(&temp.0).unwrap();
        assert!(!stored.contains(&URL_SAFE_NO_PAD.encode(token)));
        let Config::Server(updated) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert_eq!(updated.server.users.len(), original.server.users.len());
        assert_eq!(updated.server.users[0].id, "device-a");
        assert!(!updated.server.users[0].disabled);
        assert_ne!(updated.server.users[0].token_sha256, before);
        assert_eq!(
            updated.server.users[0].token_sha256,
            format!("{:x}", Sha256::digest(token))
        );
        assert_eq!(
            updated
                .server
                .inbounds
                .iter()
                .map(|inbound| inbound.allowed_user_ids.clone())
                .collect::<Vec<_>>(),
            grants
        );
    }

    #[test]
    fn rotation_rejects_unsafe_states_ungranted_user_and_external_conflict() {
        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        for id in ["", "no-such-user", "invalid name"] {
            assert!(editor.rotate_user(id).is_err(), "{id:?}");
            assert!(!editor.dirty());
        }
        editor.begin();
        assert!(editor.rotate_user("device-a").is_err());
        editor.cancel();
        editor.begin();
        editor.input = "new.example.org".into();
        assert!(editor.accept());
        assert!(editor.rotate_user("device-a").is_err());
        editor.discard();

        let Config::Server(mut record) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        record.server.users.push(User {
            id: "device-b".into(),
            token_sha256: format!("{:x}", Sha256::digest([0x77; 32])),
            disabled: false,
        });
        record.server.inbounds[1].allowed_user_ids = vec!["device-b".into()];
        let temp2 = Temp::write(&Config::Server(record).to_toml().unwrap());
        let mut ungranted = Editor::load(Role::Server, &temp2.0).unwrap();
        assert!(ungranted.rotate_user("device-b").is_err());
        ungranted.select_record(true);
        assert!(ungranted.rotate_user("device-b").is_ok());
        ungranted.discard();

        let Config::Server(mut disabled) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        disabled.server.users[0].disabled = true;
        let temp3 = Temp::write(&Config::Server(disabled).to_toml().unwrap());
        let mut editor_disabled = Editor::load(Role::Server, &temp3.0).unwrap();
        assert!(editor_disabled.rotate_user("device-a").is_err());
        assert!(!editor_disabled.dirty());

        assert!(editor.issue_user("new-device").is_ok());
        assert!(editor.rotate_user("device-a").is_err());
        editor.discard();
        assert!(editor.rotate_user("device-a").is_ok());
        let external = format!("# external edit\n{}", two_inbounds());
        fs::write(&temp.0, &external).unwrap();
        assert!(!editor.save());
        assert!(!editor.issued_ready());
        assert!(editor.take_issued().is_none());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), external);

        let client = Temp::write(include_str!("../../../examples/client.toml"));
        let mut client_editor = Editor::load(Role::Client, &client.0).unwrap();
        assert!(client_editor.rotate_user("device-a").is_err());
        assert!(!client_editor.dirty());
    }

    #[test]
    fn reenable_requires_disabled_granted_user_and_fresh_bearer() {
        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.reenable_user("device-a").is_err());
        assert!(editor.reenable_user("missing").is_err());
        assert!(!editor.dirty());
        editor.disable_user("device-a").unwrap();
        assert!(editor.save());
        let Config::Server(before) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert!(before.server.users[0].disabled);
        assert!(editor.rotate_user("device-a").is_err());
        editor.reenable_user("device-a").unwrap();
        assert!(editor.take_issued().is_none());
        assert!(editor.dirty());
        assert!(editor.save());
        let invite = editor.take_issued().unwrap();
        let token = Zeroizing::new(invite.token_bytes().unwrap());
        assert!(*token != [0x42; 32]);
        let Config::Server(after) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert!(!after.server.users[0].disabled);
        assert_eq!(before.server.inbounds, after.server.inbounds);
        assert_eq!(
            after.server.users[0].token_sha256,
            format!("{:x}", Sha256::digest(*token))
        );
        assert_ne!(
            before.server.users[0].token_sha256,
            after.server.users[0].token_sha256
        );
        assert!(editor.take_issued().is_none());
        assert!(editor.reenable_user("device-a").is_err());
    }

    #[test]
    fn reenable_conflict_and_discard_never_release_token() {
        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.disable_user("device-a").unwrap();
        assert!(editor.save());
        let disabled = fs::read_to_string(&temp.0).unwrap();
        editor.reenable_user("device-a").unwrap();
        editor.discard();
        assert!(editor.take_issued().is_none());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), disabled);
        editor.reenable_user("device-a").unwrap();
        let external = format!("# changed externally\n{disabled}");
        fs::write(&temp.0, &external).unwrap();
        assert!(!editor.save());
        assert!(editor.take_issued().is_none());
        editor.discard();
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), external);
    }

    #[test]
    fn user_disable_requires_clean_server_editor_and_explicit_selected_grant() {
        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();

        for user_id in ["", "missing", "bad id"] {
            assert!(editor.disable_user(user_id).is_err());
            assert!(!editor.dirty());
        }
        editor.begin();
        assert!(editor.disable_user("device-a").is_err());
        editor.cancel();
        editor.begin();
        editor.input = "other.example.org".into();
        assert!(editor.accept());
        assert!(editor.disable_user("device-a").is_err());
        editor.discard();

        let Config::Server(original) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        let previous_digest = original.server.users[0].token_sha256.clone();
        assert!(editor.disable_user("device-a").is_ok());
        assert!(editor.dirty());
        assert!(editor.take_issued().is_none());
        assert!(!config::read_file(&temp.0)
            .unwrap()
            .to_toml()
            .unwrap()
            .contains("disabled = true"));
        assert!(editor.save());
        let Config::Server(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert!(doc.server.users[0].disabled);
        assert_eq!(doc.server.users[0].token_sha256, previous_digest);
        assert_eq!(doc.server.inbounds[0].allowed_user_ids, ["device-a"]);
        assert_eq!(doc.server.inbounds[1].allowed_user_ids, ["device-a"]);
        assert!(
            editor.disable_user("device-a").is_err(),
            "repeat disable must fail"
        );
    }

    #[test]
    fn user_disable_requires_exact_existing_inbound_grant_not_just_global_user() {
        let Config::Server(mut doc) = config::parse(&two_inbounds()).unwrap() else {
            panic!("server");
        };
        doc.server.users.push(User {
            id: "device-b".into(),
            token_sha256: format!("{:x}", Sha256::digest([0x43; 32])),
            disabled: false,
        });
        doc.server.inbounds[1].allowed_user_ids = vec!["device-b".into()];
        let temp = Temp::write(&Config::Server(doc).to_toml().unwrap());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.disable_user("device-b").is_err());
        assert!(!editor.dirty());
        editor.select_record(true);
        assert_eq!(editor.selected_record_id(), "backup");
        assert!(editor.disable_user("device-b").is_ok());
        assert!(editor.save());
        let Config::Server(after) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert!(!after.server.users[0].disabled);
        assert!(after.server.users[1].disabled);
        assert_eq!(after.server.inbounds[0].allowed_user_ids, ["device-a"]);
        assert_eq!(after.server.inbounds[1].allowed_user_ids, ["device-b"]);
    }

    #[test]
    fn user_disable_refuses_external_file_conflict_and_client_role() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert!(editor.disable_user("device-a").is_ok());
        let changed = format!("# external edit\n{}", server_source());
        fs::write(&temp.0, &changed).unwrap();
        assert!(!editor.save());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), changed);
        editor.discard();
        assert!(!editor.dirty());

        let client = Temp::write(include_str!("../../../examples/client.toml"));
        let mut client_editor = Editor::load(Role::Client, &client.0).unwrap();
        assert!(client_editor.disable_user("device-a").is_err());
        assert!(!client_editor.dirty());
    }

    #[test]
    fn selects_second_inbound_and_edits_three_fields_without_changing_first() {
        let temp = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert_eq!(editor.record_count(), 2);
        assert_eq!(editor.selected_record_id(), "public");
        assert_eq!(editor.field_name(), "server.inbounds[0].server_name");
        editor.select_record(true);
        assert_eq!(editor.selected_record_id(), "backup");
        assert_eq!(editor.field_name(), "server.inbounds[1].server_name");
        editor.begin();
        editor.input = "backup.example.org".into();
        assert!(editor.accept());
        editor.select_field(true);
        assert_eq!(editor.field_name(), "server.inbounds[1].h2_listen");
        editor.begin();
        editor.input = "0.0.0.0:9443".into();
        assert!(editor.accept());
        editor.select_field(true);
        assert_eq!(editor.field_name(), "server.inbounds[1].quic_listen");
        editor.begin();
        editor.input = "0.0.0.0:9444".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        assert!(editor.save());
        let Config::Server(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert_eq!(saved.server.inbounds[0].server_name, "edge.example.org");
        assert_eq!(saved.server.inbounds[1].server_name, "backup.example.org");
        assert_eq!(saved.server.inbounds[1].h2_listen, "0.0.0.0:9443");
        assert_eq!(saved.server.inbounds[1].quic_listen, "0.0.0.0:9444");
        assert_eq!(saved.server.inbounds[1].allowed_user_ids, ["device-a"]);
    }

    #[test]
    fn selectable_non_active_client_profile_keeps_active_pointer_and_secret_references() {
        let temp = Temp::write(&two_profiles());
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        assert_eq!(editor.record_count(), 2);
        assert_eq!(editor.selected_record_id(), "home");
        assert!(editor.selected_record_is_active());
        editor.select_record(true);
        assert_eq!(editor.selected_record_id(), "work");
        assert!(!editor.selected_record_is_active());
        assert_eq!(editor.field_name(), "client.profiles[1].server");
        editor.begin();
        editor.input = "new-work.example.org:8443".into();
        assert!(editor.accept());
        editor.select_field(true);
        assert_eq!(editor.field_name(), "client.profiles[1].server_name");
        editor.begin();
        editor.input = "new-work.example.org".into();
        assert!(editor.accept());
        editor.select_field(true);
        assert_eq!(editor.field_name(), "client.profiles[1].transport");
        editor.begin();
        editor.input = "h2".into();
        assert!(editor.accept());
        assert_eq!(editor.field_value(), "h2");
        editor.select_field(true);
        assert_eq!(editor.field_name(), "client.profiles[1].xhttp_mode");
        editor.begin();
        editor.input = "auto".into();
        assert!(editor.accept());
        assert_eq!(editor.field_value(), "auto");
        assert!(editor.save());
        let Config::Client(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(saved.client.active_profile, "home");
        assert_eq!(saved.client.profiles[0].server, "edge.example.org:443");
        assert_eq!(saved.client.profiles[1].server, "new-work.example.org:8443");
        assert_eq!(saved.client.profiles[1].server_name, "new-work.example.org");
        assert_eq!(saved.client.profiles[1].transport, config::Transport::H2);
        assert_eq!(saved.client.profiles[1].xhttp_mode, Some(XhttpMode::Auto));
        assert_eq!(saved.client.profiles[0].xhttp_mode, None);
        assert_eq!(saved.client.profiles[1].auth_token, "env:THEIA_AUTH_TOKEN");
    }

    #[test]
    fn duplicate_inbound_listeners_and_unknown_transport_reject_without_file_change() {
        let temp = Temp::write(&two_inbounds());
        let before = fs::read(&temp.0).unwrap();
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.select_record(true);
        editor.select_field(true);
        editor.begin();
        editor.input = "0.0.0.0:443".into();
        assert!(!editor.accept());
        assert!(editor.editing);
        assert!(editor.error.as_deref().unwrap().contains("h2_listen"));
        editor.cancel();
        assert!(!editor.dirty());
        assert_eq!(fs::read(&temp.0).unwrap(), before);

        let other = Temp::write(&two_profiles());
        let mut client = Editor::load(Role::Client, &other.0).unwrap();
        client.select_record(true);
        client.select_field(true);
        client.select_field(true);
        client.begin();
        client.input = "h4".into();
        assert!(!client.accept());
        assert!(client.error.as_deref().unwrap().contains("transport"));
        assert!(!client.dirty());
        client.cancel();
        client.select_record(true);
        assert_eq!(client.selected_record_id(), "home");
        client.select_field(true);
        assert_eq!(client.field_name(), "client.profiles[0].server_name");
        client.select_field(true);
        client.select_field(true);
        assert_eq!(client.field_name(), "client.profiles[0].xhttp_mode");
        client.select_field(true);
        assert_eq!(client.field_name(), "client.profiles[0].server");
    }

    #[test]
    fn client_typed_edit_validates_saves_and_never_applies() {
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        assert!(!editor.dirty());
        assert_eq!(editor.field_name(), "client.profiles[0].server");
        editor.begin();
        editor.input = "new.example.org:8443".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        assert!(editor.save());
        assert!(!editor.dirty());
        assert!(editor.notice.contains("runtime ещё не обновлён"));
        let Config::Client(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("client document expected");
        };
        assert_eq!(saved.client.profiles[0].server, "new.example.org:8443");
        assert_eq!(saved.client.profiles[0].auth_token, "env:THEIA_AUTH_TOKEN");
    }

    #[test]
    fn server_field_validation_and_cancel_preserve_file() {
        let temp = Temp::write(&server_source());
        let source = fs::read(&temp.0).unwrap();
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.begin();
        editor.input = "127.0.0.1".into();
        assert!(!editor.accept());
        assert!(editor.editing);
        assert!(editor.error.as_deref().unwrap().contains("server_name"));
        assert!(!editor.dirty());
        editor.cancel();
        assert!(!editor.editing);
        editor.begin();
        editor.input = "new.example.org".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        editor.discard();
        assert!(!editor.dirty());
        assert_eq!(fs::read(&temp.0).unwrap(), source);
    }

    #[test]
    fn server_edit_persists_valid_name_without_touching_grants() {
        let temp = Temp::write(&server_source());
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.begin();
        editor.input = "another.example.org".into();
        assert!(editor.accept());
        assert!(editor.save());
        let Config::Server(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("server document expected");
        };
        assert_eq!(saved.server.inbounds[0].server_name, "another.example.org");
        assert_eq!(saved.server.inbounds[0].allowed_user_ids, ["device-a"]);
    }

    #[test]
    fn invalid_and_conflicted_files_are_not_overwritten() {
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        assert!(Editor::load(Role::Server, &temp.0).is_err());
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        editor.begin();
        editor.input = "bad-endpoint".into();
        assert!(!editor.accept());
        assert!(editor.error.as_deref().unwrap().contains("client.profiles"));
        editor.input = "gateway.example.org:443".into();
        assert!(editor.accept());
        fs::write(
            &temp.0,
            "# external change\n".to_owned() + include_str!("../../../examples/client.toml"),
        )
        .unwrap();
        let external = fs::read(&temp.0).unwrap();
        assert!(!editor.save());
        assert!(editor
            .error
            .as_deref()
            .unwrap()
            .contains("changed externally"));
        assert_eq!(fs::read(&temp.0).unwrap(), external);
    }

    #[test]
    fn bounded_field_rejects_control_characters_and_invalid_input() {
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let mut editor = Editor::load(Role::Client, &temp.0).unwrap();
        editor.begin();
        let before = editor.input.len();
        editor.insert('\n');
        editor.insert('\0');
        assert_eq!(editor.input.len(), before);
        for _ in 0..500 {
            editor.insert('x');
        }
        assert_eq!(editor.input.len(), MAX_INPUT);
        editor.backspace();
        assert_eq!(editor.input.len(), MAX_INPUT - 1);
        assert!(!editor.save());
    }

    #[test]
    fn m4_2c_saved_digest_tracks_only_durable_bytes_not_unsaved_editor_draft() {
        let path = std::env::temp_dir().join(format!(
            "theia-m42c-editor-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"b".repeat(64));
        std::fs::write(&path, source).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        let initial = editor.saved_sha256();
        let observed: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
        assert_eq!(initial, observed);
        editor.begin();
        editor.input = "updated.example.org".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        assert_eq!(
            editor.saved_sha256(),
            initial,
            "draft is never considered saved"
        );
        assert!(editor.save());
        assert!(!editor.dirty());
        let on_disk: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
        assert_ne!(on_disk, initial);
        assert_eq!(
            editor.saved_sha256(),
            on_disk,
            "only durably written bytes are approved"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = Temp::write(include_str!("../../../examples/client.toml"));
        let link = temp.0.with_extension("link");
        symlink(&temp.0, &link).unwrap();
        assert!(Editor::load(Role::Client, &link).is_err());
        fs::remove_file(&link).unwrap();
    }
}
