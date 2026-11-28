//! M4.1c typed, bounded, selectable inbound/profile configuration forms.
//!
//! A user-provided configuration file is explicit. Never print its contents,
//! secret references, token hashes or path in diagnostics. All writes go
//! through the existing strict validator and atomic store.
use crate::{
    client_import::{self, PrivateBearer},
    config::{self, Config, Transport, User, XhttpMode},
    invite::Invitation,
    security_profile::SecurityMode,
    Role,
};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_INPUT: usize = 255;

fn xhttp_value(mode: XhttpMode) -> String {
    match mode {
        XhttpMode::Auto => "auto",
        XhttpMode::StreamOne => "stream-one",
        XhttpMode::StreamUp => "stream-up",
    }
    .to_owned()
}

/// Configuration-only record lifecycle; no network, secret creation or runtime Apply.
#[derive(Clone, Copy)]
pub(crate) enum RecordAction {
    NewInbound,
    NewProfile,
    DeleteRecord,
    ActivateProfile,
    SetGrants,
    SetQuota,
    DeleteUser,
    EditTls,
    EditTrust,
}

impl RecordAction {
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::NewInbound => "Создать подключение (собственный TLS)",
            Self::NewProfile => "Создать клиентский профиль (собственный TLS)",
            Self::DeleteRecord => "Удалить выбранную запись",
            Self::ActivateProfile => "Выбрать активный профиль",
            Self::SetGrants => "Изменить список пользователей с доступом",
            Self::SetQuota => "Изменить лимиты соединений",
            Self::DeleteUser => "Удалить пользователя без прав доступа",
            Self::EditTls => "Настроить сертификат и закрытый ключ",
            Self::EditTrust => "Настроить доверие и токен",
        }
    }

    pub(crate) fn fields(self) -> &'static [(&'static str, bool)] {
        match self {
            Self::NewInbound => &[
                ("Название / ID", false),
                ("Адрес прослушивания TCP/UDP", false),
                ("Домен TLS (SNI)", false),
                ("Файл сертификата (file:)", true),
                ("Файл закрытого ключа (file:)", true),
                ("Доступ: ID пользователей через запятую", false),
            ],
            Self::NewProfile => &[
                ("Название / ID", false),
                ("Адрес сервера", false),
                ("Домен TLS (SNI)", false),
                ("Файл доверенного CA (file:)", true),
                ("Ссылка на токен (env:/file:)", true),
                ("Путь XHTTP", false),
            ],
            Self::SetGrants => &[("ID пользователей через запятую", false)],
            Self::SetQuota => &[("На пользователя", false), ("Всего", false)],
            Self::DeleteUser => &[("ID пользователя", false)],
            Self::EditTls => &[
                ("Сертификат (file:)", true),
                ("Закрытый ключ (file:)", true),
            ],
            Self::EditTrust => &[
                ("Доверенный CA (file:)", true),
                ("Ссылка на токен (env:/file:)", true),
            ],
            Self::DeleteRecord | Self::ActivateProfile => &[],
        }
    }
}

pub(crate) struct RecordReview {
    source: [u8; 32],
    selected: String,
    candidate: Config,
    next_selection: usize,
    body: String,
    confirmation_label: &'static str,
}

impl RecordReview {
    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    pub(crate) fn confirmation_label(&self) -> &'static str {
        self.confirmation_label
    }
}

pub(crate) fn generated_id(prefix: &str) -> Result<String, &'static str> {
    let mut random = [0u8; 8];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut random)
        .map_err(|_| "Secure random generator unavailable")?;
    Ok(format!("{prefix}-{:016x}", u64::from_be_bytes(random)))
}

fn parse_grants(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).map(str::to_owned).collect()
}

/// One-time, saved credential offer for either product security mode.
pub enum IssuedInvitation {
    OwnTls(Invitation),
    Reality {
        invitation: crate::reality_bootstrap::Invitation,
        user: String,
    },
}
impl IssuedInvitation {
    pub fn encode(&self) -> Result<String, &'static str> {
        match self {
            Self::OwnTls(value) => value.encode().map_err(|_| "Invalid invitation"),
            Self::Reality { invitation, .. } => invitation
                .encode()
                .map(|uri| uri.to_string())
                .map_err(|_| "Invalid REALITY invitation"),
        }
    }
    pub fn token_bytes(&self) -> Option<[u8; 32]> {
        match self {
            Self::OwnTls(value) => value.token_bytes(),
            Self::Reality { invitation, .. } => invitation.token_bytes(),
        }
    }
}

fn invitation_trust(invite: &Invitation, ca: Option<&str>) -> Result<Option<String>, &'static str> {
    if let Some(anchor) = invite.trust_reference() {
        if ca.is_some_and(|value| !invite.matches_trust(Some(value))) {
            return Err("Доверие в ключе не совпадает с указанным сертификатом.");
        }
        Ok(Some(anchor))
    } else {
        client_import::checked_ca_ref(ca)
            .map_err(|_| "Explicit TLS CA reference is invalid or unreadable")
    }
}

fn server_invitation(
    config: &Config,
    id: &str,
    credential: Option<(&str, &[u8; 32])>,
) -> Result<IssuedInvitation, &'static str> {
    let Config::Server(document) = config else {
        return Err("Server configuration required");
    };
    let inbound = document
        .server
        .inbounds
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("Inbound missing")?;
    if inbound.security_mode == SecurityMode::SmartReality {
        let now = crate::reference_health::unix_now().map_err(|_| "Invalid clock")?;
        let invitation =
            crate::reality_config::registered_invitation(document, id, credential, now)
                .map_err(|_| "Registered REALITY publication not eligible")?;
        // Check the actual full key before a grant or credential is saved.
        invitation
            .encode()
            .map_err(|_| "Ключ REALITY превышает лимит или невалиден")?;
        return Ok(IssuedInvitation::Reality {
            invitation,
            user: credential.map_or_else(String::new, |(user, _)| user.to_owned()),
        });
    }
    let invitation = match credential {
        Some((user, bearer)) => Invitation::issued_from_server(config, id, user, bearer),
        None => Invitation::public_from_server(config, id),
    }
    .map_err(|_| "Selected inbound cannot issue invitations")?;
    invitation
        .encode()
        .map_err(|_| "Ключ TLS превышает лимит или невалиден")?;
    Ok(IssuedInvitation::OwnTls(invitation))
}

pub struct Editor {
    role: Role,
    path: PathBuf,
    source: Vec<u8>,
    original: Config,
    draft: Config,
    issued: Option<IssuedInvitation>,
    issued_ready: bool,
    write_uncertain: bool,
    selected_record: usize,
    selected_field: usize,
    compact_server_fields: bool,
    pub input: String,
    pub editing: bool,
    pub error: Option<String>,
    pub notice: &'static str,
}

impl Editor {
    pub(crate) fn routing_settings(&self) -> Option<&crate::routing::Settings> {
        match &self.draft {
            Config::Server(doc) => doc.server.policy.routing.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn stage_routing(
        &mut self,
        mut settings: crate::routing::Settings,
    ) -> Result<(), &'static str> {
        self.require_clean_records()?;
        let Config::Server(doc) = &self.original else {
            return Err("Требуется серверная конфигурация.");
        };
        let old = doc.server.policy.routing.as_ref();
        settings.revision = old
            .map_or(1, |s| s.revision)
            .checked_add(1)
            .ok_or("Исчерпана ревизия правил.")?;
        settings
            .validate()
            .map_err(|_| "Некорректные правила или отсутствуют проверенные базы.")?;
        let mut candidate = self.original.clone();
        let Config::Server(doc) = &mut candidate else {
            unreachable!()
        };
        doc.server.policy.routing = Some(settings);
        candidate
            .validate()
            .map_err(|_| "Конфигурация не прошла проверку.")?;
        self.draft = candidate;
        self.error = None;
        self.notice = "Правила подготовлены. Сохраните TOML, затем примените через Управление.";
        Ok(())
    }

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
            compact_server_fields: false,
            input: String::new(),
            editing: false,
            error: None,
            notice: "Настройки открыты. Работающий процесс не изменён.",
        })
    }

    /// F-14: commit a completely new client profile from a reviewed invitation.
    /// The source's bearer is never written to TOML; the file is protected by
    /// a fresh owner-only directory and private ACL/mode on both platforms.
    /// Caller must explicitly review ID/endpoint/SNI/transport and pinned trust.
    /// First Own-TLS import: create only a real, fully reviewed profile.
    /// A conflicting destination is never replaced; credentials survive an
    /// indeterminate publication but are removed after a pre-commit refusal.
    pub(crate) fn create_first_invitation(
        path: &Path,
        invite: &Invitation,
        ca_ref: &str,
        public_ref: Option<&str>,
    ) -> Result<Self, &'static str> {
        let path = std::path::absolute(path).map_err(|_| "Недопустимый путь настроек.")?;
        if !crate::bounded_input::explicit_file_path(&path)
            || !matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
            || !path.parent().is_some_and(Path::is_dir)
        {
            return Err("Выберите новый файл настроек в существующем каталоге.");
        }
        let ca = invitation_trust(invite, (!ca_ref.is_empty()).then_some(ca_ref))?
            .ok_or("Не удалось проверить доверенный сертификат.")?;
        let ca = Some(ca);
        let mut secret = if let Some(bytes) = invite.token_bytes() {
            let token = Zeroizing::new(bytes);
            Some(
                PrivateBearer::create(&path, &token)
                    .map_err(|_| "Не удалось сохранить личный ключ.")?,
            )
        } else {
            None
        };
        let credential = match secret.as_ref() {
            Some(saved) => saved
                .reference()
                .map_err(|_| "Не удалось создать ссылку на личный ключ.")?,
            None => public_ref
                .filter(|r| client_import::valid_explicit_reference(r))
                .ok_or("Публичному приглашению нужен отдельный ключ (env:ИМЯ).")?
                .to_owned(),
        };
        let profile = invite
            .to_profile(&credential, ca)
            .map_err(|_| "Приглашение содержит недопустимые параметры.")?;
        let candidate = Config::Client(config::ClientDocument {
            schema_version: 1,
            management: config::Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: config::Ui {
                language: "ru".into(),
            },
            client: config::ClientSettings {
                active_profile: profile.id.clone(),
                ingress_mode: config::IngressMode::SystemProxy,
                profiles: vec![profile],
                proxy: config::LocalProxy {
                    http_listen: "127.0.0.1:7890".into(),
                    socks5_listen: "127.0.0.1:7891".into(),
                },
            },
        });
        candidate
            .validate()
            .map_err(|_| "Профиль не прошёл проверку настроек.")?;
        match config::guarded_create(&path, &candidate) {
            Ok(()) => {
                if let Some(secret) = secret.as_mut() {
                    secret.commit();
                }
            }
            Err(config::WriteFailure::BeforeReplace(_)) => {
                return Err(
                    "Файл не создан. Проверьте путь, права и отсутствие существующего файла.",
                )
            }
            Err(config::WriteFailure::AfterReplace(_)) => {
                if let Some(secret) = secret.as_mut() {
                    secret.commit();
                }
                return Err(
                    "Создание не подтверждено. Откройте файл заново; не повторяйте импорт вслепую.",
                );
            }
        }
        Self::load(Role::Client, &path)
            .map_err(|_| "Файл записан, но открыть его не удалось. Откройте настройки заново.")
    }

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
        let ca = invitation_trust(invite, ca_ref)?;
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
            || profile.path_prefix.as_deref() != Some(invite.path_prefix.as_str())
            || profile.security_mode != invite.security_mode()
            || !invite.matches_trust(profile.tls_ca.as_deref())
            || (invite.xhttp_mode() != XhttpMode::Auto
                && profile.effective_xhttp_mode() != invite.xhttp_mode())
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
        server_invitation(&self.draft, &inbound_id, None)
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
        let invitation = server_invitation(&candidate, &inbound_id, Some((user_id, &token)))
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
        server_invitation(&self.draft, &inbound_id, None)
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
        let invitation = server_invitation(&candidate, &inbound_id, Some((user_id, &token)))
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
    pub fn take_issued(&mut self) -> Option<IssuedInvitation> {
        if !self.issued_ready() {
            return None;
        }
        self.issued_ready = false;
        let invite = self.issued.take()?;
        if !config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.source) {
            self.error = Some("Saved configuration changed; issuance refused".into());
            return None;
        }
        if let IssuedInvitation::OwnTls(invitation) = &invite {
            let token = Zeroizing::new(invitation.token_bytes()?);
            let Config::Server(document) = &self.original else {
                return None;
            };
            let digest = format!("{:x}", Sha256::digest(&token[..]));
            let current = document
                .server
                .users
                .iter()
                .find(|user| !user.disabled && user.token_sha256 == digest)
                .and_then(|user| {
                    Invitation::issued_from_server(&self.original, &invitation.id, &user.id, &token)
                        .ok()
                });
            let unchanged = current.as_ref().is_some_and(|value| {
                let left = invitation.encode().ok().map(Zeroizing::new);
                let right = value.encode().ok().map(Zeroizing::new);
                matches!((left, right), (Some(a), Some(b)) if a.as_str() == b.as_str())
            });
            if !unchanged {
                self.error = Some("Own-TLS trust changed; issue a new credential.".into());
                return None;
            }
        }
        if let IssuedInvitation::Reality { invitation, user } = &invite {
            // Publication/health may have advanced during TOML save. Never
            // reveal an outdated or no-longer-authorized confidential offer.
            let token = Zeroizing::new(invitation.token_bytes()?);
            let current = server_invitation(
                &self.original,
                self.selected_record_id(),
                Some((user, &token)),
            )
            .ok();
            let unchanged = current.as_ref().is_some_and(|value| {
                let left = invite.encode().ok().map(Zeroizing::new);
                let right = value.encode().ok().map(Zeroizing::new);
                matches!((left, right), (Some(a), Some(b)) if a.as_str() == b.as_str())
            });
            if !unchanged {
                self.error = Some("REALITY publication changed; issue a new credential.".into());
                return None;
            }
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
                return server_invitation(&self.original, self.selected_record_id(), None)?
                    .encode();
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
        let result = match &invite {
            IssuedInvitation::OwnTls(value) => {
                client_import::export_invitation_file(&self.path, value)
            }
            IssuedInvitation::Reality { .. } => {
                let encoded = Zeroizing::new(invite.encode()?);
                client_import::export_encoded_invitation(&self.path, &encoded)
            }
        };
        result.map_err(|_| "Protected export failed; issue or rotate again")
    }

    pub fn clear_issued(&mut self) {
        self.issued = None;
        self.issued_ready = false;
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Safe summary for the workspace record list. Only IDs and mode are exposed;
    /// active indicates saved/draft selection, never an authenticated connection.
    pub(crate) fn workspace_records(&self) -> Vec<(String, bool, bool)> {
        match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .iter()
                .map(|entry| {
                    (
                        entry.id.clone(),
                        false,
                        entry.security_mode == crate::security_profile::SecurityMode::SmartReality,
                    )
                })
                .collect(),
            Config::Client(doc) => doc
                .client
                .profiles
                .iter()
                .map(|entry| {
                    (
                        entry.id.clone(),
                        doc.client.active_profile == entry.id,
                        entry.security_mode == crate::security_profile::SecurityMode::SmartReality,
                    )
                })
                .collect(),
        }
    }

    /// IDs, disabled state and membership in the current inbound are safe to
    /// display. Never expose password/token digests or credential references.
    pub(crate) fn workspace_users(&self) -> Vec<(String, bool, bool)> {
        let Config::Server(doc) = &self.draft else {
            return Vec::new();
        };
        let grants = doc
            .server
            .inbounds
            .get(self.selected_record)
            .map(|entry| entry.allowed_user_ids.as_slice())
            .unwrap_or(&[]);
        doc.server
            .users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    user.disabled,
                    grants.iter().any(|id| id == &user.id),
                )
            })
            .collect()
    }

    pub(crate) fn user_deletable(&self, id: &str) -> bool {
        let Config::Server(doc) = &self.draft else {
            return false;
        };
        doc.server.users.iter().any(|u| u.id == id)
            && !doc
                .server
                .inbounds
                .iter()
                .any(|i| i.allowed_user_ids.iter().any(|u| u == id))
    }

    pub(crate) fn workspace_selected(&self) -> usize {
        self.selected_record
    }

    pub(crate) fn workspace_select(&mut self, index: usize) {
        if !self.editing && self.issued.is_none() && index < self.record_count() {
            self.selected_record = index;
            self.selected_field = 0;
            self.error = None;
        }
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

    /// Display endpoint without changing the exact identity used for guarded operations.
    pub(crate) fn server_connection_label(&self, id: &str) -> Option<String> {
        let Config::Server(doc) = &self.draft else {
            return None;
        };
        let inbound = doc.server.inbounds.iter().find(|entry| entry.id == id)?;
        let port = inbound
            .h2_listen
            .parse::<std::net::SocketAddr>()
            .ok()?
            .port();
        let host = inbound.server_name.as_str();
        let endpoint = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Some(endpoint)
    }

    /// Display address only; profile identity and selection remain keyed by ID.
    pub(crate) fn client_profile_address(&self, id: &str) -> Option<&str> {
        let Config::Client(doc) = &self.draft else {
            return None;
        };
        doc.client
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.server.as_str())
    }

    /// Human-facing number and address; guarded operations still use the ID.
    pub(crate) fn client_profile_label(&self, id: &str) -> Option<String> {
        let Config::Client(doc) = &self.draft else {
            return None;
        };
        doc.client
            .profiles
            .iter()
            .enumerate()
            .find(|(_, p)| p.id == id)
            .map(|(index, p)| format!("№{} · {}", index + 1, p.server))
    }

    pub(crate) fn require_clean_records(&self) -> Result<(), &'static str> {
        if self.editing || self.dirty() || self.issued.is_some() {
            return Err("Сначала завершите или отмените редактирование и выдачу.");
        }
        if !config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.source) {
            return Err("Файл изменился; откройте редактор заново.");
        }
        Ok(())
    }

    pub(crate) fn record_user_catalog(&self, action: RecordAction) -> Option<String> {
        if !matches!(
            action,
            RecordAction::NewInbound | RecordAction::SetGrants | RecordAction::DeleteUser
        ) {
            return None;
        }
        let Config::Server(doc) = &self.original else {
            return None;
        };
        let users = doc
            .server
            .users
            .iter()
            .map(|user| {
                if user.disabled {
                    format!("{} (отключён)", user.id)
                } else {
                    user.id.clone()
                }
            })
            .collect::<Vec<_>>();
        Some(format!("Каталог пользователей: {}", users.join(", ")))
    }

    pub(crate) fn record_fields(&self, action: RecordAction) -> Result<Vec<String>, &'static str> {
        self.require_clean_records()?;
        match (&self.original, action) {
            (Config::Server(_), RecordAction::NewInbound) => Ok(vec![
                generated_id("inbound")?,
                "0.0.0.0:443".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
            (Config::Client(_), RecordAction::NewProfile) => Ok(vec![
                generated_id("profile")?,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
            (_, RecordAction::DeleteRecord)
            | (Config::Client(_), RecordAction::ActivateProfile) => Ok(vec![]),
            (Config::Server(doc), RecordAction::SetQuota) => Ok(vec![
                doc.server.policy.max_connections_per_user.to_string(),
                doc.server.policy.max_connections_total.to_string(),
            ]),
            (Config::Server(doc), RecordAction::SetGrants) => {
                let inbound = doc
                    .server
                    .inbounds
                    .get(self.selected_record)
                    .ok_or("Inbound missing")?;
                Ok(vec![inbound.allowed_user_ids.join(",")])
            }
            (Config::Server(_), RecordAction::DeleteUser) => Ok(vec![String::new()]),
            (Config::Server(doc), RecordAction::EditTls) => {
                let inbound = doc
                    .server
                    .inbounds
                    .get(self.selected_record)
                    .ok_or("Inbound missing")?;
                if !inbound.security_mode.is_plain() {
                    return Err("Для REALITY требуется отдельная процедура управления доверием.");
                }
                Ok(vec![String::new(), String::new()])
            }
            (Config::Client(doc), RecordAction::EditTrust) => {
                let profile = doc
                    .client
                    .profiles
                    .get(self.selected_record)
                    .ok_or("Profile missing")?;
                if !profile.security_mode.is_plain() {
                    return Err("Для REALITY требуется отдельная процедура управления доверием.");
                }
                Ok(vec![String::new(), String::new()])
            }
            _ => Err("Операция недоступна в этой роли."),
        }
    }

    pub(crate) fn review_record(
        &self,
        action: RecordAction,
        fields: &[String],
    ) -> Result<RecordReview, &'static str> {
        self.require_clean_records()?;
        if fields.len() != action.fields().len()
            || fields
                .iter()
                .any(|v| v.len() > 1024 || v.chars().any(char::is_control))
        {
            return Err("Неверное количество или размер полей.");
        }
        let mut candidate = self.original.clone();
        let mut next_selection = self.selected_record;
        let selected = self.selected_record_id().to_owned();
        let detail = match (&mut candidate, action) {
            (Config::Server(doc), RecordAction::NewInbound) => {
                let grants = parse_grants(&fields[5]);
                let bind: std::net::SocketAddr = fields[1].parse().map_err(|_| "Неверный bind.")?;
                if bind.port() == 0 {
                    return Err("Порт должен быть ненулевым.");
                }
                let prefix = format!("/v1/{}", generated_id("route")?);
                doc.server.inbounds.push(config::Inbound {
                    id: fields[0].clone(),
                    path_prefix: Some(prefix.clone()),
                    security_mode: Default::default(),
                    reality: None,
                    allowed_user_ids: grants.clone(),
                    quic_listen: fields[1].clone(),
                    h2_listen: fields[1].clone(),
                    server_name: fields[2].clone(),
                    tls_cert: fields[3].clone(),
                    tls_key: fields[4].clone(),
                });
                next_selection = doc.server.inbounds.len() - 1;
                format!(
                    "ID: {}\nBind TCP/UDP: {}\nSNI: {}\nXHTTP: {prefix}\nGrants: {}\nCert/key: введены скрытые ссылки",
                    fields[0], fields[1], fields[2], grants.join(", ")
                )
            }
            (Config::Client(doc), RecordAction::NewProfile) => {
                if fields[3].is_empty() {
                    return Err("Требуется явная доверенная CA.");
                }
                doc.client.profiles.push(config::Profile {
                    id: fields[0].clone(),
                    path_prefix: Some(fields[5].clone()),
                    server: fields[1].clone(),
                    server_name: fields[2].clone(),
                    auth_token: fields[4].clone(),
                    security_mode: SecurityMode::Plain,
                    reality_profile: None,
                    xhttp_mode: Some(XhttpMode::Auto),
                    tls_ca: Some(fields[3].clone()),
                    transport: Transport::Auto,
                    quic_connect_timeout_ms: 1600,
                    quic_negative_cache_ttl_s: 900,
                    direct_dpi: None,
                    direct_dpi_stun: None,
                });
                next_selection = doc.client.profiles.len() - 1;
                format!(
                    "ID: {}\nEndpoint: {}\nSNI: {}\nH2/H3 и XHTTP: auto\nCA/credential: скрытые ссылки\nАктивный профиль не меняется.",
                    fields[0], fields[1], fields[2]
                )
            }
            (Config::Server(doc), RecordAction::DeleteRecord) => {
                if doc.server.inbounds.len() <= 1 {
                    return Err("Нельзя удалить последнее подключение. Сначала создайте другое.");
                }
                if self.selected_record >= doc.server.inbounds.len() {
                    return Err("Inbound missing");
                }
                let removed = doc.server.inbounds.remove(self.selected_record);
                next_selection = next_selection.min(doc.server.inbounds.len() - 1);
                format!(
                    "Удалить inbound {} и его grants. Пользователи и файлы ключей сохраняются.",
                    removed.id
                )
            }
            (Config::Client(doc), RecordAction::DeleteRecord) => {
                if doc.client.active_profile == selected {
                    return Err("Выберите другой активный профиль (A), затем повторите удаление.");
                }
                if self.selected_record >= doc.client.profiles.len() {
                    return Err("Profile missing");
                }
                doc.client.profiles.remove(self.selected_record);
                next_selection = next_selection.min(doc.client.profiles.len() - 1);
                format!(
                    "Удалить профиль {selected}. Файлы сертификата и ключа доступа сохраняются."
                )
            }
            (Config::Client(doc), RecordAction::ActivateProfile) => {
                if doc.client.active_profile == selected {
                    return Err("Этот профиль уже выбран. Откройте «Подключить / отключить» (V).");
                }
                let previous = std::mem::replace(&mut doc.client.active_profile, selected.clone());
                format!(
                    "Активный профиль в TOML: {previous} → {selected}. Работающий процесс не переключается."
                )
            }
            (Config::Server(doc), RecordAction::SetQuota) => {
                let per: u32 = fields[0]
                    .parse()
                    .map_err(|_| "Неверный лимит пользователя")?;
                let total: u32 = fields[1].parse().map_err(|_| "Неверный общий лимит")?;
                if per == 0 || total == 0 || per > total {
                    return Err("Требуется 0 < per-user <= total");
                }
                doc.server.policy.max_connections_per_user = per;
                doc.server.policy.max_connections_total = total;
                format!("На пользователя: {per}; всего: {total}\nТолько сохранение TOML. Для runtime: v, затем c (quota-only Apply).")
            }
            (Config::Server(doc), RecordAction::SetGrants) => {
                let inbound = doc
                    .server
                    .inbounds
                    .get_mut(self.selected_record)
                    .ok_or("Inbound missing")?;
                let grants = parse_grants(&fields[0]);
                let old = inbound.allowed_user_ids.join(", ");
                inbound.allowed_user_ids = grants;
                format!(
                    "Inbound {selected}\nБыло: {old}\nБудет: {}\nНе меняет существующие туннели.",
                    inbound.allowed_user_ids.join(", ")
                )
            }
            (Config::Server(doc), RecordAction::DeleteUser) => {
                let id = &fields[0];
                if doc
                    .server
                    .inbounds
                    .iter()
                    .any(|i| i.allowed_user_ids.contains(id))
                {
                    return Err("Сначала удалите grants пользователя во всех inbound.");
                }
                let index = doc
                    .server
                    .users
                    .iter()
                    .position(|u| &u.id == id)
                    .ok_or("Пользователь не найден.")?;
                doc.server.users.remove(index);
                format!("Удалить пользователя {id}. Файлы credential не удаляются.")
            }
            (Config::Server(doc), RecordAction::EditTls) => {
                let inbound = doc
                    .server
                    .inbounds
                    .get_mut(self.selected_record)
                    .ok_or("Inbound missing")?;
                if !inbound.security_mode.is_plain() {
                    return Err("Для REALITY требуется отдельная процедура управления доверием.");
                }
                inbound.tls_cert.clone_from(&fields[0]);
                inbound.tls_key.clone_from(&fields[1]);
                format!(
                    "Inbound {selected}: заменить обе скрытые ссылки cert/key. Не TLS rotation."
                )
            }
            (Config::Client(doc), RecordAction::EditTrust) => {
                let profile = doc
                    .client
                    .profiles
                    .get_mut(self.selected_record)
                    .ok_or("Profile missing")?;
                if !profile.security_mode.is_plain() || fields[0].is_empty() {
                    return Err("Требуется own-TLS и явная доверенная CA.");
                }
                profile.tls_ca = Some(fields[0].clone());
                profile.auth_token.clone_from(&fields[1]);
                format!("Профиль {selected}: явно заменить скрытые ссылки CA и credential.")
            }
            _ => return Err("Операция недоступна в этой роли."),
        };
        candidate.validate().map_err(|_| {
            "Конфигурация не прошла строгую проверку; проверьте ID, ссылки, grants и bind."
        })?;
        if candidate == self.original {
            return Err("Изменений нет.");
        }
        Ok(RecordReview {
            source: self.saved_sha256(),
            selected,
            candidate,
            next_selection,
            confirmation_label: match action {
                RecordAction::NewInbound => "Создать подключение",
                RecordAction::NewProfile => "Создать профиль",
                RecordAction::DeleteRecord if self.role() == Role::Server => "Удалить подключение",
                RecordAction::DeleteRecord => "Удалить профиль",
                RecordAction::DeleteUser => "Удалить пользователя",
                RecordAction::ActivateProfile => "Сделать активным",
                RecordAction::SetGrants => "Сохранить права",
                RecordAction::SetQuota => "Сохранить лимиты",
                RecordAction::EditTls | RecordAction::EditTrust => "Заменить настройки доверия",
            },
            body: format!(
                "{}\n{detail}\n\nИзменяется только файл настроек. Работающий процесс и остальные файлы не изменяются.\ny: подтвердить; n/Esc: отменить",
                action.title()
            ),
        })
    }

    pub(crate) fn stage_record(&mut self, review: RecordReview) -> Result<(), &'static str> {
        self.require_clean_records()?;
        if review.source != self.saved_sha256() || review.selected != self.selected_record_id() {
            return Err("Выбранная запись или исходный файл изменились; повторите preview.");
        }
        self.draft = review.candidate;
        self.selected_record = review.next_selection;
        self.selected_field = 0;
        self.error = None;
        self.notice = "Подтверждено. Требуется guarded save; runtime не изменён.";
        Ok(())
    }

    /// Validated SNI of the selected server inbound.
    pub fn selected_server_name(&self) -> Option<&str> {
        let Config::Server(doc) = &self.draft else {
            return None;
        };
        doc.server
            .inbounds
            .get(self.selected_record)
            .map(|inbound| inbound.server_name.as_str())
    }

    /// Saved local consent belongs to the selected profile, not the backend.
    /// A draft or another profile never grants consent to this one.
    fn saved_selected_profile(&self) -> Option<&config::Profile> {
        let Config::Client(doc) = &self.original else {
            return None;
        };
        doc.client
            .profiles
            .iter()
            .find(|p| p.id == self.selected_record_id())
    }

    pub(crate) fn direct_dpi_allowed(&self) -> bool {
        self.saved_selected_profile()
            .is_some_and(|p| p.direct_dpi == Some(true))
    }

    pub(crate) fn direct_dpi_stun_allowed(&self) -> bool {
        self.saved_selected_profile()
            .is_some_and(|p| p.direct_dpi == Some(true) && p.direct_dpi_stun == Some(true))
    }

    pub(crate) fn review_direct_dpi_permission(&self) -> Result<RecordReview, &'static str> {
        self.require_clean_records()?;
        if self.write_uncertain {
            return Err("Откройте настройки заново.");
        }
        let enable = !self.direct_dpi_allowed();
        let mut candidate = self.original.clone();
        let Config::Client(doc) = &mut candidate else {
            return Err("Требуется клиентская конфигурация.");
        };
        let profile = doc
            .client
            .profiles
            .iter_mut()
            .find(|p| p.id == self.selected_record_id())
            .ok_or("Профиль не найден.")?;
        profile.direct_dpi = Some(enable);
        if !enable {
            profile.direct_dpi_stun = Some(false);
        }
        candidate
            .validate()
            .map_err(|_| "Настройки клиента не прошли проверку.")?;
        Ok(RecordReview {
            source: self.saved_sha256(),
            selected: self.selected_record_id().to_owned(),
            candidate,
            next_selection: self.selected_record,
            confirmation_label: if enable {
                "Разрешить Anti-DPI"
            } else {
                "Отключить Anti-DPI"
            },
            body: if enable {
                "Разрешить локальный Anti-DPI для выбранного профиля?\n\nДля правил direct_via_client_anti_dpi возможен локальный TCP/TLS-выход и независимая TLS-проверка назначения: сайт увидит IP вашего устройства. QUIC Modify допускается только после приёмки конкретной стратегии; STUN требует отдельного согласия. Непринятые стратегии используют VPS. DNS запрашивается через Theia. Остальные правила не меняются.\nСохранение не запускает режим; перезапустите клиент.\n\ny: разрешить · n/Esc: отменить".into()
            } else {
                "Отключить локальный Anti-DPI?\nПравила direct_via_client_anti_dpi будут использовать VPS после применения нового поколения клиента.\n\ny: отключить · n/Esc: отменить".into()
            },
        })
    }

    pub(crate) fn review_direct_dpi_stun_permission(&self) -> Result<RecordReview, &'static str> {
        self.require_clean_records()?;
        if self.write_uncertain {
            return Err("Откройте настройки заново.");
        }
        if !self.direct_dpi_allowed() {
            return Err("Сначала разрешите и сохраните Anti-DPI.");
        }
        let enable = !self.direct_dpi_stun_allowed();
        let mut candidate = self.original.clone();
        let Config::Client(doc) = &mut candidate else {
            return Err("Требуется клиентская конфигурация.");
        };
        let profile = doc
            .client
            .profiles
            .iter_mut()
            .find(|p| p.id == self.selected_record_id())
            .ok_or("Профиль не найден.")?;
        profile.direct_dpi_stun = Some(enable);
        candidate
            .validate()
            .map_err(|_| "Настройки клиента не прошли проверку.")?;
        Ok(RecordReview {
            source: self.saved_sha256(),
            selected: self.selected_record_id().to_owned(),
            candidate,
            next_selection: self.selected_record,
            confirmation_label: if enable {
                "Разрешить STUN"
            } else {
                "Отозвать согласие STUN"
            },
            body: if enable {
                format!("Сохранить отдельное согласие на STUN Binding для этого профиля?\nПосле приёмки стратегии публичный STUN-сервер может увидеть IP вашего устройства. Только credential-free Binding; ICE/TURN и неподдерживаемые запросы остаются через VPS.\n{}\nСогласие не заменяет приёмку и не запускает сеть.\n\ny: разрешить · n/Esc: отменить", crate::routing::dpi::UdpStrategy::capability_summary())
            } else {
                "Отозвать согласие STUN? После применения нового поколения локальный STUN Modify не разрешён.\n\ny: отозвать · n/Esc: отменить".into()
            },
        })
    }

    /// Non-secret values for the settings page. These are saved, not live.
    pub(crate) fn settings_summary(&self) -> String {
        match &self.original {
            Config::Server(doc) => format!(
                "Лимит на пользователя: {}\nОбщий лимит соединений: {}",
                doc.server.policy.max_connections_per_user, doc.server.policy.max_connections_total
            ),
            Config::Client(doc) => format!(
                "HTTP: {}\nSOCKS5: {}\nРежим: System Proxy (сохранённый выбор, не состояние ОС)",
                doc.client.proxy.http_listen, doc.client.proxy.socks5_listen
            ),
        }
    }

    pub(crate) fn client_proxy_addresses(&self) -> Option<(&str, &str)> {
        match &self.original {
            Config::Client(doc) => Some((
                &doc.client.proxy.http_listen,
                &doc.client.proxy.socks5_listen,
            )),
            _ => None,
        }
    }

    pub fn selected_record_is_active(&self) -> bool {
        match &self.draft {
            Config::Client(doc) => doc.client.active_profile == self.selected_record_id(),
            Config::Server(_) => false,
        }
    }

    pub fn selection_summary(&self) -> String {
        if self.record_count() == 0 {
            return "Нет записей".into();
        }
        if self.selected_reality() {
            return format!(
                "REALITY {}/{}: {} [защищённое подключение]",
                self.selected_record + 1,
                self.record_count(),
                if self.role == Role::Server {
                    self.server_connection_label(self.selected_record_id())
                        .unwrap_or_else(|| self.selected_record_id().into())
                } else {
                    self.selected_record_id().into()
                }
            );
        }
        match self.role {
            Role::Server => format!(
                "Подключение {}/{}: {}",
                self.selected_record + 1,
                self.record_count(),
                self.server_connection_label(self.selected_record_id())
                    .unwrap_or_else(|| self.selected_record_id().into()),
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

    /// Compact workspace fields: hide client transport details, and never
    /// collapse distinct server listeners. The common port edit is atomic.
    pub(crate) fn set_compact_server_fields(&mut self, compact: bool) {
        if !self.editing {
            self.compact_server_fields = compact;
            self.selected_field = self
                .selected_field
                .min(self.field_count().saturating_sub(1));
        }
    }

    pub(crate) fn compact_server_fields(&self) -> bool {
        self.role == Role::Server && self.compact_server_fields
    }

    fn common_listener(&self) -> Option<std::net::SocketAddr> {
        let Config::Server(doc) = &self.draft else {
            return None;
        };
        let inbound = doc.server.inbounds.get(self.selected_record)?;
        let h2 = inbound.h2_listen.parse::<std::net::SocketAddr>().ok()?;
        let h3 = inbound.quic_listen.parse::<std::net::SocketAddr>().ok()?;
        (h2 == h3).then_some(h2)
    }

    pub fn field_count(&self) -> usize {
        match self.role {
            Role::Server if self.compact_server_fields => {
                if self.common_listener().is_some() {
                    2
                } else {
                    1
                }
            }
            Role::Server => 3,
            Role::Client if self.compact_server_fields => 1,
            Role::Client => 4,
        }
    }

    /// Record and field focus never change the typed configuration.
    pub(crate) fn select_id(&mut self, id: &str) {
        let index = match &self.draft {
            Config::Server(doc) => doc.server.inbounds.iter().position(|entry| entry.id == id),
            Config::Client(doc) => doc.client.profiles.iter().position(|entry| entry.id == id),
        };
        if let Some(index) = index {
            self.selected_record = index;
            self.selected_field = 0;
        }
    }

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

    pub(crate) fn workspace_select_field(&mut self, index: usize) {
        if !self.editing && self.issued.is_none() && index < self.field_count() {
            self.selected_field = index;
            self.error = None;
        }
    }

    pub(crate) fn workspace_field_index(&self) -> usize {
        self.selected_field
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
            Role::Server if self.compact_server_fields && self.selected_field == 1 => "common_port",
            Role::Server => ["server_name", "h2_listen", "quic_listen"][self.selected_field],
            Role::Client => {
                ["server", "server_name", "transport", "xhttp_mode"][self.selected_field]
            }
        };
        let records = match self.role {
            Role::Server => "server.inbounds",
            Role::Client => "client.profiles",
        };
        format!("{records}[{}].{suffix}", self.selected_record)
    }

    pub fn field_value(&self) -> String {
        if self.compact_server_fields() && self.selected_field == 1 {
            return self
                .common_listener()
                .map_or_else(String::new, |address| address.port().to_string());
        }
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
                    _ => xhttp_value(profile.effective_xhttp_mode()),
                })
                .unwrap_or_default(),
        }
    }

    /// Render only the explicitly whitelisted non-secret fields.
    /// Never include token refs, TLS key refs, grants, or config file paths.
    pub(crate) fn workspace_fields(&self) -> Vec<(&'static str, String, bool)> {
        let labels: &[&str] = match self.role {
            Role::Server if self.compact_server_fields => &["Адрес сервера", "Порт подключения"],
            Role::Server => &["TLS DNS", "H2 TCP", "H3 UDP"],
            Role::Client if self.compact_server_fields => &["Адрес сервера"],
            Role::Client => &["Адрес сервера", "Имя сервера (TLS)", "Транспорт", "Режим XHTTP"],
        };
        let values: Vec<String> = match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .map(|inbound| {
                    if self.compact_server_fields {
                        let mut fields = vec![inbound.server_name.clone()];
                        if let Some(address) = self.common_listener() {
                            fields.push(address.port().to_string());
                        }
                        return fields;
                    }
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
                        xhttp_value(p.effective_xhttp_mode()),
                    ]
                })
                .unwrap_or_default(),
        };
        labels
            .iter()
            .copied()
            .zip(values)
            .enumerate()
            .map(|(index, (label, value))| {
                let selected = self.selected_field == index;
                let value = if self.editing && selected {
                    self.input.clone()
                } else {
                    value
                };
                (label, value, selected)
            })
            .collect()
    }

    pub fn fields_overview(&self) -> String {
        let mut output = String::new();
        for (label, value, selected) in self.workspace_fields() {
            let marker = if selected { '>' } else { ' ' };
            output.push_str(&format!("{marker} {label}: {value}\n"));
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

    pub(crate) fn saved_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn selected_reality(&self) -> bool {
        match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .is_some_and(|i| {
                    i.security_mode == crate::security_profile::SecurityMode::SmartReality
                }),
            Config::Client(doc) => doc
                .client
                .profiles
                .get(self.selected_record)
                .is_some_and(|p| p.security_mode == SecurityMode::SmartReality),
        }
    }

    pub fn begin(&mut self) {
        if self.selected_reality() {
            self.error = Some("Параметры REALITY защищены. Используйте действия выбранного подключения для изменения доверия.".into());
            return;
        }
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

    pub(crate) fn choice_options(&self) -> &'static [&'static str] {
        if self.role != Role::Client || self.selected_reality() {
            return &[];
        }
        match self.selected_field {
            2 => &["auto", "h2", "h3"],
            3 => &["auto", "stream-one", "stream-up"],
            _ => &[],
        }
    }

    pub(crate) fn cycle_choice(&mut self, forward: bool) {
        let options = self.choice_options();
        if !self.editing || options.is_empty() {
            return;
        }
        let index = options
            .iter()
            .position(|value| *value == self.input.as_str());
        let next = match index {
            Some(i) if forward => (i + 1) % options.len(),
            Some(i) => (i + options.len() - 1) % options.len(),
            None if forward => 0,
            None => options.len() - 1,
        };
        self.input = options[next].to_owned();
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
        let compact = self.compact_server_fields();
        let common = self.common_listener();
        match &mut candidate {
            Config::Server(doc) => {
                let Some(inbound) = doc.server.inbounds.get_mut(self.selected_record) else {
                    self.error = Some("server.inbounds: selected record missing".into());
                    return false;
                };
                match self.selected_field {
                    0 => inbound.server_name.clone_from(&self.input),
                    1 if compact => {
                        let Some(mut address) = common else {
                            self.error =
                                Some("Раздельные адреса требуют расширенных настроек.".into());
                            return false;
                        };
                        let Ok(port) = self.input.parse::<u16>() else {
                            self.error = Some("Введите номер порта от 1 до 65535.".into());
                            return false;
                        };
                        if port == 0 {
                            self.error = Some("Введите номер порта от 1 до 65535.".into());
                            return false;
                        }
                        address.set_port(port);
                        let value = address.to_string();
                        inbound.h2_listen.clone_from(&value);
                        inbound.quic_listen = value;
                    }
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
                            "auto" => Some(XhttpMode::Auto),
                            "stream-one" => Some(XhttpMode::StreamOne),
                            "stream-up" => Some(XhttpMode::StreamUp),
                            _ => {
                                self.error = Some(format!(
                                    "{field}: expected auto, stream-one or stream-up"
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
        self.selected_record = self
            .selected_record
            .min(self.record_count().saturating_sub(1));
        self.selected_field = 0;
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
        crate::invite::fixture_server_source(&[0x42; 32])
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

    #[test]
    fn record_lifecycle_client_create_activate_delete_and_conflict() {
        let fixture = Temp::write(&two_profiles());
        let mut editor = Editor::load(Role::Client, &fixture.0).unwrap();
        let fields = vec![
            "extra".into(),
            "extra.example.org:443".into(),
            "extra.example.org".into(),
            "file:/tmp/ca.pem".into(),
            "env:EXTRA_TOKEN".into(),
            "/v1/extra".into(),
        ];
        let preview = editor
            .review_record(RecordAction::NewProfile, &fields)
            .unwrap();
        assert!(!preview.body().contains("EXTRA_TOKEN"));
        assert!(!preview.body().contains("/tmp/ca.pem"));
        assert!(!editor.dirty());
        editor.stage_record(preview).unwrap();
        assert!(editor.dirty());
        assert_eq!(editor.selected_record_id(), "extra");
        assert!(!editor.selected_record_is_active());
        assert!(editor.save());
        let preview = editor
            .review_record(RecordAction::ActivateProfile, &[])
            .unwrap();
        editor.stage_record(preview).unwrap();
        assert!(editor.save());
        assert!(editor.selected_record_is_active());
        assert!(editor
            .review_record(RecordAction::DeleteRecord, &[])
            .is_err());
        editor.select_record(true);
        let preview = editor
            .review_record(RecordAction::DeleteRecord, &[])
            .unwrap();
        let before = fs::read_to_string(&fixture.0).unwrap();
        fs::write(&fixture.0, format!("{before}\n# external edit\n")).unwrap();
        assert!(editor.stage_record(preview).is_err());
        assert!(!editor.dirty());
    }

    #[test]
    fn record_lifecycle_server_validates_grants_and_preserves_references() {
        let fixture = Temp::write(&two_inbounds());
        let mut editor = Editor::load(Role::Server, &fixture.0).unwrap();
        let mut fields = vec![
            "extra".into(),
            "0.0.0.0:9443".into(),
            "extra.example.org".into(),
            "file:/tmp/cert.pem".into(),
            "file:/tmp/key.pem".into(),
            "unknown".into(),
        ];
        assert!(editor
            .review_record(RecordAction::NewInbound, &fields)
            .is_err());
        fields[5] = "device-a".into();
        let preview = editor
            .review_record(RecordAction::NewInbound, &fields)
            .unwrap();
        assert!(!preview.body().contains("/tmp/key.pem"));
        editor.stage_record(preview).unwrap();
        assert!(editor.save());
        assert_eq!(editor.record_count(), 3);
        assert!(editor
            .review_record(RecordAction::DeleteUser, &["device-a".into()])
            .is_err());
        assert!(editor
            .review_record(RecordAction::SetGrants, &["device-a,device-a".into()])
            .is_err());
        let preview = editor
            .review_record(RecordAction::DeleteRecord, &[])
            .unwrap();
        editor.stage_record(preview).unwrap();
        editor.discard();
        assert_eq!(editor.record_count(), 3);
        assert!(!editor.dirty());
        editor.select_record(true);
        let preview = editor
            .review_record(RecordAction::DeleteRecord, &[])
            .unwrap();
        editor.stage_record(preview).unwrap();
        assert!(editor.save());
        assert_eq!(editor.record_count(), 2);
        let Config::Server(doc) = config::read_file(&fixture.0).unwrap() else {
            panic!("server fixture");
        };
        assert_eq!(doc.server.users.len(), 1);
    }

    #[test]
    fn record_grants_and_user_deletion_are_independent_confirmed_changes() {
        let Config::Server(mut doc) = config::parse(&two_inbounds()).unwrap() else {
            panic!("server fixture");
        };
        doc.server.users.push(User {
            id: "other".into(),
            token_sha256: format!("{:x}", Sha256::digest([0x43; 32])),
            disabled: false,
        });
        let fixture = Temp::write(&Config::Server(doc).to_toml().unwrap());
        let mut editor = Editor::load(Role::Server, &fixture.0).unwrap();
        assert!(editor.record_fields(RecordAction::NewProfile).is_err());
        let catalog = editor.record_user_catalog(RecordAction::SetGrants).unwrap();
        assert!(catalog.contains("other"));
        assert!(!catalog.contains(&format!("{:x}", Sha256::digest([0x43; 32]))));
        let review = editor
            .review_record(RecordAction::SetGrants, &["other".into()])
            .unwrap();
        editor.select_record(true);
        assert!(editor.stage_record(review).is_err());
        assert!(!editor.dirty());
        for _ in 0..2 {
            let review = editor
                .review_record(RecordAction::SetGrants, &["other".into()])
                .unwrap();
            editor.stage_record(review).unwrap();
            assert!(editor.save());
            editor.select_record(true);
        }
        let review = editor
            .review_record(RecordAction::DeleteUser, &["device-a".into()])
            .unwrap();
        editor.stage_record(review).unwrap();
        assert!(editor.save());
        let Config::Server(doc) = config::read_file(&fixture.0).unwrap() else {
            panic!("server fixture");
        };
        assert_eq!(doc.server.users.len(), 1);
        assert_eq!(doc.server.users[0].id, "other");
        assert!(doc
            .server
            .inbounds
            .iter()
            .all(|i| i.allowed_user_ids == ["other"]));
    }

    #[test]
    fn record_trust_edit_requires_explicit_refs_and_preserves_other_fields() {
        let fixture = Temp::write(&two_profiles());
        let mut editor = Editor::load(Role::Client, &fixture.0).unwrap();
        let before = config::read_file(&fixture.0).unwrap();
        assert!(editor
            .review_record(RecordAction::EditTrust, &["".into(), "env:NEW".into()])
            .is_err());
        assert!(editor
            .review_record(
                RecordAction::EditTrust,
                &["file:/new/ca.pem".into(), "literal-token".into()]
            )
            .is_err());
        let review = editor
            .review_record(
                RecordAction::EditTrust,
                &["file:/new/ca.pem".into(), "env:NEW".into()],
            )
            .unwrap();
        assert!(!review.body().contains("env:NEW"));
        editor.stage_record(review).unwrap();
        assert!(editor.save());
        let Config::Client(mut expected) = before else {
            panic!("client fixture");
        };
        expected.client.profiles[0].tls_ca = Some("file:/new/ca.pem".into());
        expected.client.profiles[0].auth_token = "env:NEW".into();
        assert_eq!(
            config::read_file(&fixture.0).unwrap(),
            Config::Client(expected)
        );
    }

    fn uncertain_failure() -> config::WriteFailure {
        config::WriteFailure::AfterReplace(config::ConfigError {
            field: "config".into(),
            reason: "injected directory sync failure",
        })
    }

    #[test]
    fn retired_pinned_modes_cannot_be_loaded_into_editor() {
        for mode in ["pinned-cert-v1", "pinned-cert-stream-up-v1"] {
            let source = server_source().replace(
                "security_mode = \"own-tls\"",
                &format!("security_mode = \"{mode}\""),
            );
            let file = Temp::write(&source);
            assert!(Editor::load(Role::Server, &file.0).is_err());
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
    fn quota_edit_requires_valid_bounds_and_durable_save() {
        let temp = Temp::write(&server_source());
        let original = fs::read(&temp.0).unwrap();
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        assert_eq!(
            editor.record_fields(RecordAction::SetQuota).unwrap().len(),
            2
        );
        for values in [["0", "4"], ["5", "4"], ["x", "4"], ["4", "0"]] {
            assert!(editor
                .review_record(RecordAction::SetQuota, &values.map(str::to_owned))
                .is_err());
        }
        let review = editor
            .review_record(RecordAction::SetQuota, &["3".into(), "7".into()])
            .unwrap();
        assert_eq!(fs::read(&temp.0).unwrap(), original);
        editor.stage_record(review).unwrap();
        assert_eq!(fs::read(&temp.0).unwrap(), original);
        assert!(editor.save());
        let Config::Server(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("server");
        };
        assert_eq!(doc.server.policy.max_connections_per_user, 3);
        assert_eq!(doc.server.policy.max_connections_total, 7);
    }

    #[test]
    fn registered_reality_issuance_rotation_and_recovery_use_same_saved_guard() {
        use crate::reference_health::{Evidence, Plan, State, Store, Target};
        let temp = Temp::write(&server_source());
        let directory = temp.0.with_extension("reality");
        fs::create_dir(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let now = crate::reference_health::unix_now().unwrap();
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "reality".into(),
                endpoint: "127.0.0.1:9443".into(),
                own_ips: vec!["127.0.0.1".parse().unwrap()],
                references: vec![Target {
                    server_name: "reference.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![Evidence {
                h2_status: Some(200),
                h3_status: Some(200),
            }],
            now,
        )
        .unwrap();
        let health = directory.join("health.toml");
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let bundle = directory.join("bundle");
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
        let request =
            crate::reality_config::Request::Server(crate::reality_config::ServerRequest {
                health,
                bundle,
                health_sha256: digest,
                identity_sha256: record.identity_sha256,
                listen: "127.0.0.1:9443".parse().unwrap(),
                grants: vec!["device-a".into()],
            });
        let review = crate::reality_config::prepare(&temp.0, &request, now).unwrap();
        crate::reality_config::apply(&temp.0, &request, review.approval_sha256(), now).unwrap();
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.select_record(true);
        assert!(editor.selected_reality());
        let public = editor.public_share().unwrap();
        let parsed = crate::reality_bootstrap::Invitation::decode(&public, now).unwrap();
        assert!(!parsed.has_token());
        assert_eq!(parsed.fingerprint(), record.identity_sha256);
        editor.issue_user("new-reality").unwrap();
        assert!(editor.take_issued().is_none());
        assert!(editor.save());
        let invite = editor.take_issued().unwrap();
        let first = Zeroizing::new(invite.token_bytes().unwrap());
        let raw = Zeroizing::new(invite.encode().unwrap());
        assert!(crate::reality_bootstrap::Invitation::decode(&raw, now)
            .unwrap()
            .has_token());
        assert!(editor.take_issued().is_none());
        editor.rotate_user("new-reality").unwrap();
        assert!(editor.save());
        let path = editor.export_issued_file().unwrap();
        let encoded =
            crate::reality_bootstrap::read_text(&path, crate::invite::MAX_URI, true).unwrap();
        let rotated = crate::reality_bootstrap::Invitation::decode(&encoded, now).unwrap();
        assert_ne!(rotated.token_bytes(), Some(*first));
        fs::remove_file(&path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
        editor.disable_user("new-reality").unwrap();
        assert!(editor.save());
        assert!(editor.rotate_user("new-reality").is_err());
        editor.reenable_user("new-reality").unwrap();
        assert!(editor.save());
        assert!(editor.take_issued().unwrap().token_bytes().is_some());
        assert!(editor.take_issued().is_none());
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

    #[test]
    fn editor_refuses_retired_browser_security_profile() {
        let source = include_str!("../../../examples/client.toml").replace(
            "security_mode = \"own-tls\"",
            "security_mode = \"browser-h2-btls-v1\"",
        );
        let temp = Temp::write(&source);
        assert!(Editor::load(Role::Client, &temp.0).is_err());
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
        let source = crate::invite::fixture_server_source(&token);
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
        assert_eq!(doc.client.profiles[1].tls_ca, initial.trust_reference());
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
        // Same endpoint/name/transport but different trust is not rotation.
        let mut other_server =
            config::parse(&crate::invite::fixture_server_source(&[0x43; 32])).unwrap();
        let Config::Server(document) = &mut other_server else {
            panic!("server");
        };
        let other_cert =
            rcgen::generate_simple_self_signed(vec![initial.server_name.clone()]).unwrap();
        let cert_file = Temp::write(&other_cert.cert.pem());
        document.server.inbounds[0].tls_cert = format!("file:{}", cert_file.0.display());
        let other_invite =
            Invitation::issued_from_server(&other_server, "public", "device-a", &[0x43; 32])
                .unwrap();
        assert_ne!(other_invite.trust_reference(), initial.trust_reference());
        assert!(editor.refresh_credential(&other_invite).is_err());
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
        assert_eq!(imported.tls_ca, invite.trust_reference());
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
    fn import_rejects_unrelated_ca_and_preserves_invitation_anchor() {
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
            .is_err());
        assert!(editor.import_invitation(&invite, None, None).is_ok());
        let Config::Client(doc) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(
            doc.client.profiles[1].tls_ca.as_deref(),
            invite.trust_reference().as_deref()
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
        assert_eq!(
            saved.client.profiles[0].effective_xhttp_mode(),
            XhttpMode::Auto
        );
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
    fn common_server_port_edits_both_listeners_only_after_validation() {
        let source = server_source();
        let temp = Temp::write(&source);
        let mut editor = Editor::load(Role::Server, &temp.0).unwrap();
        editor.set_compact_server_fields(true);
        assert_eq!(editor.field_count(), 2);
        editor.workspace_select_field(1);
        assert_eq!(editor.field_value(), "443");
        editor.begin();
        editor.input = "0".into();
        assert!(!editor.accept());
        assert!(!editor.dirty());
        editor.input = "8443".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), source);
        editor.set_compact_server_fields(false);
        let fields = editor.workspace_fields();
        assert!(fields[1].1.ends_with(":8443") && fields[2].1.ends_with(":8443"));
        editor.workspace_select_field(2);
        editor.begin();
        editor.input = "0.0.0.0:9443".into();
        assert!(editor.accept());
        editor.set_compact_server_fields(true);
        assert_eq!(editor.field_count(), 1);
        assert_eq!(editor.workspace_fields().len(), 1);
        assert_eq!(editor.workspace_field_index(), 0);
        editor.set_compact_server_fields(false);
        assert_eq!(editor.workspace_fields()[2].1, "0.0.0.0:9443");
        assert_eq!(fs::read_to_string(&temp.0).unwrap(), source);
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
