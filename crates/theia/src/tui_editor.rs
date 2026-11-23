//! M4.1c typed, bounded, selectable inbound/profile configuration forms.
//!
//! A user-provided configuration file is explicit. Never print its contents,
//! secret references, token hashes or path in diagnostics. All writes go
//! through the existing strict validator and atomic store.
use crate::{
    config::{self, Config, Transport, User},
    invite::Invitation,
    Role,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_DOCUMENT: u64 = 1024 * 1024;
const MAX_INPUT: usize = 255;

pub struct Editor {
    role: Role,
    path: PathBuf,
    source: Vec<u8>,
    original: Config,
    draft: Config,
    issued: Option<Invitation>,
    issued_ready: bool,
    selected_record: usize,
    selected_field: usize,
    pub input: String,
    pub editing: bool,
    pub error: Option<String>,
    pub notice: &'static str,
}

impl Editor {
    pub fn load(role: Role, path: &Path) -> Result<Self, &'static str> {
        // Refuse symlinked paths rather than modifying the referenced file.
        let metadata = fs::symlink_metadata(path).map_err(|_| "cannot inspect config file")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("configuration must be an existing regular file");
        }
        let source = read_bounded(path).map_err(|_| "cannot read config file")?;
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
            selected_record,
            selected_field: 0,
            input: String::new(),
            editing: false,
            error: None,
            notice: "Загружено. Изменения не применяются к runtime.",
        })
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
        let result = self.try_rotate_user(user_id);
        if let Err(message) = result {
            self.error = Some(message.to_owned());
        }
        result
    }

    fn try_rotate_user(&mut self, user_id: &str) -> Result<(), &'static str> {
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
            return Err("Disabled users require a separate explicit re-enable flow");
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
        candidate
            .validate()
            .map_err(|_| "Rotated user did not pass configuration validation")?;
        let invitation = Invitation::issued_from_server(&candidate, &inbound_id, user_id, &token)
            .map_err(|_| "Cannot issue replacement invitation for selected inbound")?;
        self.draft = candidate;
        self.issued = Some(invitation);
        self.issued_ready = false;
        self.error = None;
        self.notice = "Токен заменён в черновике. Сохранение не обновляет runtime.";
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
        self.issued.take()
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
        3
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
            Role::Client => ["server", "server_name", "transport"][self.selected_field],
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
                    _ => match profile.transport {
                        Transport::Auto => "auto".to_owned(),
                        Transport::H2 => "h2".to_owned(),
                        Transport::H3 => "h3".to_owned(),
                    },
                })
                .unwrap_or_default(),
        }
    }

    /// Render only the three explicitly whitelisted non-secret fields.
    /// Never include token refs, TLS key refs, grants, or config file paths.
    pub fn fields_overview(&self) -> String {
        let labels = match self.role {
            Role::Server => ["TLS DNS", "H2 TCP", "H3 UDP"],
            Role::Client => ["Endpoint", "TLS SNI", "Transport"],
        };
        let values: [String; 3] = match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .get(self.selected_record)
                .map(|inbound| {
                    [
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
                    [
                        p.server.clone(),
                        p.server_name.clone(),
                        match p.transport {
                            Transport::Auto => "auto".to_owned(),
                            Transport::H2 => "h2".to_owned(),
                            Transport::H3 => "h3".to_owned(),
                        },
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

    pub fn dirty(&self) -> bool {
        self.draft != self.original
    }

    /// An exact digest of the bytes last loaded or durably saved by this
    /// editor. It is NOT the dirty draft or a bearer credential. The running
    /// Linux server must verify the same bytes before accepting TUI Apply.
    pub(crate) fn saved_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.source).into()
    }

    pub fn begin(&mut self) {
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
                    _ => {
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
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => meta,
            _ => {
                self.error = Some("config: file missing or not regular".into());
                return false;
            }
        };
        if metadata.len() > MAX_DOCUMENT {
            self.error = Some("config: file exceeds size limit".into());
            return false;
        }
        let unchanged = read_bounded(&self.path)
            .map(|bytes| bytes == self.source)
            .unwrap_or(false);
        if !unchanged {
            self.error = Some("config: file changed externally; reload before saving".into());
            return false;
        }
        let serialized = match self.draft.to_toml() {
            Ok(data) => data,
            Err(error) => {
                self.error = Some(error.to_string());
                return false;
            }
        };
        if let Err(error) = config::atomic_write(&self.path, &self.draft) {
            self.error = Some(error.to_string());
            return false;
        }
        self.source = serialized.into_bytes();
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

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?
        .take(MAX_DOCUMENT + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_DOCUMENT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration too large",
        ));
    }
    Ok(data)
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
        assert!(Invitation::decode(&invite.encode().unwrap()).unwrap().has_token());
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
        assert!(editor.save());
        let Config::Client(saved) = config::read_file(&temp.0).unwrap() else {
            panic!("client");
        };
        assert_eq!(saved.client.active_profile, "home");
        assert_eq!(saved.client.profiles[0].server, "edge.example.org:443");
        assert_eq!(saved.client.profiles[1].server, "new-work.example.org:8443");
        assert_eq!(saved.client.profiles[1].server_name, "new-work.example.org");
        assert_eq!(saved.client.profiles[1].transport, config::Transport::H2);
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
