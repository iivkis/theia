//! M4.1b typed, bounded, single-field configuration drafts.
//!
//! A user-provided configuration file is explicit. Never print its contents,
//! secret references, token hashes or path in diagnostics. All writes go
//! through the existing strict validator and atomic store.
use crate::{
    config::{self, Config},
    Role,
};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_DOCUMENT: u64 = 1024 * 1024;
const MAX_INPUT: usize = 255;

pub struct Editor {
    role: Role,
    path: PathBuf,
    source: Vec<u8>,
    original: Config,
    draft: Config,
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
        Ok(Self {
            role,
            path: path.to_owned(),
            source,
            original: parsed.clone(),
            draft: parsed,
            input: String::new(),
            editing: false,
            error: None,
            notice: "Загружено. Изменения не применяются к runtime.",
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn field_name(&self) -> &'static str {
        match self.role {
            Role::Server => "server.inbounds[0].server_name",
            Role::Client => "client.profiles[active].server",
        }
    }

    pub fn field_value(&self) -> &str {
        match &self.draft {
            Config::Server(doc) => doc
                .server
                .inbounds
                .first()
                .map(|inbound| inbound.server_name.as_str())
                .unwrap_or(""),
            Config::Client(doc) => doc
                .client
                .profiles
                .iter()
                .find(|p| p.id == doc.client.active_profile)
                .map(|profile| profile.server.as_str())
                .unwrap_or(""),
        }
    }

    pub fn dirty(&self) -> bool {
        self.draft != self.original
    }

    pub fn begin(&mut self) {
        self.input = self.field_value().to_owned();
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

    /// Validate an updated typed document before accepting a visible field.
    pub fn accept(&mut self) -> bool {
        if !self.editing {
            return false;
        }
        let mut candidate = self.draft.clone();
        match &mut candidate {
            Config::Server(doc) => {
                if let Some(inbound) = doc.server.inbounds.first_mut() {
                    inbound.server_name.clone_from(&self.input);
                }
            }
            Config::Client(doc) => {
                if let Some(profile) = doc
                    .client
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == doc.client.active_profile)
                {
                    profile.server.clone_from(&self.input);
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
        let Config::Client(mut doc) = config::parse(include_str!("../../../examples/client.toml")).unwrap() else {
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
        assert_eq!(editor.field_name(), "client.profiles[active].server");
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
