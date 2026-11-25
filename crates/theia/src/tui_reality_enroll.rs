//! Client enrollment UI for the independently pinned REALITY trust store.
//! Reads explicit protected local files, never starts a proxy or changes
//! the active own-TLS profile. All file operations run outside terminal I/O.
use crate::{
    reality_bootstrap::{self as bootstrap, EnrollmentMaterial, Error, ImportApproval, Invitation},
    reference_health,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{path::PathBuf, sync::mpsc::{self, Receiver, TryRecvError}};
use zeroize::Zeroizing;

const LIMIT: usize = 1024;
const LABELS: [&str; 6] = ["Файл приглашения", "Отдельный admission-файл", "Новый файл профиля",
    "Новый trust store", "Fingerprint из независимого канала", "Ссылка bearer (если нет в приглашении)"];

struct Input {
    source: PathBuf,
    admission: PathBuf,
    profile: PathBuf,
    trust: PathBuf,
    identity: [u8; 32],
    token: Option<Zeroizing<String>>,
}

struct Review {
    approval: ImportApproval,
    admission: [u8; 32],
    body: String,
}

fn inspect(input: &Input, now: u64) -> Result<Review, Error> {
    for path in [&input.source, &input.admission, &input.profile, &input.trust] {
        if !crate::bounded_input::explicit_file_path(path) { return Err(Error::Storage); }
    }
    if input.profile == input.trust { return Err(Error::Storage); }
    for path in [&input.profile, &input.trust] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::Storage),
        }
    }
    let uri = bootstrap::read_text(&input.source, bootstrap::MAX_URI, true)?;
    let invitation = Invitation::decode(&uri, now)?;
    if invitation.fingerprint() != input.identity { return Err(Error::Approval); }
    if invitation.has_token() == input.token.is_some() { return Err(Error::Credential); }
    if let Some(token) = &input.token {
        if !crate::config::valid_secret_ref(token) { return Err(Error::Credential); }
    }
    let admission = invitation.admission_preview(&input.admission)?;
    let approval = ImportApproval {
        document_sha256: bootstrap::digest(&uri), identity_sha256: input.identity
    };
    let body = format!("ПРЕДПРОСМОТР: fingerprint совпал с введённым значением.\n{}\nAdmission-файл проверен; секрет будет скопирован в защищённое хранилище.\nTransport/XHTTP: auto. CA не требуется.\nСохранение отдельного профиля не меняет active profile, proxy или runtime.\ny: сохранить; n/Esc: отменить.",
        invitation.preview(now)?);
    Ok(Review { approval, admission, body })
}

fn apply(input: &Input, review: Review, now: u64) -> Result<String, Error> {
    let uri = bootstrap::read_text(&input.source, bootstrap::MAX_URI, true)?;
    bootstrap::import(&uri, review.approval, &input.profile, &input.trust,
        EnrollmentMaterial { admission_path: &input.admission,
            expected_admission: Some(review.admission),
            external_token: input.token.as_ref().map(|value| value.as_str()) },
        bootstrap::auto_policy(), now)?;
    Ok("Профиль REALITY и доверие сохранены. Runtime НЕ изменён.\nEsc: закрыть.".into())
}

enum Stage {
    Input,
    Loading(Receiver<Result<Review, Error>>),
    Confirm(Review),
    Applying(Receiver<Result<String, Error>>),
    Done(String),
}

pub(crate) struct EnrollmentPanel {
    fields: [Zeroizing<String>; 6],
    focus: usize,
    stage: Stage,
    error: Option<String>,
    config:Option<(PathBuf,[u8;32])>,
    registration:Option<crate::tui_reality_register::RegistrationPanel>,
}

impl EnrollmentPanel {
    pub(crate) fn new() -> Self {
        Self { fields: std::array::from_fn(|_| Zeroizing::new(String::new())),
            focus: 0, stage: Stage::Input, error: None,config:None,registration:None }
    }

    pub(crate) fn bound(editor:&crate::tui_editor::Editor)->Result<Self,&'static str>{
        editor.require_clean_records()?;
        let mut panel=Self::new();
        panel.config=Some((std::path::absolute(editor.saved_path()).map_err(|_|"Недопустимый путь TOML")?,editor.saved_sha256()));
        Ok(panel)
    }

    fn input(&self) -> Result<Input, Error> {
        let path = |i: usize| PathBuf::from(self.fields[i].as_str());
        let identity = crate::parse_restart_digest(&self.fields[4]).ok_or(Error::Approval)?;
        let token = (!self.fields[5].is_empty()).then(|| self.fields[5].clone());
        Ok(Input { source: path(0), admission: path(1), profile: path(2), trust: path(3), identity, token })
    }

    pub(crate) fn paste(&mut self, value: &str) {
        if let Some(panel)=self.registration.as_mut(){panel.paste(value);return;}
        if !matches!(self.stage, Stage::Input) { return; }
        let value = value.trim_end_matches(['\r', '\n']);
        let field = &mut self.fields[self.focus];
        if !value.chars().any(char::is_control) && field.len().saturating_add(value.len()) <= LIMIT {
            field.push_str(value);
        }
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(panel)=self.registration.as_mut(){return panel.key(key);}
        match &self.stage {
            Stage::Loading(_) | Stage::Applying(_) => return false,
            Stage::Done(_) => {
                if key.code==KeyCode::Char('g'){
                    if let (Some((path,digest)),Ok(input))=(&self.config,self.input()){
                        match crate::tui_reality_register::RegistrationPanel::from_enrollment(path.clone(),*digest,&input.profile,input.identity){
                            Ok(panel)=>self.registration=Some(panel),
                            Err(error)=>self.error=Some(error.to_string()),
                        }
                    }
                }
                return key.code==KeyCode::Esc;
            }
            Stage::Confirm(_) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => self.stage = Stage::Input,
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let Ok(input) = self.input() else { self.stage = Stage::Input; return false; };
                        let Stage::Confirm(review) = std::mem::replace(&mut self.stage, Stage::Input) else { return false; };
                        let (tx, rx) = mpsc::channel();
                        self.stage = Stage::Applying(rx);
                        let _worker = std::thread::spawn(move || {
                            let result = reference_health::unix_now().map_err(|_| Error::Clock)
                                .and_then(|now| apply(&input, review, now));
                            let _ = tx.send(result);
                        });
                    }
                    _ => {}
                }
                return false;
            }
            Stage::Input => {}
        }
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Tab => self.focus = (self.focus + 1) % LABELS.len(),
            KeyCode::BackTab => self.focus = (self.focus + LABELS.len() - 1) % LABELS.len(),
            KeyCode::Backspace => { self.fields[self.focus].pop(); }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                self.fields[self.focus] = Zeroizing::new(String::new());
            }
            KeyCode::Enter => match self.input() {
                Ok(input) => {
                    let (tx, rx) = mpsc::channel();
                    self.error = None;
                    self.stage = Stage::Loading(rx);
                    let _worker = std::thread::spawn(move || {
                        let result = reference_health::unix_now().map_err(|_| Error::Clock)
                            .and_then(|now| inspect(&input, now));
                        let _ = tx.send(result);
                    });
                }
                Err(error) => self.error = Some(error.to_string()),
            },
            KeyCode::Char(ch) if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) && !ch.is_control() => {
                if self.fields[self.focus].len() + ch.len_utf8() <= LIMIT { self.fields[self.focus].push(ch); }
            }
            _ => {}
        }
        false
    }

    pub(crate) fn poll(&mut self)->Option<crate::tui_editor::Editor> {
        if let Some(panel)=self.registration.as_mut(){return panel.poll();}
        let result = match &self.stage {
            Stage::Loading(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::Applying(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Done),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Indeterminate),
            },
            _ => return None,
        };
        match result {
            Ok(stage) => self.stage = stage,
            Err(error) => {
                self.error = Some(format!("ОТКАЗ: {error}. При неопределённой записи проверьте файлы перед повтором."));
                self.stage = Stage::Input;
            }
        }
        None
    }

    pub(crate) fn body(&self) -> String {
        if let Some(panel)=&self.registration{return panel.body();}
        match &self.stage {
            Stage::Input => {
                let mut out = String::from("Локальные абсолютные пути; значения скрыты.\n");
                for (i, label) in LABELS.iter().enumerate() {
                    out.push_str(&format!("{} {label}: {} ({} bytes)\n",
                        if i == self.focus { ">" } else { " " },
                        if self.fields[i].is_empty() { "[пусто]" } else { "[скрыто]" }, self.fields[i].len()));
                }
                out.push_str("\nFingerprint введите из отдельного доверенного канала. Bearer: только env:/file: ссылка, не значение.\nEnter: предпросмотр; Tab: поле; Ctrl+U: очистить; Esc: отменить.\n");
                out.push_str(self.error.as_deref().unwrap_or(""));
                out
            }
            Stage::Loading(_) => "Проверка локального приглашения и admission; без сети и записи.".into(),
            Stage::Confirm(review) => review.body.clone(),
            Stage::Applying(_) => "Сохранение защищённого профиля; runtime не меняется.".into(),
            Stage::Done(body) => if self.config.is_some(){format!("{body}\nСледующий шаг: g — зарегистрировать созданный enrollment в сохранённом TOML (отдельный preview/confirm).\n{}",self.error.as_deref().unwrap_or(""))}else{body.clone()},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{descriptor::Scope, identity_tls::Identity, reality_admission::Secret, reference_health::{Evidence, Plan, State, Target}};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn preview_binds_independent_identity_and_admission_without_exposing_secret() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("theia-enroll-ui-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        let state = State::new(Plan { schema_version: 1, inbound: "edge".into(), endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }] },
            vec![Evidence { h2_status: Some(200), h3_status: None }], 1000).unwrap();
        let identity = Identity::generate(Scope { inbound: "edge".into(), endpoint: "edge.example.org:443".into() }).unwrap();
        let document = bootstrap::initial_descriptor(&state, &identity, 1000).unwrap();
        let invite = Invitation::public(&identity, &document, 1000).unwrap();
        let uri = invite.encode().unwrap();
        let mut input = Input { source: dir.join("invitation"), admission: dir.join("admission"),
            profile: dir.join("profile"), trust: dir.join("trust"),
            identity: [0;32], token: Some(Zeroizing::new("env:TEST_BEARER".into())) };
        bootstrap::create_text(&input.source, &uri).unwrap();
        Secret::generate().unwrap().save_new(identity.scope(), &input.admission).unwrap();
        assert!(matches!(inspect(&input, 1000), Err(Error::Approval)));
        input.identity = invite.fingerprint();
        let review = inspect(&input, 1000).unwrap();
        assert!(!review.body.contains(uri.as_str()));
        assert!(!review.body.contains("env:TEST_BEARER"));
        assert!(!input.profile.exists() && !input.trust.exists());
        std::fs::remove_file(&input.admission).unwrap();
        Secret::generate().unwrap().save_new(identity.scope(), &input.admission).unwrap();
        assert_eq!(apply(&input, review, 1000), Err(Error::Approval));
        assert!(!input.profile.exists() && !input.trust.exists());
        let review = inspect(&input, 1000).unwrap();
        assert!(apply(&input, review, 1000).unwrap().contains("Runtime НЕ изменён"));
        let profile = bootstrap::Profile::read(&input.profile).unwrap();
        assert!(profile.admission().is_ok());
        assert!(profile.load(1000).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn source_fields_are_masked_and_cancel_is_read_only() {
        let mut panel = EnrollmentPanel::new();
        panel.paste("SECRET-NEVER-DISPLAY");
        assert!(!panel.body().contains("SECRET-NEVER-DISPLAY"));
        assert!(panel.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    }
}
