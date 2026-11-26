//! Guarded server identity controls plus separate saved/runtime status.
use crate::{
    reality_bootstrap::Error,
    reality_config::{self, ExpiryReview, RotationReview, TrustReview},
    reference_health,
    tui_editor::Editor,
    Role,
};
use crossterm::event::{KeyCode, KeyEvent};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, TryRecvError},
};

enum Update {
    Report(String),
    Observation {
        brief: String,
        details: Option<String>,
    },
    Review(RotationReview),
    Trust(TrustReview),
    Expiry(ExpiryReview),
    HeadlessReview(u64),
    CredentialReview(PathBuf, [u8; 32], u64),
    CredentialSaved(Box<Editor>),
}
struct ClientRun {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: Receiver<Result<(), crate::client::ClientError>>,
    report: std::sync::Arc<std::sync::Mutex<String>>,
}
impl Drop for ClientRun {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
pub(crate) struct StatusPanel {
    path: PathBuf,
    digest: [u8; 32],
    id: String,
    server: bool,
    server_endpoint: Option<PathBuf>,
    reality: bool,
    pending: Option<Receiver<Result<Update, Error>>>,
    review: Option<RotationReview>,
    committing: bool,
    report: String,
    details: Option<String>,
    show_details: bool,
    client_active: bool,
    client_confirm: Option<bool>,
    client_run: Option<ClientRun>,
    trust_input: Option<(bool, String)>,
    trust_review: Option<TrustReview>,
    expiry_review: Option<ExpiryReview>,
    headless_review: Option<u64>,
    credential_input: Option<String>,
    credential_review: Option<(PathBuf, [u8; 32], u64)>,
    refreshed_editor: Option<Editor>,
    reopen_required: bool,
    action_focus: usize,
}
impl StatusPanel {
    pub(crate) fn open(editor: &Editor) -> Self {
        Self::open_with_endpoint(editor, None)
    }

    pub(crate) fn open_with_endpoint(editor: &Editor, server_endpoint: Option<PathBuf>) -> Self {
        let mut panel = Self {
            path: editor.saved_path().to_owned(),
            digest: editor.saved_sha256(),
            id: editor.selected_record_id().to_owned(),
            server: editor.role() == Role::Server,
            server_endpoint,
            reality: editor.selected_reality(),
            pending: None,
            review: None,
            committing: false,
            report: String::new(),
            details: None,
            show_details: false,
            client_active: editor.selected_record_is_active(),
            client_confirm: None,
            client_run: None,
            trust_input: None,
            trust_review: None,
            expiry_review: None,
            headless_review: None,
            credential_input: None,
            credential_review: None,
            refreshed_editor: None,
            reopen_required: false,
            action_focus: 0,
        };
        panel.start(None);
        panel
    }
    fn start(&mut self, rotation: Option<bool>) {
        if self.pending.is_some() {
            return;
        }
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let server = self.server;
        let server_endpoint = self.server_endpoint.clone();
        let reality = self.reality;
        let selected_active = self.client_active;
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = (|| {
                let path = std::path::absolute(path).map_err(|_| Error::Storage)?;
                let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                if let Some(retire) = rotation {
                    return RotationReview::prepare(&path, digest, &id, retire, now)
                        .map(Update::Review);
                }
                let mut details = None;
                let mut report = if reality {
                    if server {
                        let (brief, technical) =
                            reality_config::status_expected(&path, digest, &id, now)?;
                        details = Some(technical);
                        brief
                    } else {
                        reality_config::client_status_expected(&path, digest, &id, now)?
                    }
                } else {
                    let raw = crate::local_proxy::saved_client_bytes(&path, digest)
                        .map_err(|_| Error::Approval)?;
                    let crate::config::Config::Client(doc) = crate::config::parse(
                        std::str::from_utf8(&raw).map_err(|_| Error::Storage)?,
                    )
                    .map_err(|_| Error::Storage)?
                    else {
                        return Err(Error::Storage);
                    };
                    let p = doc
                        .client
                        .profiles
                        .iter()
                        .find(|p| p.id == id)
                        .ok_or(Error::Storage)?;
                    let transport = format!("{:?}", p.transport);
                    let mode = format!("{:?}", p.effective_xhttp_mode());
                    format!("Сервер: {}\nЗащита: собственный TLS\nПрофиль выбран для запуска: {}\nРежим передачи: {}\nРежим XHTTP: {}\nСертификат и ключ доступа проверяются при запуске.\nСвязь с сервером пока не проверена этим экраном.", p.server,
                        if doc.client.active_profile == id { "да" } else { "нет" },
                        if transport == "Auto" { "автоматически" } else { transport.as_str() },
                        if mode == "Auto" { "автоматически" } else { mode.as_str() })
                };
                if server {
                    use crate::management::StatusReply;
                    let command = reality_config::runtime_status_command(&path, digest, &id)?;
                    let response = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .and_then(|rt| {
                            match server_endpoint.as_deref() {
                                Some(endpoint) => rt.block_on(crate::tui_runtime::query_endpoint(
                                    endpoint, command,
                                )),
                                None => rt.block_on(crate::management::query_environment(command)),
                            }
                            .ok()
                        });
                    let (live, technical) = match response {
                        Some(StatusReply::RealityRunning{generation,revision,health_revision,active_reference,overlap}) => (
                            format!("Сервер: принимает подключения (версия {revision})."),
                            format!("generation={generation} revision={revision} health_revision={health_revision}\nreference_index={active_reference} overlap={overlap}")),
                        Some(StatusReply::RealitySuspended) => ("Сервер: новые подключения приостановлены; действующие туннели не отозваны.".into(), "Runtime: suspended".into()),
                        _ => ("Состояние работающего сервера не подтверждено. Это не означает, что он остановлен.".into(), "Runtime: нет подтверждённого IPC статуса этого bundle.".into()),
                    };
                    report.push_str("\n\n");
                    report.push_str(&live);
                    if let Some(detail) = details.as_mut() {
                        detail.push_str("\n\n");
                        detail.push_str(&technical);
                    }
                } else {
                    use crate::management::{StatusCommand, StatusReply};
                    let response = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .and_then(|rt| {
                            rt.block_on(crate::management::query_client_environment(
                                StatusCommand::ClientStatus,
                            ))
                            .ok()
                        });
                    let live=match response{
                        Some(StatusReply::ClientRunning{revision,config_sha256,descriptor_revision,transport,xhttp,fallback,..}) if config_sha256 == digest && selected_active =>
                            format!("Фоновый клиент: работает с этими настройками (версия {revision}).\nВерсия описания сервера: {descriptor_revision}\nПоследнее подтверждённое соединение: {}; XHTTP: {}\nВременный переход с H3: {}",
                                match transport{2=>"H2",3=>"H3",_=>"пока нет"}, crate::local_proxy::xhttp_observation(xhttp), if fallback {"да, H3 временно недоступен"} else {"нет"}),
                        Some(StatusReply::ClientRunning{revision,..})=>format!("Фоновый клиент: работает (версия {revision}), но использование выбранного профиля не подтверждено."),
                        _=>"Фоновый клиент: состояние не подтверждено. Это не означает, что он остановлен.".into(),
                    };
                    report.push_str("\n\n");
                    report.push_str(&live);
                }
                Ok(Update::Observation {
                    brief: report,
                    details,
                })
            })();
            let _ = tx.send(result);
        });
    }
    fn apply(&mut self, review: RotationReview) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.committing = true;
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path)
                .map_err(|_| Error::Storage)
                .and_then(|path| {
                    reference_health::unix_now()
                        .map_err(|_| Error::Clock)
                        .and_then(|now| review.apply(&path, digest, &id, now))
                })
                .map(Update::Report);
            let _ = tx.send(result);
        });
    }
    pub(crate) fn paste(&mut self, text: &str) {
        if let Some(field) = &mut self.credential_input {
            let text = text.trim_end_matches(['\r', '\n']);
            if !text.chars().any(char::is_control) && field.len() + text.len() <= 1024 {
                field.push_str(text);
            }
            return;
        }
        if let Some((_, field)) = &mut self.trust_input {
            let text = text.trim_end_matches(['\r', '\n']);
            if !text.chars().any(char::is_control) && field.len() + text.len() <= 1024 {
                field.push_str(text);
            }
        }
    }
    fn start_credential(&mut self, source: PathBuf, approval: Option<[u8; 32]>) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.committing = approval.is_some();
        let _worker = std::thread::spawn(move || {
            let result = (|| {
                let path = std::path::absolute(path).map_err(|_| Error::Storage)?;
                let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                if let Some(approval) = approval {
                    reality_config::save_credential_refresh(&path, &id, &source, approval, now)?;
                    let mut editor =
                        Editor::load(Role::Client, &path).map_err(|_| Error::Indeterminate)?;
                    for _ in 0..editor.record_count() {
                        if editor.selected_record_id() == id {
                            break;
                        }
                        editor.select_record(true);
                    }
                    if editor.selected_record_id() != id {
                        return Err(Error::Indeterminate);
                    }
                    Ok(Update::CredentialSaved(Box::new(editor)))
                } else {
                    let (approval, revision) =
                        reality_config::preview_credential_refresh_for_editor(
                            &path, digest, &id, &source, now,
                        )?;
                    Ok(Update::CredentialReview(source, approval, revision))
                }
            })();
            let _ = tx.send(result);
        });
    }

    pub(crate) fn take_refreshed_editor(&mut self) -> Option<Editor> {
        self.refreshed_editor.take()
    }

    fn start_trust(&mut self, promote: bool, source: PathBuf) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path)
                .map_err(|_| Error::Storage)
                .and_then(|path| {
                    reference_health::unix_now()
                        .map_err(|_| Error::Clock)
                        .and_then(|now| {
                            TrustReview::prepare(&path, digest, &id, &source, promote, now)
                        })
                })
                .map(Update::Trust);
            let _ = tx.send(result);
        });
    }
    fn apply_trust(&mut self, review: TrustReview) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.committing = true;
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path)
                .map_err(|_| Error::Storage)
                .and_then(|path| {
                    reference_health::unix_now()
                        .map_err(|_| Error::Clock)
                        .and_then(|now| review.apply(&path, digest, &id, now))
                })
                .map(Update::Report);
            let _ = tx.send(result);
        });
    }
    fn start_expiry(&mut self) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path)
                .map_err(|_| Error::Storage)
                .and_then(|path| {
                    reference_health::unix_now()
                        .map_err(|_| Error::Clock)
                        .and_then(|now| ExpiryReview::prepare(&path, digest, &id, now))
                })
                .map(Update::Expiry);
            let _ = tx.send(result);
        });
    }
    fn apply_expiry(&mut self, review: ExpiryReview) {
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.committing = true;
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path)
                .map_err(|_| Error::Storage)
                .and_then(|path| {
                    reference_health::unix_now()
                        .map_err(|_| Error::Clock)
                        .and_then(|now| review.apply(&path, digest, &id, now))
                })
                .map(Update::Report);
            let _ = tx.send(result);
        });
    }
    fn headless(&mut self, apply: Option<u64>) {
        let digest = self.digest;
        let path = self.path.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.committing = apply.is_some();
        let _worker = std::thread::spawn(move || {
            use crate::management::{self, StatusCommand, StatusReply};
            let result = (|| {
                crate::local_proxy::saved_client_bytes(&path, digest)
                    .map_err(|_| Error::Approval)?;
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Storage)?;
                rt.block_on(async{
                    if let Some(expected_revision)=apply{
                        return Ok(match management::query_client_environment(StatusCommand::ClientApply{expected_revision,candidate_sha256:digest}).await{
                            Ok(StatusReply::ClientApplied{revision})=>Update::Report(format!("Настройки фонового клиента применены (версия {revision}). Прежние туннели сохранены.")),
                            Err(management::ManagementError::CandidateRejected)=>Update::Report("Фоновый клиент отклонил настройки. Изменения не подтверждены.".into()),
                            _=>Update::Report("Применение настроек фонового клиента не подтверждено. Обновите состояние перед повтором.".into()),
                        });
                    }
                    let StatusReply::ClientRunning{revision,config_sha256,..}=management::query_client_environment(StatusCommand::ClientStatus).await.map_err(|_|Error::Storage)? else{return Err(Error::Storage);};
                    if config_sha256==digest{return Ok(Update::Report("Фоновый клиент уже использует сохранённые настройки.".into()));}
                    match management::query_client_environment(StatusCommand::ClientPreview{expected_revision:revision,candidate_sha256:digest}).await{
                        Ok(StatusReply::ClientReady{revision:ready}) if ready==revision=>Ok(Update::HeadlessReview(revision)),
                        _=>Err(Error::Approval),
                    }
                })
            })();
            let _ = tx.send(result);
        });
    }
    fn start_client(&mut self) {
        if !self.client_active || self.client_run.is_some() {
            return;
        }
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (stop, rx) = tokio::sync::oneshot::channel();
        let (tx, done) = mpsc::channel();
        let report = std::sync::Arc::new(std::sync::Mutex::new(
            "Проверяем доверие к серверу, ключ доступа и доступность двух локальных портов..."
                .into(),
        ));
        let monitor = report.clone();
        self.client_run = Some(ClientRun {
            stop: Some(stop),
            done,
            report,
        });
        let _worker = std::thread::spawn(move || {
            use crate::{client::ClientError, local_proxy::PreparedLocalProxy};
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| ClientError::Io)
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let mut rx = rx;
                        let prepared = tokio::select! {
                            result=PreparedLocalProxy::start_selected(&path,digest,&id)=>result?,
                            _=&mut rx=>return Ok(()),
                        };
                        prepared.serve_selected_observed(rx, monitor).await
                    })
                });
            let _ = tx.send(result);
        });
    }
    pub(crate) fn local_running(&self) -> bool {
        self.client_run.is_some()
    }
    pub(crate) fn client_confirmation(&self) -> Option<bool> {
        self.client_confirm
    }

    pub(crate) fn can_minimize(&self) -> bool {
        self.client_run.is_some() && self.client_confirm.is_none()
    }

    pub(crate) fn confirmation_choice(&self) -> Option<(char, &'static str)> {
        if self.reopen_required || self.pending.is_some() || self.committing {
            return None;
        }
        if self.credential_review.is_some() {
            return Some(('y', "Сохранить ключ"));
        }
        if self.headless_review.is_some() {
            return Some(('y', "Применить"));
        }
        if self.trust_review.is_some() {
            return Some(('y', "Подтвердить доверие"));
        }
        if let Some(start) = self.client_confirm {
            return Some((
                'y',
                if start {
                    "Запустить"
                } else {
                    "Остановить"
                },
            ));
        }
        if self.expiry_review.is_some() || self.review.is_some() {
            return Some(('y', "Подтвердить запись"));
        }
        None
    }

    pub(crate) fn actions(&self) -> Vec<crate::tui_widgets::ActionItem> {
        use crate::tui_widgets::ActionItem;
        if self.reopen_required
            || self.pending.is_some()
            || self.committing
            || self.review.is_some()
            || self.expiry_review.is_some()
            || self.client_confirm.is_some()
            || self.credential_input.is_some()
            || self.credential_review.is_some()
            || self.headless_review.is_some()
            || self.trust_input.is_some()
            || self.trust_review.is_some()
        {
            return Vec::new();
        }
        if self.show_details && self.details.is_some() {
            return vec![ActionItem {
                key: 'd',
                label: "К краткому состоянию",
            }];
        }
        if let Some(run) = &self.client_run {
            return if run.stop.is_some() {
                vec![ActionItem {
                    key: 'x',
                    label: "Остановить локальный прокси",
                }]
            } else {
                Vec::new()
            };
        }
        let mut items = Vec::new();
        if !self.server && self.client_active {
            items.push(ActionItem {
                key: 's',
                label: "Запустить локальный прокси",
            });
            items.push(ActionItem {
                key: 'h',
                label: "Применить настройки к фоновому клиенту",
            });
        }
        items.push(ActionItem {
            key: 'r',
            label: "Обновить состояние",
        });
        if self.server {
            items.extend([
                ActionItem {
                    key: 't',
                    label: "Начать замену ключей доверия",
                },
                ActionItem {
                    key: 'p',
                    label: "Отозвать старый ключ",
                },
                ActionItem {
                    key: 'e',
                    label: "Восстановить подписанное описание",
                },
            ]);
        } else if self.reality {
            items.extend([
                ActionItem {
                    key: 'o',
                    label: "Восстановить доверие",
                },
                ActionItem {
                    key: 'k',
                    label: "Плановая замена ключа доверия",
                },
                ActionItem {
                    key: 'c',
                    label: "Обновить ключ доступа",
                },
            ]);
        }
        if self.details.is_some() {
            items.push(ActionItem {
                key: 'd',
                label: "Технические подробности",
            });
        }
        items
    }
    pub(crate) fn action_focus(&self) -> usize {
        self.action_focus
    }
    pub(crate) fn select_action(&mut self, index: usize) {
        if index < self.actions().len() {
            self.action_focus = index;
        }
    }
    pub(crate) fn title(&self) -> &'static str {
        if self.server {
            "Состояние REALITY на сервере"
        } else if self.reality {
            "Подключение REALITY"
        } else {
            "Подключение клиента · собственный TLS"
        }
    }

    pub(crate) fn summary(&self) -> String {
        if self.show_details {
            if let Some(details) = &self.details {
                return details.clone();
            }
        }
        if let Some(run) = &self.client_run {
            let status = run
                .report
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| "Статус недоступен".into());
            return format!("{status}\n\nEsc: свернуть, подключение продолжит работу.");
        }
        let mut summary = self.report.clone();
        if !self.server && !self.client_active {
            summary.push_str("\n\nДля запуска сначала выберите активный профиль.");
        }
        summary.push_str("\n\nEsc: назад.");
        summary
    }

    pub(crate) fn key(&mut self, mut key: KeyEvent) -> bool {
        let items = self.actions();
        let Some(code) = crate::tui_widgets::action_key(&items, &mut self.action_focus, key.code)
        else {
            return false;
        };
        key.code = code;
        if self.show_details {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('d')) {
                self.show_details = false;
                self.action_focus = 0;
            }
            return false;
        }
        if key.code == KeyCode::Char('d') && items.iter().any(|item| item.key == 'd') {
            self.show_details = true;
            self.action_focus = 0;
            return false;
        }
        if self.reopen_required {
            return key.code == KeyCode::Esc;
        }
        if !self.server {
            if let Some((source, approval, revision)) = self.credential_review.take() {
                match key.code {
                    KeyCode::Char('y') => self.start_credential(source, Some(approval)),
                    KeyCode::Char('n') | KeyCode::Esc => {}
                    _ => self.credential_review = Some((source, approval, revision)),
                }
                return false;
            }
            if let Some(field) = self.credential_input.as_mut() {
                match key.code {
                    KeyCode::Esc => self.credential_input = None,
                    KeyCode::Enter => {
                        let source = PathBuf::from(field.as_str());
                        self.credential_input = None;
                        self.start_credential(source, None);
                    }
                    KeyCode::Backspace => {
                        field.pop();
                    }
                    KeyCode::Char(ch)
                        if !ch.is_control()
                            && field.len() + ch.len_utf8() <= 1024
                            && (key.modifiers.is_empty()
                                || key.modifiers == crossterm::event::KeyModifiers::SHIFT) =>
                    {
                        field.push(ch)
                    }
                    _ => {}
                }
                return false;
            }
            if let Some(revision) = self.headless_review {
                match key.code {
                    KeyCode::Char('y') => {
                        self.headless_review = None;
                        self.headless(Some(revision));
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.headless_review = None,
                    _ => {}
                }
                return false;
            }
            if self.trust_review.is_some() {
                match key.code {
                    KeyCode::Char('y') => {
                        if let Some(review) = self.trust_review.take() {
                            self.apply_trust(review);
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.trust_review = None,
                    _ => {}
                }
                return false;
            }
            if let Some((promote, field)) = self.trust_input.as_mut() {
                match key.code {
                    KeyCode::Esc => self.trust_input = None,
                    KeyCode::Enter => {
                        let promote = *promote;
                        let source = PathBuf::from(field.as_str());
                        self.trust_input = None;
                        self.start_trust(promote, source);
                    }
                    KeyCode::Backspace => {
                        field.pop();
                    }
                    KeyCode::Char(ch)
                        if !ch.is_control()
                            && field.len() + ch.len_utf8() <= 1024
                            && (key.modifiers.is_empty()
                                || key.modifiers == crossterm::event::KeyModifiers::SHIFT) =>
                    {
                        field.push(ch)
                    }
                    _ => {}
                }
                return false;
            }
            if let Some(start) = self.client_confirm {
                match key.code {
                    KeyCode::Char('y') => {
                        self.client_confirm = None;
                        if start {
                            self.start_client();
                        } else if let Some(run) = self.client_run.as_mut() {
                            if let Some(stop) = run.stop.take() {
                                let _ = stop.send(());
                            }
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.client_confirm = None,
                    _ => {}
                }
                return false;
            }
            if self.client_run.is_some() {
                if key.code == KeyCode::Char('x') {
                    self.client_confirm = Some(false);
                }
                return false;
            }
            if self.reality
                && self.pending.is_none()
                && !self.committing
                && key.code == KeyCode::Char('c')
            {
                self.credential_input = Some(String::new());
                return false;
            }
            if self.reality
                && self.pending.is_none()
                && !self.committing
                && matches!(key.code, KeyCode::Char('o' | 'k'))
            {
                self.trust_input = Some((key.code == KeyCode::Char('k'), String::new()));
                return false;
            }
            if self.pending.is_none() && self.client_active && key.code == KeyCode::Char('h') {
                self.headless(None);
                return false;
            }
            if self.pending.is_none() && self.client_active && key.code == KeyCode::Char('s') {
                self.client_confirm = Some(true);
                return false;
            }
        }
        if self.committing {
            return false;
        }
        if self.pending.is_some() {
            return key.code == KeyCode::Esc;
        }
        if self.expiry_review.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(review) = self.expiry_review.take() {
                        self.apply_expiry(review);
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => self.expiry_review = None,
                _ => {}
            }
            return false;
        }
        if self.review.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(review) = self.review.take() {
                        self.apply(review);
                    }
                    false
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.review = None;
                    false
                }
                _ => false,
            }
        } else {
            match key.code {
                KeyCode::Esc => true,
                KeyCode::Char('r') => {
                    self.start(None);
                    false
                }
                KeyCode::Char('e') if self.server => {
                    self.start_expiry();
                    false
                }
                KeyCode::Char('t') if self.server => {
                    self.start(Some(false));
                    false
                }
                KeyCode::Char('p') if self.server => {
                    self.start(Some(true));
                    false
                }
                _ => false,
            }
        }
    }
    pub(crate) fn poll(&mut self) {
        if let Some(run) = &self.client_run {
            let result = match run.done.try_recv() {
                Ok(result) => Some(result),
                Err(TryRecvError::Disconnected) => Some(Err(crate::client::ClientError::Io)),
                Err(TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.client_run = None;
                self.client_confirm = None;
                self.report=match result{Ok(())=>"Локальный прокси остановлен; системный прокси не изменён.".into(),Err(_)=>"Локальный прокси завершился с ошибкой; локальные порты закрыты. Проверьте сохранённый профиль.".into()};
            }
        }
        let Some(rx) = self.pending.as_ref() else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(value) => value,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(Error::Storage),
        };
        self.pending = None;
        self.committing = false;
        self.details = None;
        self.show_details = false;
        match result {
            Ok(Update::Report(report)) => self.report = report,
            Ok(Update::Observation { brief, details }) => {
                self.report = brief;
                self.details = details;
            }
            Ok(Update::Review(review)) => self.review = Some(review),
            Ok(Update::Trust(review)) => self.trust_review = Some(review),
            Ok(Update::Expiry(review)) => self.expiry_review = Some(review),
            Ok(Update::HeadlessReview(revision)) => self.headless_review = Some(revision),
            Ok(Update::CredentialReview(source, approval, revision)) => {
                self.credential_review = Some((source, approval, revision))
            }
            Ok(Update::CredentialSaved(editor)) => {
                self.digest = editor.saved_sha256();
                self.client_active = editor.selected_record_is_active();
                self.refreshed_editor = Some(*editor);
                self.report="Ключ доступа сохранён, доверие к серверу не изменено. Для новых соединений отдельно примените настройки или запустите прокси.".into();
            }
            Err(Error::Indeterminate) => {
                self.reopen_required = true;
                self.report="Запись могла состояться. Закройте экран и перечитайте конфигурацию с диска, не повторяйте операцию вслепую.".into();
            }
            Err(error) => {
                self.report = if self.server {
                    format!("Операция не подтверждена: {error}\nПри неопределённой записи сначала перечитайте сохранённый и runtime статус. Не повторяйте вслепую.")
                } else {
                    let reason = match error {
                    Error::Format | Error::Scope => "Неверный формат настроек или выбран не тот профиль.",
                    Error::Approval => "Настройки или подтверждение доверия не совпадают. Откройте настройки заново.",
                    Error::Identity | Error::Descriptor => "Не удалось подтвердить доверие к серверу. Обратитесь к администратору.",
                    Error::Health => "Данные для защищённого подключения устарели или недоступны.",
                    Error::Grant | Error::Credential => "Ключ доступа недействителен или доступ не разрешён. Запросите новый ключ.",
                    Error::Storage => "Не удалось прочитать настройки или получить состояние фонового клиента. Проверьте файл и права доступа.",
                    Error::Indeterminate => "Результат записи неизвестен. Проверьте настройки перед повтором.",
                    Error::Clock => "Проверьте дату и время устройства.",
                };
                    format!("Операция не подтверждена. {reason}")
                }
            }
        }
    }
    pub(crate) fn routing_observation(&self, digest: [u8; 32]) -> Option<String> {
        if self.digest != digest || !self.client_active {
            return None;
        }
        let run = self.client_run.as_ref()?;
        run.stop.as_ref()?;
        let report = run.report.lock().ok()?;
        let start = report.find("Правила маршрутизации:")?;
        Some(report[start..].to_owned())
    }

    pub(crate) fn body(&self) -> String {
        if self.show_details {
            if let Some(details) = &self.details {
                return format!("{details}\n\nEsc: к краткому состоянию");
            }
        }
        if self.reopen_required {
            return format!("{}\nEsc: закрыть", self.report);
        }
        if let Some(field) = &self.credential_input {
            return format!("Обновить ключ доступа, не меняя доверие к серверу.\nАбсолютный путь к приватному приглашению: [скрыто, {} байт]\nEnter: предпросмотр | Esc: отменить", field.len());
        }
        if let Some((_, _, revision)) = &self.credential_review {
            return format!("Обновление ключа доступа (версия описания {revision}).\nБудут созданы защищённые файлы. Доверие к серверу, работающий прокси и настройки системы не изменятся.\ny: сохранить | n/Esc: отменить");
        }
        if let Some(revision) = self.headless_review {
            return format!("Применение настроек фонового клиента (версия {revision}). Сохранённый файл проверен. Меняются только будущие соединения; системный прокси и локальные порты не меняются.\ny: применить | n/Esc: отменить");
        }
        if let Some((promote, field)) = &self.trust_input {
            return format!("{}\nАбсолютный путь к подписанному описанию сервера: [скрыто, {} байт]\nEnter: предпросмотр | Esc: отменить",
            if *promote{"Плановая замена ключа доверия"}else{"Восстановление доверия"},field.len());
        }
        if let Some(review) = &self.trust_review {
            return format!("{}\n\ny: подтвердить | n/Esc: отменить", review.report());
        }
        if let Some(start) = self.client_confirm {
            return if start {
                "Запустить локальный прокси для выбранного сервера?\nНастройки системы не изменятся. Настройте прокси в нужных приложениях.\ny: запустить | n/Esc: отменить".into()
            } else {
                "Остановить локальный прокси? Подключённые через него приложения потеряют соединение.\ny: остановить | n/Esc: отменить".into()
            };
        }
        if let Some(run) = &self.client_run {
            if run.stop.is_none() {
                return "Остановка локального прокси...".into();
            }
            let status = run
                .report
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| "Статус недоступен".into());
            return format!(
                "{status}\n\nx: остановить (подтверждение). Esc: свернуть экран, прокси продолжает работу; V: вернуться."
            );
        }
        if self.committing {
            return "Подтверждённая запись публикации выполняется. Не закрывайте экран.".into();
        }
        if self.pending.is_some() {
            return "Проверяем сохранённые настройки и состояние локального процесса. Изменения не применяются.\nEsc: закрыть.".into();
        }
        if let Some(review) = &self.expiry_review {
            return format!("{}\n\ny: подтвердить | n/Esc: отменить", review.report());
        }
        if let Some(review) = &self.review {
            return format!(
                "{}\n\ny: подтвердить запись | n/Esc: отменить",
                review.report()
            );
        }
        format!(
            "{}\n\nr: перечитать | {}Esc: закрыть",
            self.report,
            if self.server {
                "t: начать ротацию | p: отозвать старый ключ после overlap | e: восстановить истёкший descriptor | "
            } else if !self.reality {
                if self.client_active {
                    "s: запустить локальный прокси | h: применить настройки фонового клиента | "
                } else {
                    "для запуска выберите активный профиль | "
                }
            } else if self.client_active {
                "s: запустить локальный прокси | h: применить настройки фонового клиента | o: восстановить доверие | k: заменить ключ доверия | c: обновить ключ доступа | "
            } else {
                "o: восстановить доверие | k: заменить ключ доверия | c: обновить ключ доступа | для запуска выберите активный профиль | "
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn panel(active: bool) -> StatusPanel {
        StatusPanel {
            path: PathBuf::new(),
            digest: [1; 32],
            id: "test".into(),
            server: false,
            server_endpoint: None,
            reality: true,
            pending: None,
            review: None,
            committing: false,
            report: String::new(),
            details: None,
            show_details: false,
            client_active: active,
            client_confirm: None,
            client_run: None,
            trust_input: None,
            trust_review: None,
            expiry_review: None,
            headless_review: None,
            credential_input: None,
            credential_review: None,
            refreshed_editor: None,
            reopen_required: false,
            action_focus: 0,
        }
    }
    #[test]
    fn technical_status_is_opt_in_and_never_starts_a_worker() {
        let mut p = panel(true);
        p.server = true;
        p.report = "Краткое состояние".into();
        p.details = Some("identity_sha256=public-fingerprint".into());
        assert!(!p.summary().contains("identity_sha256"));
        assert!(p.actions().iter().any(|a| a.key == 'd'));
        assert!(!p.key(key(KeyCode::Char('d'))));
        assert!(p.summary().contains("identity_sha256"));
        assert!(!p.key(key(KeyCode::Esc)));
        assert!(!p.summary().contains("identity_sha256"));
        assert!(p.pending.is_none());
    }

    #[test]
    fn own_tls_status_only_offers_common_runtime_controls() {
        let mut p = panel(true);
        p.reality = false;
        assert!(!p.body().contains("promotion"));
        assert!(p.body().contains("применить настройки фонового клиента"));
        for ch in ['c', 'o', 'k'] {
            assert!(!p.key(key(KeyCode::Char(ch))));
            assert!(p.credential_input.is_none());
            assert!(p.trust_input.is_none());
            assert!(p.pending.is_none());
        }
        assert!(!p.key(key(KeyCode::Char('s'))));
        assert_eq!(p.client_confirm, Some(true));
        assert!(!p.key(key(KeyCode::Char('n'))));
        assert!(p.client_run.is_none());
        assert!(p.client_confirm.is_none());
    }

    #[test]
    fn credential_input_is_hidden_and_cancel_does_not_start_a_worker() {
        let mut p = panel(true);
        assert!(!p.key(key(KeyCode::Char('c'))));
        p.paste("private-invitation");
        assert!(!p.body().contains("private-invitation"));
        assert!(p.pending.is_none());
        assert!(!p.key(key(KeyCode::Esc)));
        assert!(p.credential_input.is_none());
        assert!(p.pending.is_none());
        assert!(p.credential_review.is_none());
    }

    #[test]
    fn runtime_and_trust_inputs_never_implicitly_apply() {
        let mut p = panel(true);
        assert!(!p.key(key(KeyCode::Char('s'))));
        assert_eq!(p.client_confirm, Some(true));
        assert!(p.client_run.is_none());
        assert!(!p.key(key(KeyCode::Char('n'))));
        assert!(p.client_confirm.is_none());
        assert!(!p.key(key(KeyCode::Char('o'))));
        p.paste("/secret/location");
        assert!(!p.body().contains("/secret/location"));
        assert!(!p.key(key(KeyCode::Esc)));
        assert!(p.trust_input.is_none());
        let mut inactive = panel(false);
        inactive.key(key(KeyCode::Char('s')));
        assert!(inactive.client_confirm.is_none() && inactive.client_run.is_none());
    }

    fn finish(p: &mut StatusPanel) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while p.pending.is_some() {
            p.poll();
            assert!(
                std::time::Instant::now() < deadline,
                "local status worker deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    #[test]
    fn offline_status_workers_fail_closed_and_never_publish_on_missing_config() {
        let mut p = panel(true);
        let nonexistent =
            std::env::temp_dir().join(format!("theia-missing-status-{}", std::process::id()));
        assert!(!nonexistent.exists());
        p.path = nonexistent.clone();
        p.key(key(KeyCode::Char('r')));
        assert!(p.pending.is_some());
        assert!(p.body().contains("Изменения не применяются"));
        p.start(None);
        assert!(!p.key(key(KeyCode::Char('s'))));
        assert!(p.client_confirm.is_none());
        finish(&mut p);
        assert!(p.body().contains("Операция не подтверждена"));
        p.key(key(KeyCode::Char('h')));
        finish(&mut p);
        assert!(p.body().contains("Операция не подтверждена"));
        for action in ['o', 'k'] {
            p.key(key(KeyCode::Char(action)));
            assert!(p.trust_input.is_some());
            p.paste("private");
            p.key(key(KeyCode::Backspace));
            p.key(key(KeyCode::Char('x')));
            p.paste("\x01");
            p.paste(&"a".repeat(1025));
            assert_eq!(p.trust_input.as_ref().unwrap().1, "privatx");
            assert!(!p.body().contains("privatx"));
            p.key(key(KeyCode::Enter));
            finish(&mut p);
            assert!(p.body().contains("Операция не подтверждена"));
        }
        p.server = true;
        for action in ['t', 'p', 'e', 'r'] {
            p.key(key(KeyCode::Char(action)));
            finish(&mut p);
            assert!(p.body().contains("Операция не подтверждена"));
        }
        assert!(!nonexistent.exists());
    }

    #[test]
    fn runtime_stop_confirmation_and_disconnected_worker_are_observable() {
        let mut p = panel(true);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (tx, done) = mpsc::channel();
        p.client_run = Some(ClientRun {
            stop: Some(stop),
            done,
            report: std::sync::Arc::new(std::sync::Mutex::new("active-local".into())),
        });
        assert!(p.body().contains("active-local"));
        assert!(!p.key(key(KeyCode::Esc)));
        p.key(key(KeyCode::Char('x')));
        assert!(p.body().contains("приложения потеряют соединение"));
        p.key(key(KeyCode::Char('n')));
        assert!(matches!(
            stopped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        p.key(key(KeyCode::Char('x')));
        p.key(key(KeyCode::Char('y')));
        assert_eq!(stopped.try_recv(), Ok(()));
        assert!(p.body().contains("Остановка"));
        tx.send(Ok(())).unwrap();
        p.poll();
        assert!(p.client_run.is_none());
        assert!(p.body().contains("прокси остановлен"));
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (tx, done) = mpsc::channel();
        p.client_run = Some(ClientRun {
            stop: Some(stop),
            done,
            report: Default::default(),
        });
        drop(tx);
        p.poll();
        assert_eq!(stopped.try_recv(), Ok(()));
        assert!(p.body().contains("ошибкой"));
        let (tx, rx) = mpsc::channel();
        p.pending = Some(rx);
        p.committing = true;
        assert!(p.body().contains("Подтверждённая запись"));
        assert!(!p.key(key(KeyCode::Esc)));
        p.poll();
        assert!(p.committing);
        drop(tx);
        p.poll();
        assert!(!p.committing);
        assert!(p.body().contains("Операция не подтверждена"));
        p.headless_review = Some(7);
        assert!(p.body().contains("версия 7"));
        p.key(key(KeyCode::Esc));
        assert!(p.headless_review.is_none());
    }

    #[test]
    fn client_start_with_missing_saved_profile_reports_failure_without_runtime() {
        let mut p = panel(true);
        p.path = std::env::temp_dir().join(format!("theia-missing-start-{}", std::process::id()));
        assert!(!p.path.exists());
        p.key(key(KeyCode::Char('s')));
        assert!(p.body().contains("Настройки системы не изменятся"));
        p.key(key(KeyCode::Char('y')));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while p.client_run.is_some() {
            p.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(p.body().contains("ошибкой"));
        assert!(!p.path.exists());
    }
}
