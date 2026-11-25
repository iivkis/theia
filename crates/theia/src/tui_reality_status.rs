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
    pending: Option<Receiver<Result<Update, Error>>>,
    review: Option<RotationReview>,
    committing: bool,
    report: String,
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
}
impl StatusPanel {
    pub(crate) fn open(editor: &Editor) -> Self {
        let mut panel = Self {
            path: editor.saved_path().to_owned(),
            digest: editor.saved_sha256(),
            id: editor.selected_record_id().to_owned(),
            server: editor.role() == Role::Server,
            pending: None,
            review: None,
            committing: false,
            report: String::new(),
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
                let mut report = reality_config::status_expected(&path, digest, &id, now)?;
                if server {
                    use crate::management::StatusReply;
                    let command = reality_config::runtime_status_command(&path, digest, &id)?;
                    let response = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .and_then(|rt| {
                            rt.block_on(crate::management::query_environment(command))
                                .ok()
                        });
                    let live=match response{
                        Some(StatusReply::RealityRunning{generation,revision,health_revision,active_reference,overlap})=>
                            format!("Runtime: принимает подключения\ngeneration={generation} revision={revision} health_revision={health_revision}\nreference_index={active_reference} overlap={overlap}"),
                        Some(StatusReply::RealitySuspended)=>"Runtime: новые подключения приостановлены; действующие туннели не отозваны.".into(),
                        _=>"Runtime: нет подтверждённого IPC статуса этого bundle.".into(),
                    };
                    report.push_str("\n\n");
                    report.push_str(&live);
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
                        Some(StatusReply::ClientRunning{revision,config_sha256,descriptor_revision,transport,fallback})=>
                            format!("Headless runtime: revision={revision}; saved TOML совпадает={}\ndescriptor_revision={descriptor_revision}; last_open={}; H3 fallback={fallback}",
                                config_sha256==digest,match transport{2=>"H2",3=>"H3",_=>"не подтверждён"}),
                        _=>"Headless runtime: защищённый IPC не подтверждён.".into(),
                    };
                    report.push_str("\n\n");
                    report.push_str(&live);
                }
                Ok(Update::Report(report))
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
                            Ok(StatusReply::ClientApplied{revision})=>Update::Report(format!("Headless Apply подтверждён: revision={revision}. Прежние туннели сохранены.")),
                            Err(management::ManagementError::CandidateRejected)=>Update::Report("Headless Apply отклонён. Ничего не подтверждено.".into()),
                            _=>Update::Report("Headless Apply: результат не подтверждён. Перечитайте IPC status; не повторяйте вслепую.".into()),
                        });
                    }
                    let StatusReply::ClientRunning{revision,config_sha256,..}=management::query_client_environment(StatusCommand::ClientStatus).await.map_err(|_|Error::Storage)? else{return Err(Error::Storage);};
                    if config_sha256==digest{return Ok(Update::Report("Headless runtime уже использует этот TOML.".into()));}
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
            "Проверка trust, credentials и двух loopback bind...".into(),
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
                            result=PreparedLocalProxy::start_reality(&path,digest,&id)=>result?,
                            _=&mut rx=>return Ok(()),
                        };
                        prepared.serve_reality_observed(rx, monitor).await
                    })
                });
            let _ = tx.send(result);
        });
    }
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
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
            if self.pending.is_none() && !self.committing && key.code == KeyCode::Char('c') {
                self.credential_input = Some(String::new());
                return false;
            }
            if self.pending.is_none()
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
                self.report=match result{Ok(())=>"Локальный runtime остановлен; OS proxy не изменён.".into(),Err(_)=>"Локальный runtime завершился с ошибкой; слушатели закрыты. Проверьте сохранённый профиль.".into()};
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
        match result{
            Ok(Update::Report(report))=>self.report=report,
            Ok(Update::Review(review))=>self.review=Some(review),
            Ok(Update::Trust(review))=>self.trust_review=Some(review),
            Ok(Update::Expiry(review))=>self.expiry_review=Some(review),
            Ok(Update::HeadlessReview(revision))=>self.headless_review=Some(revision),
            Ok(Update::CredentialReview(source, approval, revision))=>self.credential_review=Some((source, approval, revision)),
            Ok(Update::CredentialSaved(editor))=>{
                self.digest=editor.saved_sha256();
                self.client_active=editor.selected_record_is_active();
                self.refreshed_editor=Some(*editor);
                self.report="Credential сохранён, trust не изменён. Для новых соединений требуется отдельный Apply или запуск.".into();
            }
            Err(Error::Indeterminate)=>{
                self.reopen_required=true;
                self.report="Запись могла состояться. Закройте экран и перечитайте конфигурацию с диска, не повторяйте операцию вслепую.".into();
            }
            Err(error)=>self.report=format!("Операция не подтверждена: {error}\nПри неопределённой записи сначала перечитайте сохранённый и runtime статус. Не повторяйте вслепую."),
        }
    }
    pub(crate) fn body(&self) -> String {
        if self.reopen_required {
            return format!("{}\nEsc: закрыть", self.report);
        }
        if let Some(field) = &self.credential_input {
            return format!("Обновить credential, не меняя trust.\nАбсолютный путь к приватному приглашению: [скрыто, {} bytes]\nEnter: предпросмотр | Esc: отменить", field.len());
        }
        if let Some((_, _, revision)) = &self.credential_review {
            return format!("Credential-only refresh: revision={revision}.\nБудут созданы новые приватные файлы; trust, runtime и OS proxy не изменяются.\ny: сохранить | n/Esc: отменить");
        }
        if let Some(revision) = self.headless_review {
            return format!("Headless Apply: revision={revision}; точный сохранённый TOML проверен. Меняются только будущие локальные соединения, OS proxy и listeners сохраняются.\ny: применить | n/Esc: отменить");
        }
        if let Some((promote, field)) = &self.trust_input {
            return format!("{}\nАбсолютный путь к подписанному descriptor: [скрыто, {} bytes]\nEnter: предпросмотр | Esc: отменить",
            if *promote{"Плановый переход identity"}else{"Offline recovery"},field.len());
        }
        if let Some(review) = &self.trust_review {
            return format!("{}\n\ny: подтвердить | n/Esc: отменить", review.report());
        }
        if let Some(start) = self.client_confirm {
            return if start {
                "Запустить сохранённый активный REALITY-профиль с двумя loopback listeners? OS proxy не изменяется.\ny: подтвердить | n/Esc: отменить".into()
            } else {
                "Остановить локальный runtime? Открытые туннели будут закрыты.\ny: подтвердить | n/Esc: отменить".into()
            };
        }
        if let Some(run) = &self.client_run {
            if run.stop.is_none() {
                return "Остановка локального runtime...".into();
            }
            let status = run
                .report
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| "Статус недоступен".into());
            return format!(
                "{status}\n\nx: остановить (подтверждение). Esc не закрывает работающий runtime."
            );
        }
        if self.committing {
            return "Подтверждённая запись публикации выполняется. Не закрывайте экран.".into();
        }
        if self.pending.is_some() {
            return "Проверка сохранённых материалов/локального IPC. Ничего не применяется.\nEsc: закрыть.".into();
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
            } else if self.client_active {
                "s: запустить локальный runtime | h: headless Apply | o: recovery | k: promotion | c: сменить credential | "
            } else {
                "o: recovery | k: promotion | c: сменить credential | для запуска выберите активный профиль | "
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
            pending: None,
            review: None,
            committing: false,
            report: String::new(),
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
        }
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
        assert!(p.body().contains("Ничего не применяется"));
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
        assert!(p.body().contains("Открытые туннели"));
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
        assert!(p.body().contains("runtime остановлен"));
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
        assert!(p.body().contains("revision=7"));
        p.key(key(KeyCode::Esc));
        assert!(p.headless_review.is_none());
    }

    #[test]
    fn client_start_with_missing_saved_profile_reports_failure_without_runtime() {
        let mut p = panel(true);
        p.path = std::env::temp_dir().join(format!("theia-missing-start-{}", std::process::id()));
        assert!(!p.path.exists());
        p.key(key(KeyCode::Char('s')));
        assert!(p.body().contains("OS proxy не изменяется"));
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
