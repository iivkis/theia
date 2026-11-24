//! Read-only asynchronous view of a registered REALITY record. This screen
//! reports authenticated local evidence, not a running listener.
use crate::{reality_bootstrap::Error, reality_config, reference_health, tui_editor::Editor};
use crossterm::event::{KeyCode, KeyEvent};
use std::{path::PathBuf, sync::mpsc::{self, Receiver, TryRecvError}};

pub(crate) struct StatusPanel {
    path: PathBuf,
    digest: [u8;32],
    id: String,
    pending: Option<Receiver<Result<String, Error>>>,
    report: String,
}

impl StatusPanel {
    pub(crate) fn open(editor: &Editor) -> Self {
        let mut panel = Self {
            path: editor.saved_path().to_owned(), digest: editor.saved_sha256(),
            id: editor.selected_record_id().to_owned(), pending: None, report: String::new(),
        };
        panel.start();
        panel
    }

    fn start(&mut self) {
        if self.pending.is_some() { return; }
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = std::path::absolute(path).map_err(|_| Error::Storage)
                .and_then(|path| reference_health::unix_now().map_err(|_| Error::Clock)
                    .and_then(|now| reality_config::status_expected(&path, digest, &id, now)));
            let _ = tx.send(result);
        });
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Char('r') => { self.start(); false }
            _ => false,
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some(rx) = self.pending.as_ref() else { return; };
        let result = match rx.try_recv() {
            Ok(value) => value,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(Error::Storage),
        };
        self.pending = None;
        self.report = match result {
            Ok(report) => report,
            Err(error) => format!("Проверка отклонена: {error}\nПредыдущее состояние не используется. При изменении TOML заново откройте редактор."),
        };
    }

    pub(crate) fn body(&self) -> String {
        if self.pending.is_some() {
            return "Проверяются сохранённые материалы и доверие. Без сети и записи.\nEsc: закрыть.".into();
        }
        format!("{}\n\nr: перечитать; Esc: закрыть. Runtime не изменяется.", self.report)
    }
}
