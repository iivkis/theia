// Offline, synthetic UI states; no network or Windows changes.
#[cfg(test)]
impl Panel {
    pub(crate) fn review_stages(path: PathBuf) -> Vec<(&'static str, Self)> {
        use crate::{client::ClientError, local_proxy::profile_diagnostics::ActualRoute};
        let mut states = Vec::new();
        for (name, phase) in [
            ("state-profile-diagnostics-choose", Phase::Choose),
            ("state-profile-diagnostics-custom", Phase::Custom),
            ("state-profile-diagnostics-validation-error", Phase::Custom),
            ("state-profile-diagnostics-fetching", Phase::Fetching),
            ("state-profile-diagnostics-consent", Phase::Confirm),
            ("state-profile-diagnostics-running", Phase::Running),
            ("state-profile-diagnostics-completed", Phase::Done),
            ("state-profile-diagnostics-partial", Phase::Done),
            ("state-profile-diagnostics-details", Phase::Done),
            ("state-profile-diagnostics-blocked", Phase::Done),
            ("state-profile-diagnostics-failed", Phase::Done),
        ] {
            let mut p = Self::new(path.clone(), [0; 32], "review-profile".into());
            p.phase = phase;
            if phase == Phase::Custom {
                p.input = "example.test, blocked.test".into();
                if name.ends_with("validation-error") {
                    p.input.clear();
                    p.error = "Введите хотя бы один допустимый домен.".into();
                }
            }
            if matches!(phase, Phase::Confirm | Phase::Running | Phase::Done) {
                p.domains = vec!["example.test".into(), "failed.test".into(), "blocked.test".into()];
                p.checks.push(Check { domain: None, kind: CheckKind::Carrier("H2"), outcome: Outcome::Verified(8) });
            }
            if matches!(phase, Phase::Running | Phase::Done) {
                p.checks.push(Check { domain: Some("example.test".into()), kind: CheckKind::Https("штатный"), outcome: Outcome::Http(200, ActualRoute::Direct, 10) });
                p.finished.push("example.test".into());
                p.checks.push(Check { domain: Some("blocked.test".into()), kind: CheckKind::Policy, outcome: Outcome::Route(crate::routing::Action::Blocked) });
                p.finished.push("blocked.test".into());
                if phase == Phase::Done {
                    p.checks.push(Check { domain: Some("failed.test".into()), kind: CheckKind::Https("H2"), outcome: Outcome::Failure(ClientError::Timeout) });
                    p.finished.push("failed.test".into());
                    p.completed = !name.ends_with("partial") && !name.ends_with("failed");
                    if !p.completed {
                        p.error = "Проверка прервана. Частичные результаты сохранены.".into();
                    }
                }
            }
            if name.ends_with("details") {
                p.details = true;
            }
            if name.ends_with("failed") {
                p.checks.clear();
                p.domains.clear();
                p.finished.clear();
                p.error = "Не удалось получить подтверждённый список доменов.".into();
            }
            states.push((name, p));
        }
        states
    }
}
