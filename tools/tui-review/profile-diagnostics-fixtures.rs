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
            let blocked = name.ends_with("blocked");
            let partial = name.ends_with("partial");
            let failed = name.ends_with("failed");
            if phase == Phase::Custom {
                p.input = "example.test, second.test".into();
                if name.ends_with("validation-error") {
                    p.input.clear();
                    p.error = "Введите хотя бы один допустимый домен.".into();
                }
            }
            if matches!(phase, Phase::Confirm | Phase::Running | Phase::Done) && !failed {
                p.domains = vec!["example.test".into(), "second.test".into(), "third.test".into()];
                for carrier in ["H2", "H3"] {
                    p.checks.push(Check { domain: None, kind: CheckKind::Carrier(carrier), outcome: Outcome::Verified(8) });
                }
            }
            if matches!(phase, Phase::Running | Phase::Done) && !failed {
                let domains = p.domains.clone();
                for (index, domain) in domains.iter().enumerate() {
                    if (phase == Phase::Running && index > 0) || (partial && index == 2) {
                        continue;
                    }
                    if blocked && index == 2 {
                        p.checks.push(Check { domain: Some(domain.clone()), kind: CheckKind::Policy, outcome: Outcome::Route(crate::routing::Action::Blocked) });
                    } else if partial && index == 1 {
                        p.checks.push(Check { domain: Some(domain.clone()), kind: CheckKind::Https("H2"), outcome: Outcome::Failure(ClientError::Timeout) });
                        continue;
                    } else {
                        for mode in ["штатный", "H2", "H3"] {
                            p.checks.push(Check { domain: Some(domain.clone()), kind: CheckKind::Https(mode), outcome: Outcome::Http(200, ActualRoute::Direct, 10) });
                            p.checks.push(Check { domain: Some(domain.clone()), kind: CheckKind::Udp(mode), outcome: Outcome::Udp(200, ActualRoute::Direct, 12) });
                        }
                    }
                    p.finished.push(domain.clone());
                }
                if phase == Phase::Done {
                    p.completed = !partial;
                    if partial {
                        p.error = "Проверка прервана. Частичные результаты сохранены.".into();
                    }
                }
            }
            if name.ends_with("details") {
                p.details = true;
            }
            if failed {
                p.error = "Не удалось получить подтверждённый список доменов.".into();
            }
            states.push((name, p));
        }
        states
    }
}
