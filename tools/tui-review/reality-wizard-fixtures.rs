// Appended only to the temporary CI checkout of tui_reality_provision.rs.
// Real production stages and ranking; synthetic observations, no worker,
// DNS, TLS/QUIC connection, credential generation or real config write.
#[cfg(test)]
impl ProvisionPanel {
    pub(crate) fn review_wizard_stages(path: PathBuf) -> Vec<(&'static str, Self)> {
        let setup = || {
            let mut panel = Self::first(path.clone()).unwrap();
            let wizard = panel.wizard.as_mut().unwrap();
            wizard.fields[2] = "93.184.216.1".into();
            wizard.suggest_own_ip();
            wizard.fields[5] = "phone".into();
            wizard.sources = true;
            wizard.catalogue = false;
            wizard.custom_enabled = true;
            wizard.fields[4] = (1..=6).map(|i| format!("site{i}.example.org")).collect::<Vec<_>>().join(",");
            let input = WizardInput::parse(wizard.config.clone(), wizard.source, &wizard.effective_fields()).unwrap();
            (panel, input)
        };
        let targets: Vec<_> = (1..=6).map(|i| reference_health::Target {
            server_name: format!("site{i}.example.org"),
            address: format!("93.184.216.{}:443", i + 1).parse().unwrap(),
        }).collect();
        let now = reference_health::unix_now().unwrap();
        let mut screens = Vec::new();
        let (mut panel, input) = setup();
        panel.wizard.as_mut().unwrap().stage = WizardStage::ProbeConfirm(Box::new((input.clone(), ResolvedSearch {
            plan: Some(input.search_plan(targets.clone()).unwrap()),
            unresolved: Vec::new(),
        })));
        screens.push(("state-reality-step4-tls-consent", panel));
        for (name, completed) in [
            ("state-reality-step4-tls-progress", 3),
            ("state-reality-step4-tls-recheck", 6),
        ] {
            let (mut panel, _) = setup();
            let wizard = panel.wizard.as_mut().unwrap();
            let (_tx, rx) = mpsc::channel();
            let (cancel, _cancelled) = tokio::sync::oneshot::channel();
            wizard.total = targets.len();
            wizard.progress.store(completed, Ordering::Relaxed);
            wizard.stage = WizardStage::Checking(rx, cancel);
            screens.push((name, panel));
        }
        let good = vec![
            reference_health::Evidence { h2_status: Some(200), h3_status: Some(200) },
            reference_health::Evidence { h2_status: Some(200), h3_status: None },
            reference_health::Evidence { h2_status: Some(200), h3_status: Some(200) },
            reference_health::Evidence { h2_status: Some(200), h3_status: None },
            reference_health::Evidence { h2_status: None, h3_status: None },
            reference_health::Evidence { h2_status: None, h3_status: None },
        ];
        let (mut panel, input) = setup();
        let (state, review) = rank_checked(&input, targets.clone(), good, now, Vec::new()).unwrap();
        assert_eq!(review.rows.iter().filter(|r| r.selected.is_some()).count(), 3);
        assert_eq!(review.rows.iter().filter(|r| r.h2).count(), 4);
        panel.wizard.as_mut().unwrap().stage = WizardStage::CreateConfirm(Box::new((input, state.unwrap(), review)));
        screens.push(("state-reality-step5-ranked-review", panel));
        let (mut panel, input) = setup();
        let failed = targets.iter().map(|_| reference_health::Evidence { h2_status: None, h3_status: None }).collect();
        let (state, report) = rank_checked(&input, targets, failed, now, Vec::new()).unwrap();
        assert!(state.is_none());
        panel.wizard.as_mut().unwrap().stage = WizardStage::NoEligible(report);
        screens.push(("state-reality-step5-no-eligible", panel));
        let (mut panel, input) = setup();
        let (_tx, rx) = mpsc::channel();
        panel.wizard.as_mut().unwrap().stage = WizardStage::SavingInitial(rx, input.health.parent().unwrap().to_owned());
        screens.push(("state-reality-step6-saving", panel));
        // Feed real poll() error transitions; never dispatch a saving action.
        let (mut panel, input) = setup();
        let (tx, rx) = mpsc::channel();
        tx.send(Err(Error::Storage)).unwrap();
        panel.wizard.as_mut().unwrap().stage = WizardStage::SavingInitial(rx, input.health.parent().unwrap().to_owned());
        assert!(panel.poll().is_none());
        assert!(panel.body().contains("Не удалось сохранить первый TOML"));
        screens.push(("state-reality-step6-save-error", panel));
        let (mut panel, input) = setup();
        let (tx, rx) = mpsc::channel();
        drop(tx);
        panel.wizard.as_mut().unwrap().stage = WizardStage::SavingInitial(rx, input.health.parent().unwrap().to_owned());
        assert!(panel.poll().is_none());
        assert!(panel.body().contains("Запись не подтверждена"));
        screens.push(("state-reality-step6-save-uncertain", panel));
        assert!(!path.exists());
        screens
    }
}
