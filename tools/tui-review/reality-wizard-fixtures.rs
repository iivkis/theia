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
        let (mut panel, input) = setup();
        panel.wizard.as_mut().unwrap().stage = WizardStage::ProbeConfirm(Box::new((input.clone(), ResolvedSearch {
            plan: Some(input.search_plan(targets.clone()).unwrap()), unresolved: Vec::new(),
        })));
        panel.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(panel.confirmation_choice().is_none());
        screens.push(("state-reality-step4-tls-expanded", panel));

        let (mut panel, _) = setup();
        let wizard = panel.wizard.as_mut().unwrap();
        let (_tx, rx) = mpsc::channel();
        let (cancel, _cancelled) = tokio::sync::oneshot::channel();
        wizard.total = 71;
        wizard.progress.store(28, Ordering::Relaxed);
        wizard.stage = WizardStage::Resolving(rx, cancel);
        screens.push(("state-reality-step3-dns-progress", panel));
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
            if completed == targets.len() {
                wizard.recheck_total.store(3, Ordering::Relaxed);
                wizard.recheck_done.store(1, Ordering::Relaxed);
            }
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
        let (state, review) = rank_checked(&input, targets.clone(), good.clone(), now, Vec::new()).unwrap();
        assert_eq!(review.rows.iter().filter(|r| r.selected.is_some()).count(), 3);
        assert_eq!(review.rows.iter().filter(|r| r.h2).count(), 4);
        panel.wizard.as_mut().unwrap().stage = WizardStage::CreateConfirm(Box::new((input, state.unwrap(), review)));
        screens.push(("state-reality-step5-ranked-review", panel));
        let (mut panel, input) = setup();
        let (state, review) = rank_checked(&input, targets.clone(), good, now, Vec::new()).unwrap();
        panel.wizard.as_mut().unwrap().stage = WizardStage::CreateConfirm(Box::new((input, state.unwrap(), review)));
        panel.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(panel.confirmation_choice().is_none());
        screens.push(("state-reality-step5-ranked-expanded", panel));

        let (mut panel, _) = setup();
        let wizard = panel.wizard.as_mut().unwrap();
        wizard.fields[4] = (1..=40).map(|i| format!("site{i}.example.org")).collect::<Vec<_>>().join(",");
        let input = WizardInput::parse(wizard.config.clone(), wizard.source, &wizard.effective_fields()).unwrap();
        let many: Vec<_> = (1..=40).map(|i| reference_health::Target {
            server_name: format!("site{i}.example.org"),
            address: format!("93.184.216.{}:443", i + 1).parse().unwrap(),
        }).collect();
        let observations = (1..=40).map(|i| reference_health::Evidence {
            h2_status: if i % 5 == 0 { None } else { Some(200) },
            h3_status: if i % 3 == 0 && i % 5 != 0 { Some(200) } else { None },
        }).collect();
        let (state, review) = rank_checked(&input, many, observations, now, Vec::new()).unwrap();
        assert_eq!(review.rows.len(), 40);
        wizard.stage = WizardStage::CreateConfirm(Box::new((input, state.unwrap(), review)));
        wizard.result_details = true;
        screens.push(("state-reality-step5-long-report", panel));
        let (mut panel, input) = setup();
        let failed = targets.iter().map(|_| reference_health::Evidence { h2_status: None, h3_status: None }).collect();
        let (state, report) = rank_checked(&input, targets.clone(), failed, now, Vec::new()).unwrap();
        assert!(state.is_none());
        panel.wizard.as_mut().unwrap().stage = WizardStage::NoEligible(report);
        screens.push(("state-reality-step5-no-eligible", panel));
        let (mut panel, input) = setup();
        let failed = targets.iter().map(|_| reference_health::Evidence { h2_status: None, h3_status: None }).collect();
        let (_, report) = rank_checked(&input, targets, failed, now, Vec::new()).unwrap();
        panel.wizard.as_mut().unwrap().stage = WizardStage::NoEligible(report);
        panel.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        screens.push(("state-reality-step5-no-eligible-expanded", panel));
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
        assert!(panel.body().contains("Не удалось сохранить настройки"));
        assert_eq!(panel.confirmation_choice(), Some(('y', "Повторить настройку")));
        screens.push(("state-reality-step6-save-error", panel));
        let (mut panel, input) = setup();
        let (tx, rx) = mpsc::channel();
        drop(tx);
        panel.wizard.as_mut().unwrap().stage = WizardStage::SavingInitial(rx, input.health.parent().unwrap().to_owned());
        assert!(panel.poll().is_none());
        assert!(panel.body().contains("Запись не подтверждена"));
        assert!(panel.confirmation_choice().is_none());
        screens.push(("state-reality-step6-save-uncertain", panel));

        let (mut panel, input) = setup();
        panel.wizard.as_mut().unwrap().stage = save_failed(input.health.parent().unwrap().to_owned(), None);
        panel.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(panel.confirmation_choice().is_none());
        screens.push(("state-reality-step6-save-inspection", panel));

        let (mut panel, _) = setup();
        panel.key(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE));
        assert!(panel.wizard.as_ref().unwrap().domain_draft.is_some());
        panel.paste("\nextra.example.org\nexample.net");
        screens.push(("state-reality-step2-domain-editor", panel));

        let (mut panel, _) = setup();
        let wizard = panel.wizard.as_mut().unwrap();
        wizard.catalogue = true;
        wizard.ranges_enabled = true;
        // Show the optional fields without validating or approving any range.
        wizard.fields[7] = "203.0.113.8/29".into();
        wizard.focus = 7;
        screens.push(("state-reality-step2-extra-sources", panel));
        assert!(!path.exists());
        screens
    }

    // Exercise the actual offline create/poll path in the isolated temporary
    // directory. Observations are synthetic; no site is contacted.
    pub(crate) fn review_saved_wizard(path: PathBuf) -> (Self, Editor) {
        let mut panel = Self::first(path.clone()).unwrap();
        let wizard = panel.wizard.as_mut().unwrap();
        wizard.fields[2] = "93.184.216.1".into();
        wizard.suggest_own_ip();
        wizard.fields[5] = "phone".into();
        wizard.sources = true;
        wizard.catalogue = false;
        wizard.custom_enabled = true;
        wizard.fields[4] = "reference.example.org".into();
        let input = WizardInput::parse(path, None, &wizard.effective_fields()).unwrap();
        let (state, report) = rank_checked(
            &input,
            vec![reference_health::Target { server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }],
            vec![reference_health::Evidence { h2_status: Some(200), h3_status: None }],
            reference_health::unix_now().unwrap(),
            Vec::new(),
        ).unwrap();
        wizard.stage = WizardStage::CreateConfirm(Box::new((input, state.unwrap(), report)));
        panel.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let editor = loop {
            if let Some(editor) = panel.poll() { break editor; }
            assert!(std::time::Instant::now() < deadline, "{}", panel.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(panel.succeeded() && editor.selected_reality());
        (panel, editor)
    }

    pub(crate) fn review_grant_picker(editor: &Editor) -> Self {
        let mut panel = Self::bound(editor).unwrap();
        let wizard = panel.wizard.as_mut().unwrap();
        wizard.focus = 5;
        wizard.open_grants();
        assert!(wizard.grant_picker.is_some());
        panel
    }
}
