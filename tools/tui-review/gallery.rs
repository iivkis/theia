// Included inside tui::tests only by the dedicated Linux visual-review workflow.
fn review_capture(name: &str, model: &Model, ui: &Interaction) {
    ui.viewport.reset();
    review_capture_current(name, model, ui);
}

fn review_capture_current(name: &str, model: &Model, ui: &Interaction) {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var_os("THEIA_REVIEW_CELLS").unwrap());
    let (width, height) = (120u16, 40u16);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| draw(f, model, Some(ui))).unwrap();
    let mut out = std::io::BufWriter::new(std::fs::File::create(root.join(format!("{name}.cells"))).unwrap());
    writeln!(out, "{width}\t{height}").unwrap();
    for cell in terminal.backend().buffer().content() {
        write!(out, "{:?}\t{:?}\t{:?}\t", cell.fg, cell.bg, cell.modifier).unwrap();
        for byte in cell.symbol().as_bytes() {
            write!(out, "{byte:02x}").unwrap();
        }
        writeln!(out).unwrap();
    }
    out.flush().unwrap();
}

#[test]
fn visual_review_gallery() {
    let root = std::path::PathBuf::from(std::env::var_os("THEIA_REVIEW_FIXTURES").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let server = root.join("server.toml");
    let client = root.join("client.toml");
    std::fs::write(&server, server_issuance_fixture()).unwrap();
    std::fs::write(&client, include_str!("../../../examples/client.toml")).unwrap();
    // Capture otherwise nondeterministic asynchronous wizard stages using
    // the real renderer and offline test-only state fixtures.
    {
        let path = root.join("wizard-review-only.toml");
        let mut model = Model::new(Some(Role::Server));
        for (name, panel) in ProvisionPanel::review_wizard_stages(path.clone()) {
            let mut ui = Interaction::new(None);
            ui.reality_provision = Some(panel);
            review_capture(name, &model, &ui);
            if name == "state-reality-step5-ranked-review" {
                let screen = rendered_interaction(120, 40, &model, &ui);
                assert!(screen.contains("Основной") && screen.contains("Резерв"));
                assert!(screen.contains("F2") && !screen.contains("Конфигурация к сохранению"));
            }
            if name == "state-reality-step5-ranked-expanded" {
                let screen = rendered_interaction(120, 40, &model, &ui);
                assert!(screen.contains("Конфигурация к сохранению"));
            }
            if name == "state-reality-step5-long-report" {
                assert!(ui.viewport.max.get() > 0);
                let last = ui.reality_provision.as_ref().unwrap().reference_review().unwrap().rows.last().unwrap().name.clone();
                for _ in 0..10 {
                    if ui.viewport.offset.get() == ui.viewport.max.get() { break; }
                    ui.update(&mut model, press(KeyCode::PageDown));
                    let _ = rendered_interaction(120, 40, &model, &ui);
                }
                assert_eq!(ui.viewport.offset.get(), ui.viewport.max.get());
                let screen = rendered_interaction(120, 40, &model, &ui);
                assert!(screen.contains("TLS / H2 / H3") && screen.contains(&last));
                review_capture_current("state-reality-step5-long-report-scrolled", &model, &ui);
            }
            assert!(!path.exists());
        }
        let editor = Editor::load(Role::Server, &server).unwrap();
        let panel = ProvisionPanel::review_grant_picker(&editor);
        let mut ui = Interaction::new(Some(editor));
        ui.reality_provision = Some(panel);
        review_capture("state-reality-step1-grant-picker", &model, &ui);

        let saved = root.join("wizard-saved-fixture.toml");
        let (panel, editor) = ProvisionPanel::review_saved_wizard(saved.clone());
        let before = std::fs::read(&saved).unwrap();
        let mut ui = Interaction::new(Some(editor));
        ui.reality_provision = Some(panel);
        review_capture("state-reality-step6-success", &model, &ui);
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Подключение REALITY создано") && screen.contains("Выпустить ключ доступа"));
        ui.update(&mut model, press(KeyCode::Right));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(&ui.issuance, Some(IssueFlow::Confirm(id)) if id == "phone"));
        assert_eq!(ui.issue_kind, IssueKind::FirstKey);
        assert!(!ui.editor.as_ref().unwrap().dirty() && !ui.server_process.running());
        assert_eq!(std::fs::read(&saved).unwrap(), before);
        review_capture("state-reality-step6-key-handoff", &model, &ui);
    }
    // Real first-run import through the production state machine, using a synthetic invitation.
    first_key_import_fixture(&root.join("first-own-tls"), review_capture);
    // Exercise a self-contained REALITY key through the actual first-run UI.
    {
        use crate::config;
        use sha2::{Digest, Sha256};
        use crate::reference_health::{Evidence, Plan, State, Target};
        let now = crate::reference_health::unix_now().unwrap();
        let scope = crate::descriptor::Scope {
            inbound: "edge".into(), endpoint: "edge.example.org:443".into(),
        };
        let state = State::new(Plan {
            schema_version: 1, inbound: scope.inbound.clone(), endpoint: scope.endpoint.clone(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }],
        }, vec![Evidence { h2_status: Some(200), h3_status: Some(200) }], now).unwrap();
        let identity = crate::identity_tls::Identity::generate(scope).unwrap();
        let signed = crate::reality_bootstrap::initial_descriptor(&state, &identity, now).unwrap();
        let bearer = [42u8; 32];
        let server_source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &format!("{:x}", Sha256::digest(bearer)))
            .replace("id = \"public\"", "id = \"edge\"");
        let config::Config::Server(server_doc) = config::parse(&server_source).unwrap() else { panic!("server fixture") };
        let admission = crate::reality_admission::Secret::generate().unwrap();
        let uri = crate::reality_bootstrap::Invitation::issued(&identity, &signed, &server_doc, "device-a", &bearer, &admission, now).unwrap().encode().unwrap();
        let path = root.join("first-reality.toml");
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        let mut dialog = ConfigDialog::new(Role::Client, Some(&path));
        dialog.begin_client_import();
        ui.config_dialog = Some(dialog);
        ui.paste_record_field(&uri);
        review_capture("client-reality-key-masked", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ui.config_dialog.as_ref().is_some_and(|d| d.title() == "Импорт REALITY" && d.guide().is_some_and(|g| g.2 == "Подтверждение доверия")) {
            ui.poll_navigation(&mut model);
            assert!(std::time::Instant::now() < deadline, "REALITY key review did not appear");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!path.exists());
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(!screen.contains(uri.as_str()));
        assert!(!screen.contains("Файл допуска (admission)"));
        assert!(screen.contains("› Отменить"));
        review_capture("client-reality-key-trust-review", &model, &ui);
        ui.update(&mut model, press(KeyCode::Right));
        assert!(ui.confirm_selected);
        assert!(!path.exists());
        review_capture("client-reality-key-trust-selected", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ui.config_dialog.is_some() {
            ui.poll_navigation(&mut model);
            assert!(std::time::Instant::now() < deadline, "REALITY profile was not saved");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(matches!(ui.importing, Some(ImportFlow::Done)));
        let config::Config::Client(doc) = config::read_file(&path).unwrap() else { panic!("client fixture") };
        assert_eq!(doc.client.profiles.len(), 1);
        assert_eq!(doc.client.active_profile, doc.client.profiles[0].id);
        assert_eq!(doc.client.ingress_mode, config::IngressMode::SystemProxy);
        // Saved mode is configuration, not OS proxy activation.
        assert!(!ui.owned_running(Role::Client));
        review_capture("client-reality-key-saved", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_page, 3);
        assert!(!ui.owned_running(Role::Client));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Активный профиль: №1 · edge.example.org:443"));
        assert!(!screen.contains("Выбран:"));
        assert!(!screen.contains(&doc.client.profiles[0].id));
        review_capture("client-reality-key-connect", &model, &ui);
        ui.update(&mut model, press(KeyCode::Char('V')));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let status = ui.reality_status.as_mut().unwrap();
            status.poll();
            if status.actions().iter().any(|a| a.key == 's') { break; }
            assert!(std::time::Instant::now() < deadline, "REALITY status did not finish");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Сервер: edge.example.org:443"));
        assert!(screen.contains("Описание сервера: версия"));
        assert!(screen.contains("Фоновый клиент:"));
        for term in ["Endpoint=", "Headless runtime", "IPC", "credential", "identity_sha256"] {
            assert!(!screen.contains(term), "{term}");
        }
        review_capture("client-reality-local-proxy-before-start", &model, &ui);
        ui.update(&mut model, press(KeyCode::Char('s')));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Запуск локального прокси"));
        assert!(!screen.contains("ШАГ 1/1"));
        assert!(screen.contains("Следующее действие"));
        assert!(!ui.owned_running(Role::Client));
        assert!(screen.contains("› Отменить"));
        let rect = ui.viewport.confirm_rect.get().unwrap();
        assert!(rect.y < 18);
        review_capture("client-reality-local-proxy-start-confirm", &model, &ui);
        ui.update(&mut model, press(KeyCode::Right));
        assert!(!ui.owned_running(Role::Client));
        review_capture("client-reality-local-proxy-start-selected", &model, &ui);
        ui.update(&mut model, press(KeyCode::Left));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(!ui.owned_running(Role::Client));
    }
    let mut modes = Interaction::new(Some(Editor::load(Role::Client, &client).unwrap()));
    let mut client_model = Model::new(Some(Role::Client));
    modes.update(&mut client_model, press(KeyCode::Char('P')));
    assert_eq!(modes.workspace_page, 3);
    assert!(!modes.owned_running(Role::Client));
    review_capture("client-connection-modes", &client_model, &modes);
    modes.update(&mut client_model, press(KeyCode::Char('V')));
    assert!(modes.reality_status.is_some());
    assert!(!modes.owned_running(Role::Client));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let status = modes.reality_status.as_mut().unwrap();
        status.poll();
        if status.actions().iter().any(|a| a.key == 's') { break; }
        assert!(std::time::Instant::now() < deadline, "local proxy start action did not appear");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    review_capture("client-local-proxy-before-start", &client_model, &modes);
    modes.update(&mut client_model, press(KeyCode::Char('s')));
    assert!(!modes.owned_running(Role::Client));
    let screen = rendered_interaction(120, 40, &client_model, &modes);
    assert!(!screen.contains("ШАГ 1/1"));
    assert!(screen.contains("Следующее действие"));
    assert!(screen.contains("› Отменить"));
    assert!(modes.viewport.confirm_rect.get().unwrap().y < 18);
    review_capture("client-local-proxy-start-confirm", &client_model, &modes);
    modes.update(&mut client_model, press(KeyCode::Enter));
    assert!(!modes.owned_running(Role::Client));
    {
        use crate::config::{self, Config};
        let path = root.join("multiple-profiles.toml");
        let Config::Client(mut doc) = config::parse(include_str!("../../../examples/client.toml")).unwrap() else { panic!("client fixture") };
        let mut profile = doc.client.profiles[0].clone();
        profile.id = "backup".into();
        profile.server = "long-label-for-testing-profile-address.example.org:443".into();
        doc.client.profiles.push(profile);
        let original = Config::Client(doc).to_toml().unwrap();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('P')));
        let items = page_actions(Role::Client, 3, ui.editor.as_ref());
        ui.workspace_action = items.iter().position(|a| a.key == 'L').unwrap();
        review_capture("client-direct-profile-action", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Down));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
        assert!(!ui.editor.as_ref().unwrap().selected_record_is_active());
        review_capture("client-direct-profile-selection", &model, &ui);
        ui.update(&mut model, press(KeyCode::F(7)));
        review_capture("client-direct-profile-full-address", &model, &ui);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(!ui.owned_running(Role::Client));
    }
    let mut model = Model::new(None);
    let mut ui = Interaction::new(None);
    review_capture("home-role-selection", &model, &ui);
    ui.update(&mut model, press(KeyCode::Down));
    assert_eq!(model.selected, Role::Server);
    ui.update(&mut model, press(KeyCode::Right));
    assert_eq!(model.selected, Role::Client);
    assert_eq!(model.screen, Screen::Home);
    review_capture("home-role-selection-client", &model, &ui);
    ui.update(&mut model, press(KeyCode::Left));
    assert_eq!(model.selected, Role::Server);
    let mut help = model;
    help.update(press(KeyCode::Char('?')));
    review_capture("help", &help, &ui);

    for (role, prefix, path) in [(Role::Server, "server", &server), (Role::Client, "client", &client)] {
        let mut model = Model::new(Some(role));
        let mut ui = Interaction::new(None);
        review_capture(&format!("{prefix}-welcome"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.config_dialog.is_some());
        review_capture(&format!("{prefix}-file-picker"), &model, &ui);
        let new_path = root.join(format!("{prefix}-new.toml"));
        let dialog = ui.config_dialog.as_mut().unwrap();
        dialog.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        dialog.paste(new_path.to_str().unwrap());
        ui.update(&mut model, press(KeyCode::Down));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.config_dialog.is_some());
        review_capture(&format!("{prefix}-first-run-{}", if role == Role::Server { "reality" } else { "key-import" }), &model, &ui);
        assert!(!new_path.exists());
        if role == Role::Server {
            let dialog = ui.config_dialog.as_mut().unwrap();
            dialog.select_field(2);
            dialog.paste("93.184.216.1");
            dialog.select_field(5);
            dialog.paste("phone");
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.config_dialog.as_ref().unwrap().guide().is_some_and(|g| g.2 == "Источники поиска"));
            review_capture("server-first-reality-sources", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.config_dialog.as_ref().unwrap().guide().is_some_and(|g| g.2 == "Поиск адресов сайтов"));
            review_capture("server-first-reality-dns-consent", &model, &ui);
            ui.update(&mut model, press(KeyCode::F(2)));
            assert!(ui.config_dialog.as_ref().unwrap().guide().is_some_and(|g| g.2 == "Полный список целей"));
            review_capture("server-first-reality-dns-expanded", &model, &ui);
            ui.update(&mut model, press(KeyCode::Esc));
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(!new_path.exists());
        }

        let labels: &[(&str, &str)] = if role == Role::Server {
            &[("overview", "Обзор"), ("connections", "Подключения"),
              ("users", "Пользователи и ключи"), ("management", "Управление"),
              ("traffic", "Статистика"), ("settings", "Настройки"), ("diagnostics", "Диагностика"), ("routing", "Маршрутизация")]
        } else {
            &[("overview", "Обзор"), ("profiles", "Профили"),
              ("import", "Импорт ключа"), ("proxy", "Подключение"),
              ("traffic", "Статистика"), ("settings", "Настройки"), ("routing", "Маршрутизация")]
        };
        assert_eq!(labels.len(), pages(role).len());
        let mut action_keys = std::collections::HashSet::new();
        for (page, (label, title)) in labels.iter().enumerate() {
            assert_eq!(pages(role)[page], *title);
            for item in page_actions(role, page, None) {
                assert!(action_keys.insert(item.key), "duplicate visible action {}", item.key);
            }
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, page);
            ui.workspace_focus = ui.workspace_content_focus(role);
            let screen = rendered_interaction(120, 40, &model, &ui);
            if page == 4 {
                assert!(screen.contains("H2") && screen.contains("H3") && ui.workspace_monitor.is_some());
            }
            if page == 5 {
                assert!(screen.contains(path.to_str().unwrap()));
            }
            review_capture(&format!("{prefix}-page-{label}"), &model, &ui);
        }
        if role == Role::Server {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, 7);
            let mut panel = RoutingPanel::new(ui.editor.as_ref().unwrap());
            panel.settings.rules = vec![
                crate::routing::Rule { name: "Локальная сеть".into(), action: crate::routing::Action::Direct, domains: vec!["domain:example.test".into()], ips: vec![], applications: vec![] },
                crate::routing::Rule { name: "Заблокированные адреса".into(), action: crate::routing::Action::Blocked, domains: vec!["full:blocked.invalid".into()], ips: vec![], applications: vec![] },
            ];
            ui.routing_panel = Some(panel);
            ui.workspace_focus = WorkspaceFocus::Fields;
            ui.routing_panel.as_mut().unwrap().action_focus = Some(0);
            review_capture("server-routing-rules", &model, &ui);
            ui.routing_panel.as_mut().unwrap().edit(Some(0));
            review_capture("server-routing-edit", &model, &ui);
        } else {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, 6);
            ui.workspace_focus = WorkspaceFocus::Actions;
            let digest = ui.editor.as_ref().unwrap().saved_sha256();
            for (name, state, revision) in [("fresh", 1, 5), ("expired", 2, 5), ("unconfirmed", 0, 0)] {
                let mut observation = RoutingObservation::new(digest);
                let (tx, rx) = mpsc::channel();
                observation.pending = Some(rx);
                tx.send(Ok(crate::management::StatusReply::ClientRunning {
                    revision: 1, config_sha256: digest, descriptor_revision: 0,
                    transport: 2, xhttp: 1, fallback: false, routing_revision: revision,
                    routing_state: state,
                    routing_totals: Box::new({
                        let mut totals = [0u64; 38];
                        totals[..7].copy_from_slice(&[1024, 2048, 5120, 10240, 2, 1, 2]);
                        totals
                    }),
                    flow_counts: None,
                    capture_state: 0,
                })).unwrap();
                observation.poll();
                ui.routing_observation = Some(observation);
                review_capture(&format!("client-routing-{name}"), &model, &ui);
            }
        }
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.select_workspace_page(role, 0);
        ui.workspace_focus = WorkspaceFocus::Actions;
        let before = std::fs::read(path).unwrap();
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_page, 3);
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        assert!(ui.workspace_visible());
        assert!(!ui.owned_running(role));
        assert_eq!(std::fs::read(path).unwrap(), before);
        review_capture(&format!("{prefix}-overview-next-step"), &model, &ui);

        // F2 now focuses the actual sections, not an independent catalog.
        ui.update(&mut model, press(KeyCode::F(2)));
        assert!(ui.menu.is_none());
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
        review_capture(&format!("{prefix}-sections-focus"), &model, &ui);

        // Capture the actual monitor, not merely the navigation page.
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.update(&mut model, press(KeyCode::F(4)));
        if role == Role::Server {
            assert!(ui.traffic_monitor.is_none() && ui.workspace_monitor.is_some());
            assert_eq!(ui.workspace_page, 4);
        } else {
            assert!(ui.traffic_monitor.is_some());
            review_capture(&format!("{prefix}-traffic-monitor-idle"), &model, &ui);
            ui.update(&mut model, press(KeyCode::Esc));
        }
        if role == Role::Server {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.update(&mut model, press(KeyCode::F(5)));
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.show_server_process);
            assert!(!ui.server_process.running());
            assert!(ui.server_process.actions().is_empty());
            review_capture("server-start-confirmation", &model, &ui);
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(!ui.server_process.running());
        }
        // Navigate through the actual arrow-only workspace route.
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.select_workspace_page(role, 0);
        review_capture(&format!("{prefix}-focus-navigation"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Down));
        assert_eq!(ui.workspace_page, 1);
        ui.update(&mut model, press(KeyCode::Right));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
        ui.update(&mut model, press(KeyCode::Right));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Fields);
        review_capture(&format!("{prefix}-focus-fields"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Left));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
        review_capture(&format!("{prefix}-focus-records"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Left));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
        ui.update(&mut model, press(KeyCode::Up));
        assert_eq!(ui.workspace_page, 0);
        ui.update(&mut model, press(KeyCode::Right));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        // The overview has one navigation action. Move through it, then
        // capture focus in the canonical operation section.
        let before = std::fs::read(path).unwrap();
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_page, 3);
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        assert!(ui.workspace_visible());
        assert!(!ui.owned_running(role));
        assert_eq!(std::fs::read(path).unwrap(), before);

        // Open ordinary actions through their canonical visible section,
        // not through a separate command catalog or direct letter shortcuts.
        let actions: &[(usize, char, &str)] = if role == Role::Server {
            &[(1,'N',"new-connection"),(2,'G',"grant-picker"),(2,'u',"new-user"),
              (2,'t',"rotate-token"),(2,'x',"disable-user"),
              (5,'Q',"limits"),(1,'E',"certificate"),(3,'s',"server-process"),
              (3,'v',"runtime-status"),(6,'p',"network-diagnostics")]
        } else {
            &[(1,'N',"new-profile"),(2,'i',"invitation-import"),
              (1,'E',"trust-material"),(3,'V',"connection-status")]
        };
        for (page, key, label) in actions {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            let before = std::fs::read(path).unwrap();
            ui.select_workspace_page(role, *page);
            ui.workspace_focus = WorkspaceFocus::Actions;
            let items = page_actions(role, *page, ui.editor.as_ref());
            ui.workspace_action = items.iter().position(|a| a.key == *key)
                .unwrap_or_else(|| panic!("missing canonical action {key} in page {page}"));
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(!ui.workspace_visible(), "action {key} did not open its workflow");
            assert!(!ui.owned_running(role));
            assert_eq!(std::fs::read(path).unwrap(), before);
            if *key == 'i' {
                assert!(matches!(ui.importing, Some(ImportFlow::Input(_))));
                assert!(ui.reality_enrollment.is_none());
            }
            if role == Role::Server && *key == 's' {
                assert!(ui.show_server_process);
                assert_eq!(ui.server_process.confirmation(), Some(true));
                // Captured once as server-start-confirmation, not another view.
            } else {
                review_capture(&format!("{prefix}-action-{label}"), &model, &ui);
            }
            if role == Role::Server && *key == 'N' {
                ui.update(&mut model, press(KeyCode::Char('2')));
                assert!(ui.reality_provision.is_some());
                review_capture("server-action-reality-wizard", &model, &ui);
            }
        }
        // Advanced actions are deliberately hidden until the user expands
        // the canonical section. Never execute a technical operation here.
        {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, 1);
            ui.workspace_focus = WorkspaceFocus::Actions;
            let items = page_actions(role, 1, ui.editor.as_ref());
            assert!(!items.iter().any(|a| a.key == 'M'));
            ui.workspace_action = items.iter().position(|a| a.key == 'z').unwrap();
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.workspace_advanced && ui.workspace_visible());
            assert!(!ui.owned_running(role));
            review_capture(&format!("{prefix}-page-advanced"), &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(!ui.workspace_advanced);
        }
        if role == Role::Client {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, 2);
            ui.update(&mut model, press(KeyCode::Enter));
            ui.paste_workspace_import(&model, "theia://v1/synthetic-review");
            assert!(ui.inline_import());
            let view = rendered_interaction(120, 40, &model, &ui);
            assert!(view.contains("скрыто") && view.contains("Разделы"));
            assert!(!view.contains("synthetic-review"));
            review_capture("client-page-import-masked", &model, &ui);
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.importing.is_none());
            assert!(!ui.owned_running(role));
        }
        // Keep guarded shortcut-only failure cases explicitly marked as such.
        if role == Role::Server {
            let ungranted = root.join("server-ungranted.toml");
            let original = server_issuance_fixture().replace("[server.policy]", &format!("[[server.users]]\nid = \"review-ungranted\"\ntoken_sha256 = \"{}\"\ndisabled = false\n\n[server.policy]", "22".repeat(32)));
            std::fs::write(&ungranted, &original).unwrap();
            let mut ui = Interaction::new(Some(Editor::load(role, &ungranted).unwrap()));
            ui.select_workspace_page(role, 2);
            ui.workspace_user = 1;
            ui.workspace_focus = WorkspaceFocus::Actions;
            let items = page_actions_for(role, 2, ui.editor.as_ref(), 1, false);
            assert!(!items.iter().any(|a| matches!(a.key, 'b' | 't' | 'x')));
            ui.workspace_action = items.iter().position(|a| a.key == 'U').unwrap();
            review_capture("server-page-users-ungranted", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(matches!(&ui.records, Some(RecordFlow::Input { action: RecordAction::DeleteUser, fields, .. }) if fields[0] == "review-ungranted"));
            review_capture("server-action-delete-user", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert_eq!(ui.confirmation_choice(), Some(('y', "Удалить пользователя")));
            assert!(!ui.confirm_selected);
            review_capture("server-action-delete-user-confirm", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert_eq!(std::fs::read_to_string(&ungranted).unwrap(), original);
            assert!(!ui.owned_running(role));
            for (key, label) in [('D',"delete-connection"),('V',"reality-status-unavailable")] {
                let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
                ui.update(&mut model, press(KeyCode::Char(key)));
                assert!(!ui.owned_running(role));
                review_capture(&format!("{prefix}-action-{label}"), &model, &ui);
            }
        }
        if role == Role::Client {
            let path = root.join("multiple-profiles.toml");
            for (page, key, label) in [(1,'D',"delete-profile"),(3,'A',"active-profile")] {
                let mut ui = Interaction::new(Some(Editor::load(role, &path).unwrap()));
                ui.editor.as_mut().unwrap().workspace_select(1);
                ui.select_workspace_page(role, page);
                ui.workspace_focus = WorkspaceFocus::Actions;
                let items = page_actions(role, page, ui.editor.as_ref());
                ui.workspace_action = items.iter().position(|a| a.key == key).unwrap();
                ui.update(&mut model, press(KeyCode::Enter));
                assert!(ui.records.is_some());
                assert!(!ui.owned_running(role));
                review_capture(&format!("{prefix}-action-{label}"), &model, &ui);
            }
        }

        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.editor.as_mut().unwrap().error = Some("Пример ошибки: файл изменился на диске. Откройте его повторно.".into());
        review_capture(&format!("{prefix}-validation-error"), &model, &ui);
        if role == Role::Server {
            let mut ui = Interaction::new(None);
            ui.update(&mut model, press(KeyCode::Char('p')));
            let screen = rendered_interaction(120, 40, &model, &ui);
            assert!(screen.contains("Узнать внешний IP"));
            review_capture("server-discovery-actions", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.discovery.as_ref().unwrap().is_consent_pending());
            review_capture("server-discovery-consent", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            ui.update(&mut model, press(KeyCode::Down));
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.candidates.is_some());
            review_capture("server-reference-candidate-groups", &model, &ui);
            ui.update(&mut model, press(KeyCode::End));
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.domain.is_some());
            review_capture("server-domain-catalog", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.domain.as_ref().unwrap().is_dns_confirming());
            review_capture("server-domain-dns-confirm", &model, &ui);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(!ui.domain.as_ref().unwrap().is_running());
            ui.update(&mut model, press(KeyCode::Esc));
            ui.update(&mut model, press(KeyCode::Enter));
            review_capture("server-reference-cidr-input", &model, &ui);
        }
    }
    // Registered REALITY server: actual local material and the production
    // status reader, no listener, DNS query or reference probe.
    {
        use crate::reference_health::{Evidence, Plan, State, Store, Target};
        use crate::reality_config::{self, Request, ServerRequest};
        let now = crate::reference_health::unix_now().unwrap();
        let path = root.join("review-reality-server.toml");
        let health = root.join("review-reality-health");
        let bundle = root.join("review-reality-bundle");
        let state = State::new(Plan {
            schema_version: 1, inbound: "reality-edge".into(), endpoint: "edge.example.org:9443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "ref.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }],
        }, vec![Evidence { h2_status: Some(200), h3_status: None }], now).unwrap();
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
        std::fs::write(&path, server_issuance_fixture()).unwrap();
        let request = Request::Server(ServerRequest { health, bundle, health_sha256: digest, identity_sha256: record.identity_sha256, listen: "127.0.0.1:9443".parse().unwrap(), grants: vec!["device-a".into()] });
        let preview = reality_config::prepare(&path, &request, now).unwrap();
        reality_config::apply(&path, &request, preview.approval_sha256(), now).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        editor.workspace_select(1);
        assert!(editor.selected_reality());
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('V')));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let status = ui.reality_status.as_mut().unwrap();
            status.poll();
            if status.actions().iter().any(|a| a.key == 'd') { break; }
            assert!(std::time::Instant::now() < deadline, "server REALITY status did not finish");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Основной референс: ref.example.org"));
        assert!(screen.contains("Технические подробности"));
        assert!(!screen.contains("identity_sha256"));
        review_capture("server-reality-status-summary", &model, &ui);
        ui.update(&mut model, press(KeyCode::End));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(rendered_interaction(120, 40, &model, &ui).contains("identity_sha256"));
        review_capture("server-reality-status-technical", &model, &ui);
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_status.is_some());
        assert!(!ui.owned_running(Role::Server));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    // State fixtures use synthetic inputs, never actual issued credentials.
    let model = Model::new(Some(Role::Server));
    let disabled_server = root.join("server-disabled.toml");
    let disabled_fixture = server_issuance_fixture().replace("disabled = false", "disabled = true");
    assert_ne!(disabled_fixture, server_issuance_fixture());
    std::fs::write(&disabled_server, &disabled_fixture).unwrap();
    for (kind, label) in [(IssueKind::NewUser, "new"), (IssueKind::Rotation, "rotate"), (IssueKind::Reenable, "recover")] {
        let path = if kind == IssueKind::Reenable { &disabled_server } else { &server };
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, path).unwrap()));
        ui.issue_kind = kind;
        let user = if kind == IssueKind::NewUser { "review-device" } else { "device-a" };
        ui.issuance = Some(IssueFlow::Input(user.into()));
        review_capture(&format!("state-issuance-{label}-input"), &model, &ui);
        ui.issuance = Some(IssueFlow::Confirm(user.into()));
        review_capture(&format!("state-issuance-{label}-confirm"), &model, &ui);
        ui.issuance = Some(IssueFlow::SaveFailed);
        review_capture(&format!("state-issuance-{label}-failed"), &model, &ui);
        ui.issuance = Some(IssueFlow::Offer);
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Показать ссылку один раз"));
        assert!(!screen.contains("theia://v1/"));
        review_capture(&format!("state-issuance-{label}-offer"), &model, &ui);
        ui.issuance = Some(IssueFlow::ConfirmReveal);
        review_capture(&format!("state-issuance-{label}-reveal-confirm"), &model, &ui);
    }
    {
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &disabled_server).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.select_workspace_page(Role::Server, 2);
        ui.workspace_focus = WorkspaceFocus::Actions;
        let items = page_actions(Role::Server, 2, ui.editor.as_ref());
        assert!(!items.iter().any(|a| matches!(a.key, 't' | 'x')));
        ui.workspace_action = items.iter().position(|a| a.key == 'b').unwrap();
        review_capture("server-page-users-disabled", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(&ui.issuance, Some(IssueFlow::Input(id)) if id == "device-a"));
        assert!(!ui.owned_running(Role::Server));
        review_capture("server-action-recover-user", &model, &ui);
    }
    assert_eq!(std::fs::read_to_string(&disabled_server).unwrap(), disabled_fixture);
    let mut ui = Interaction::new(Some(Editor::load(Role::Server, &server).unwrap()));
    ui.revocation = Some(DisableFlow::Confirm("device-a".into()));
    review_capture("state-disable-confirm", &model, &ui);
    ui.revocation = Some(DisableFlow::SaveFailed);
    let screen = rendered_interaction(120, 40, &model, &ui);
    assert!(screen.contains("Повторить сохранение") && !screen.contains("Что это значит") && !screen.contains("Адрес UDP"));
    review_capture("state-disable-failed", &model, &ui);
    ui.revocation = Some(DisableFlow::Done);
    review_capture("state-disable-done", &model, &ui);
    let model = Model::new(Some(Role::Client));
    let mut ui = Interaction::new(Some(Editor::load(Role::Client, &client).unwrap()));
    ui.importing = Some(ImportFlow::Failed);
    review_capture("state-import-failed", &model, &ui);
    ui.importing = Some(ImportFlow::Done);
    review_capture("state-import-done", &model, &ui);
    assert_eq!(std::fs::read_to_string(server).unwrap(), server_issuance_fixture());
    assert_eq!(std::fs::read_to_string(client).unwrap(), include_str!("../../../examples/client.toml"));
}
