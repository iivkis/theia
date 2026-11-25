// Included inside tui::tests only by the dedicated Linux visual-review workflow.
fn review_capture(name: &str, model: &Model, ui: &Interaction) {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var_os("THEIA_REVIEW_CELLS").unwrap());
    let (width, height) = (120u16, 40u16);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    ui.viewport.reset();
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
    // Real first-run import through the production state machine, using a synthetic invitation.
    first_key_import_fixture(&root.join("first-own-tls"), review_capture);
    // Exercise a self-contained REALITY key through the actual first-run UI.
    {
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
        while !ui.config_dialog.as_ref().is_some_and(|d| d.title() == "Импорт REALITY" && d.guide().is_some_and(|g| g.0 == 3)) {
            ui.poll_navigation(&mut model);
            assert!(std::time::Instant::now() < deadline, "REALITY key review did not appear");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!path.exists());
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(!screen.contains(uri.as_str()));
        assert!(!screen.contains("Файл допуска (admission)"));
        review_capture("client-reality-key-trust-review", &model, &ui);
        ui.update(&mut model, press(KeyCode::Char('y')));
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
        assert_eq!(doc.client.proxy.system_proxy, config::SystemProxy::Off);
        assert!(!ui.owned_running(Role::Client));
        review_capture("client-reality-key-saved", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_page, 3);
        assert!(!ui.owned_running(Role::Client));
        review_capture("client-reality-key-connect", &model, &ui);
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
    review_capture("client-local-proxy-before-start", &client_model, &modes);
    let model = Model::new(None);
    let ui = Interaction::new(None);
    review_capture("home-role-selection", &model, &ui);
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

        let labels = if role == Role::Server {
            ["overview", "connections", "users", "invitations", "traffic", "settings", "diagnostics"]
        } else {
            ["overview", "profiles", "import", "proxy", "traffic", "settings", "diagnostics"]
        };
        for (page, label) in labels.iter().enumerate() {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            ui.select_workspace_page(role, page);
            ui.workspace_focus = if role == Role::Server && matches!(page, 2 | 3) {
                WorkspaceFocus::Users
            } else { WorkspaceFocus::Fields };
            review_capture(&format!("{prefix}-page-{label}"), &model, &ui);
        }
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.update(&mut model, press(KeyCode::F(2)));
        assert!(ui.menu.is_some());
        review_capture(&format!("{prefix}-command-menu"), &model, &ui);

        // Capture the actual monitor, not merely the navigation page.
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.update(&mut model, press(KeyCode::F(4)));
        assert!(ui.traffic_monitor.is_some());
        review_capture(&format!("{prefix}-traffic-monitor-idle"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Esc));
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
        // Capture both focus states without confirming an action.
        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.select_workspace_page(role, 0);
        review_capture(&format!("{prefix}-focus-navigation"), &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        // Show a different focused row than the default overview screenshot.
        // Moving focus must not open a workflow or change saved configuration.
        let before = std::fs::read(path).unwrap();
        ui.update(&mut model, press(KeyCode::Down));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        assert_eq!(std::fs::read(path).unwrap(), before);
        review_capture(&format!("{prefix}-focus-actions"), &model, &ui);

        // Only passive/input paths; no live operation confirmation.
        let keys: &[(char, &str)] = if role == Role::Server {
            &[('N',"new-connection"),('G',"grant-picker"),('u',"new-user"),('b',"recover-user"),
              ('t',"rotate-token"),('x',"disable-user"),('D',"delete-connection"),('U',"delete-user"),
              ('Q',"limits"),('E',"certificate"),('W',"reality-wizard"),('s',"server-process"),
              ('v',"runtime-status"),('p',"network-diagnostics"),('V',"reality-status-unavailable")]
        } else {
            &[('N',"new-profile"),('i',"invitation-import"),('I',"reality-import"),('E',"trust-material"),
              ('A',"active-profile"),('D',"delete-profile"),('V',"connection-status")]
        };
        for (key, label) in keys {
            let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
            if role == Role::Server && *key == 's' {
                ui.update(&mut model, press(KeyCode::F(5)));
                assert!(ui.show_server_process, "server process capture must open the actual panel");
            } else {
                ui.update(&mut model, press(KeyCode::Char(*key)));
            }
            // An unavailable action deliberately records the actual error, not a mock success.
            review_capture(&format!("{prefix}-action-{label}"), &model, &ui);
        }

        let mut ui = Interaction::new(Some(Editor::load(role, path).unwrap()));
        ui.editor.as_mut().unwrap().error = Some("Пример ошибки: файл изменился на диске. Откройте его повторно.".into());
        review_capture(&format!("{prefix}-validation-error"), &model, &ui);
        if role == Role::Server {
            let mut ui = Interaction::new(None);
            ui.update(&mut model, press(KeyCode::Char('p')));
            ui.update(&mut model, press(KeyCode::Char('i')));
            assert!(ui.discovery.is_some());
            review_capture("server-discovery-consent", &model, &ui);
            ui.update(&mut model, press(KeyCode::Char('n')));
            ui.update(&mut model, press(KeyCode::Char('r')));
            assert!(ui.candidates.is_some());
            review_capture("server-reference-candidate-groups", &model, &ui);
            ui.update(&mut model, press(KeyCode::Char('a')));
            review_capture("server-reference-cidr-input", &model, &ui);
        }
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
        review_capture(&format!("state-issuance-{label}-offer"), &model, &ui);
    }
    assert_eq!(std::fs::read_to_string(&disabled_server).unwrap(), disabled_fixture);
    let mut ui = Interaction::new(Some(Editor::load(Role::Server, &server).unwrap()));
    ui.revocation = Some(DisableFlow::Confirm("device-a".into()));
    review_capture("state-disable-confirm", &model, &ui);
    ui.revocation = Some(DisableFlow::SaveFailed);
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
