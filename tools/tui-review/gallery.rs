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
        review_capture(&format!("{prefix}-first-run-reality"), &model, &ui);
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

        // Only passive/input paths; no live operation confirmation.
        let keys: &[(char, &str)] = if role == Role::Server {
            &[('N',"new-connection"),('G',"grant-picker"),('u',"new-user"),('b',"recover-user"),
              ('t',"rotate-token"),('x',"disable-user"),('D',"delete-connection"),('U',"delete-user"),
              ('Q',"limits"),('E',"certificate"),('W',"reality-wizard"),('s',"server-process"),
              ('v',"runtime-status"),('p',"network-diagnostics"),('V',"reality-status")]
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
    for (kind, label) in [(IssueKind::NewUser, "new"), (IssueKind::Rotation, "rotate"), (IssueKind::Reenable, "recover")] {
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &server).unwrap()));
        ui.issue_kind = kind;
        ui.issuance = Some(IssueFlow::Input("review-device".into()));
        review_capture(&format!("state-issuance-{label}-input"), &model, &ui);
        ui.issuance = Some(IssueFlow::Confirm("review-device".into()));
        review_capture(&format!("state-issuance-{label}-confirm"), &model, &ui);
        ui.issuance = Some(IssueFlow::SaveFailed);
        review_capture(&format!("state-issuance-{label}-failed"), &model, &ui);
    }
    let mut ui = Interaction::new(Some(Editor::load(Role::Server, &server).unwrap()));
    ui.revocation = Some(DisableFlow::Confirm("review-device".into()));
    review_capture("state-disable-confirm", &model, &ui);
    ui.revocation = Some(DisableFlow::SaveFailed);
    review_capture("state-disable-failed", &model, &ui);
    let model = Model::new(Some(Role::Client));
    let mut ui = Interaction::new(Some(Editor::load(Role::Client, &client).unwrap()));
    ui.importing = Some(ImportFlow::Failed);
    review_capture("state-import-failed", &model, &ui);
    assert_eq!(std::fs::read_to_string(server).unwrap(), server_issuance_fixture());
    assert_eq!(std::fs::read_to_string(client).unwrap(), include_str!("../../../examples/client.toml"));
}
