//! M4.2d: compiled Windows server, H2/H3 and SID-scoped Named Pipe CAS Apply.
//! No public network, TUI Apply or system proxy modifications.
#![cfg(target_os = "windows")]
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::{
    client::{ClientError, H2Client},
    config::{Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User},
    h3_client::H3Client,
    invite::Invitation,
    management::{ManagementError, StatusCommand, StatusReply},
    protocol::Address,
    tui_editor::Editor,
    windows_control::query_pipe,
    Role,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
#[path = "support/shared_port.rs"]
mod shared_port;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn save(path: &Path, doc: &ServerDocument) {
    fs::write(path, Config::Server(doc.clone()).to_toml().unwrap()).unwrap();
}
fn token(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 32])
}
fn hash(byte: u8) -> String {
    format!("{:x}", Sha256::digest([byte; 32]))
}
async fn echo_one(tcp: tokio::net::TcpStream) {
    let (mut input, mut output) = tcp.into_split();
    let _ = tokio::io::copy(&mut input, &mut output).await;
    let _ = output.shutdown().await;
}
fn cli(pipe_id: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(args)
        .env("THEIA_CONTROL_PIPE", pipe_id)
        .output()
        .unwrap()
}
async fn has_revision(pipe_id: &str, revision: u64) {
    assert_eq!(
        query_pipe(pipe_id, StatusCommand::Status).await,
        Ok(StatusReply::RunningRevision {
            inbounds: 1,
            revision
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atomic_apply_rotates_h2_and_h3_without_dropping_open_tunnels_or_quotas() {
    timeout(Duration::from_secs(45), async {
        let dir = std::env::temp_dir().join(format!(
            "theia-apply-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let pipe_id = format!(
            "m42d{}{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let toml = dir.join("server.toml");
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der())
        );
        let key = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        );
        fs::write(&cert_path, &cert).unwrap();
        {
            let mut private = theia::client_import::create_private_file(&key_path)
                .expect("create protected Windows TLS key fixture");
            private.write_all(key.as_bytes()).unwrap();
            private.sync_all().unwrap();
        }

        let mut roots = RootCertStore::empty();
        roots.add(generated.cert.der().clone()).unwrap();
        let (tcp_reservation, udp_reservation) = shared_port::reserve_shared_port();
        let tcp = tcp_reservation.local_addr().unwrap().port();
        let udp = udp_reservation.local_addr().unwrap().port();
        let mut doc = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
        path_prefix: Some("/v1/theia-example".into()),
                    allowed_user_ids: vec!["device-a".into()],
                    h2_listen: format!("127.0.0.1:{tcp}"),
                    quic_listen: format!("127.0.0.1:{udp}"),
                    server_name: "localhost".into(),
                    tls_cert: format!("file:{}", cert_path.display()),
                    security_mode: Default::default(),
                    reality: None,
                    tls_key: format!("file:{}", key_path.display()),
                }],
                users: vec![User {
                    id: "device-a".into(),
                    token_sha256: hash(0x42),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    allow_private_ips: true,
                    max_connections_per_user: 5,
                    max_connections_total: 12,
                    connect_timeout_ms: 1500,
                },
            },
            management: Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: Ui {
                language: "ru".into(),
            },
        };
        save(&toml, &doc);
        assert!(
            theia::server::tls_fingerprint_file(&toml).is_ok(),
            "Windows Apply fixture must satisfy the protected PEM reader and TLS builders"
        );
        drop(tcp_reservation);
        drop(udp_reservation);
        let mut server = Running(
            Command::new(env!("CARGO_BIN_EXE_theia"))
                .args(["server", "run", "--config"])
                .arg(&toml)
                .env("THEIA_CONTROL_PIPE", &pipe_id)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        timeout(Duration::from_secs(8), async {
            loop {
                if query_pipe(&pipe_id, StatusCommand::Status).await
                    == Ok(StatusReply::RunningRevision {
                        inbounds: 1,
                        revision: 1,
                    })
                {
                    break;
                }
                if let Some(status) = server.0.try_wait().unwrap() {
                    panic!("Windows Apply server exited before management readiness: {status}");
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        has_revision(&pipe_id, 1).await;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = target.accept().await else {
                    break;
                };
                tokio::spawn(echo_one(tcp));
            }
        });
        let addr = Address::V4([127, 0, 0, 1]);
        let h2old = H2Client::new(
            &format!("127.0.0.1:{tcp}"),
            "localhost",
            &token(0x42),
            roots.clone(),
        )
        .unwrap();
        let h3old = H3Client::new(
            format!("127.0.0.1:{udp}").parse().unwrap(),
            "localhost",
            &token(0x42),
            roots.clone(),
        )
        .unwrap();
        let mut h2_open = Some(h2old.open(addr.clone(), target_port).await.unwrap());
        let mut h3_open = Some(h3old.open(addr.clone(), target_port).await.unwrap());

        // Store the original grant in a separate client configuration.
        // Import does not select the new profile or launch a connection.
        let client_path = dir.join("client.toml");
        fs::write(&client_path, include_str!("../../../examples/client.toml")).unwrap();
        let mut importer = Editor::load(Role::Client, &client_path).unwrap();
        let initial = Invitation::issued_from_server(
            &Config::Server(doc.clone()),
            "edge",
            "device-a",
            &[0x42; 32],
        )
        .unwrap();
        let ca_ref = format!("file:{}", cert_path.display());
        importer
            .import_invitation(&initial, Some(&ca_ref), None)
            .unwrap();
        let original_config = theia::config::read_file(&client_path).unwrap();
        let Config::Client(mut original_client) = original_config else {
            panic!("client");
        };
        assert_eq!(original_client.client.active_profile, "home");
        let original_ref = original_client.client.profiles[1].auth_token.clone();
        let original_secret = original_ref.strip_prefix("file:").unwrap();

        // Stage is a safe read-only preview, not an implicit commit.
        doc.server.users[0].token_sha256 = hash(0x43);
        save(&toml, &doc);
        assert_eq!(
            query_pipe(&pipe_id, StatusCommand::CheckReload).await,
            Ok(StatusReply::Compatible)
        );
        has_revision(&pipe_id, 1).await;

        // The TUI's saved TOML is an exact-content candidate, not just
        // an unscoped request to apply whatever some other file contains.
        let digest: [u8; 32] = Sha256::digest(fs::read(&toml).unwrap()).into();
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReloadBound {
                    expected_revision: 1,
                    candidate_sha256: [0u8; 32],
                }
            )
            .await,
            Err(ManagementError::CandidateRejected),
            "another TOML file must never silently apply the active server file"
        );
        has_revision(&pipe_id, 1).await;
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReloadBound {
                    expected_revision: 1,
                    candidate_sha256: digest,
                }
            )
            .await,
            Ok(StatusReply::Applied { revision: 2 })
        );
        has_revision(&pipe_id, 2).await;
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReload {
                    expected_revision: 1
                }
            )
            .await,
            Err(ManagementError::CandidateRejected),
            "stale CAS must not apply twice"
        );
        let old_h2 = h2old.open(addr.clone(), target_port).await.err();
        let old_h3 = h3old.open(addr.clone(), target_port).await.err();
        assert_eq!(old_h2, Some(ClientError::Unauthorized));
        assert_eq!(old_h3, Some(ClientError::Unauthorized));
        let h2new = H2Client::new(
            &format!("127.0.0.1:{tcp}"),
            "localhost",
            &token(0x43),
            roots.clone(),
        )
        .unwrap();
        let h3new = H3Client::new(
            format!("127.0.0.1:{udp}").parse().unwrap(),
            "localhost",
            &token(0x43),
            roots.clone(),
        )
        .unwrap();
        assert!(h2new.open(addr.clone(), target_port).await.is_ok());
        assert!(h3new.open(addr.clone(), target_port).await.is_ok());

        // Pre-commit H2/H3 streams still echo after the token is revoked.
        for old in [0u8, 1u8] {
            let (mut app, local) = tokio::io::duplex(256);
            let relay = if old == 0 {
                let tunnel = h2_open.take().unwrap();
                tokio::spawn(async move { tunnel.relay(local).await.map_err(|e| format!("{e}")) })
            } else {
                let tunnel = h3_open.take().unwrap();
                tokio::spawn(async move { tunnel.relay(local).await.map_err(|e| format!("{e}")) })
            };
            app.write_all(b"still-open").await.unwrap();
            let mut reply = [0; 10];
            app.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"still-open");
            app.shutdown().await.unwrap();
            relay.await.unwrap().unwrap();
        }

        // Saved candidate is invalid: no revision increment, no changed auth.
        let stable = doc.clone();
        doc.server.policy.max_connections_total += 1;
        save(&toml, &doc);
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReload {
                    expected_revision: 2
                }
            )
            .await,
            Err(ManagementError::CandidateRejected)
        );
        has_revision(&pipe_id, 2).await;
        doc = stable;
        save(&toml, &doc);
        fs::write(&cert_path, b"swapped PEM").unwrap();
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReload {
                    expected_revision: 2
                }
            )
            .await,
            Err(ManagementError::CandidateRejected)
        );
        has_revision(&pipe_id, 2).await;
        fs::write(&cert_path, &cert).unwrap();

        // Verify compiled CLI performs a REAL second CAS publication, not
        // merely printing a fake success before IPC has answered.
        doc.server.users[0].disabled = true;
        save(&toml, &doc);
        let accepted = tokio::task::spawn_blocking({
            let pipe_id = pipe_id.clone();
            move || cli(&pipe_id, &["server", "reload", "--expected-revision", "2"])
        })
        .await
        .unwrap();
        assert!(accepted.status.success(), "{:?}", accepted.stderr);
        assert_eq!(
            accepted.stdout,
            b"authorization applied; revision=3; existing tunnels retained\n"
        );
        has_revision(&pipe_id, 3).await;
        assert_eq!(
            h2new.open(addr.clone(), target_port).await.err(),
            Some(ClientError::Unauthorized)
        );
        assert_eq!(
            h3new.open(addr.clone(), target_port).await.err(),
            Some(ClientError::Unauthorized)
        );

        let rejected = tokio::task::spawn_blocking({
            let pipe_id = pipe_id.clone();
            move || cli(&pipe_id, &["server", "reload", "--expected-revision", "2"])
        })
        .await
        .unwrap();
        assert!(!rejected.status.success());
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains(&token(0x43)));
        let status = tokio::task::spawn_blocking({
            let pipe_id = pipe_id.clone();
            move || cli(&pipe_id, &["server", "status"])
        })
        .await
        .unwrap();
        assert!(status.status.success());
        assert!(String::from_utf8_lossy(&status.stdout).contains("revision=3"));

        // A real explicit editor recovery issues a new bearer. Save
        // alone must not restore runtime admission on either branch.
        let mut issuer = Editor::load(Role::Server, &toml).unwrap();
        issuer.reenable_user("device-a").unwrap();
        assert!(issuer.take_issued().is_none());
        assert!(issuer.save());
        let exported = issuer.export_issued_file().unwrap();
        let invite = theia::client_import::read_source(exported.to_str().unwrap()).unwrap();
        let recovered = zeroize::Zeroizing::new(invite.token_bytes().unwrap());
        assert!(*recovered != [0x42; 32] && *recovered != [0x43; 32]);
        // Refresh only the credential reference. The original file is
        // retained even though its token is no longer authorized.
        importer.refresh_credential(&invite).unwrap();
        let updated_config = theia::config::read_file(&client_path).unwrap();
        let Config::Client(updated_client) = updated_config else {
            panic!("client");
        };
        let new_ref = &updated_client.client.profiles[1].auth_token;
        assert_ne!(new_ref, &original_ref);
        original_client.client.profiles[1].auth_token = new_ref.clone();
        assert_eq!(updated_client, original_client);
        let old_bytes = zeroize::Zeroizing::new(fs::read_to_string(original_secret).unwrap());
        assert!(old_bytes.as_str() == token(0x42));
        let new_path = new_ref.strip_prefix("file:").unwrap();
        let credential = zeroize::Zeroizing::new(fs::read_to_string(new_path).unwrap());
        assert!(credential.as_str() == URL_SAFE_NO_PAD.encode(*recovered));
        let h2recovered = H2Client::new(
            &format!("127.0.0.1:{tcp}"),
            "localhost",
            &credential,
            roots.clone(),
        )
        .unwrap();
        let h3recovered = H3Client::new(
            format!("127.0.0.1:{udp}").parse().unwrap(),
            "localhost",
            &credential,
            roots,
        )
        .unwrap();
        assert_eq!(
            h2recovered.open(addr.clone(), target_port).await.err(),
            Some(ClientError::Unauthorized)
        );
        assert_eq!(
            h3recovered.open(addr.clone(), target_port).await.err(),
            Some(ClientError::Unauthorized)
        );
        has_revision(&pipe_id, 3).await;
        let digest: [u8; 32] = Sha256::digest(fs::read(&toml).unwrap()).into();
        assert_eq!(
            query_pipe(
                &pipe_id,
                StatusCommand::ApplyReloadBound {
                    expected_revision: 3,
                    candidate_sha256: digest,
                }
            )
            .await,
            Ok(StatusReply::Applied { revision: 4 })
        );
        has_revision(&pipe_id, 4).await;
        for old in [&h2old, &h2new] {
            assert_eq!(
                old.open(addr.clone(), target_port).await.err(),
                Some(ClientError::Unauthorized)
            );
        }
        for old in [&h3old, &h3new] {
            assert_eq!(
                old.open(addr.clone(), target_port).await.err(),
                Some(ClientError::Unauthorized)
            );
        }
        assert!(h2recovered.open(addr.clone(), target_port).await.is_ok());
        assert!(h3recovered.open(addr, target_port).await.is_ok());

        echo_task.abort();
        drop(server);
        fs::remove_dir_all(dir).unwrap();
    })
    .await
    .expect("H2/H3 apply E2E must stay bounded");
}
