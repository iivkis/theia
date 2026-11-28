//! F-18 registered REALITY supervisor: protected native IPC, exact material
//! Apply, independent root retirement across real process restarts, no network
//! beyond loopback. Replay admission is not bypassed in the compiled binary.
#![cfg(any(target_os = "linux", target_os = "windows"))]

use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::{
    config::{self, Config, ServerDocument},
    management::{ManagementError, StatusCommand as C, StatusReply as R},
    reality_config::{self, Request, ServerReplacement, ServerRequest},
    reference_health::{self, Evidence, Plan, State, Store, Target},
};
use tokio::time::{sleep, timeout};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Endpoint {
    #[cfg(target_os = "linux")]
    directory: PathBuf,
    #[cfg(target_os = "windows")]
    id: String,
}
impl Endpoint {
    fn new(directory: &Path, sequence: u64) -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::DirBuilderExt;
            let directory = directory.join(format!("ipc-{sequence}"));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            Self { directory }
        }
        #[cfg(target_os = "windows")]
        {
            let _ = directory;
            Self {
                id: format!("f18-life-{}-{sequence}", std::process::id()),
            }
        }
    }

    fn launch(&self, config: &Path) -> Running {
        let mut command = Command::new(env!("CARGO_BIN_EXE_theia"));
        command
            .args(["server", "run", "--config"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(target_os = "linux")]
        command.env("THEIA_CONTROL_DIR", &self.directory);
        #[cfg(target_os = "windows")]
        command.env("THEIA_CONTROL_PIPE", &self.id);
        Running(command.spawn().unwrap())
    }

    async fn query(&self, command: C) -> Result<R, ManagementError> {
        #[cfg(target_os = "linux")]
        {
            theia::management::query_in(&self.directory, command).await
        }
        #[cfg(target_os = "windows")]
        {
            theia::windows_control::query_pipe(&self.id, command).await
        }
    }

    async fn ready(&self, process: &mut Running) {
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "supervisor exited during startup"
            );
            if self.query(C::Status).await
                == Ok(R::RunningRevision {
                    inbounds: 1,
                    revision: 1,
                })
            {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    }
}

fn reserve_address() -> (SocketAddr, TcpListener, UdpSocket) {
    // The Windows TCP and UDP ephemeral/excluded ranges can differ. Try
    // both allocation directions, then a bounded set of explicit loopback
    // ports outside the default dynamic range. Keep both reservations alive.
    for attempt in 0..128 {
        if attempt % 2 == 0 {
            if let Ok(tcp) = TcpListener::bind("127.0.0.1:0") {
                let address = tcp.local_addr().unwrap();
                if let Ok(udp) = UdpSocket::bind(address) {
                    return (address, tcp, udp);
                }
            }
        } else if let Ok(udp) = UdpSocket::bind("127.0.0.1:0") {
            let address = udp.local_addr().unwrap();
            if let Ok(tcp) = TcpListener::bind(address) {
                return (address, tcp, udp);
            }
        }
        let port = 20_000
            + ((std::process::id()
                .wrapping_mul(137)
                .wrapping_add(attempt * 131))
                % 20_000) as u16;
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(tcp) = TcpListener::bind(address) {
            if let Ok(udp) = UdpSocket::bind(address) {
                return (address, tcp, udp);
            }
        }
    }
    panic!("shared TCP/UDP fixture port")
}

fn save(path: &Path, doc: &ServerDocument) -> [u8; 32] {
    config::atomic_write(path, &Config::Server(doc.clone())).unwrap();
    Sha256::digest(fs::read(path).unwrap()).into()
}

async fn preview(endpoint: &Endpoint, revision: u64, digest: [u8; 32]) -> [u8; 32] {
    let reply = endpoint
        .query(C::CheckRestartBound {
            expected_revision: revision,
            candidate_sha256: digest,
        })
        .await
        .unwrap();
    let R::RestartPreview {
        same_port: true,
        material_sha256,
    } = reply
    else {
        panic!("expected independent same-port replacement preview, got {reply:?}");
    };
    material_sha256
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_replacement_apply_is_irreversible_across_native_supervisor_restart() {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQ.fetch_add(3, Ordering::Relaxed);
    let directory =
        Scratch(std::env::temp_dir().join(format!("theia-f18-{}-{sequence}", std::process::id())));
    fs::create_dir(&directory.0).unwrap();
    timeout(Duration::from_secs(55), async {
        let (address, reserved_tcp, reserved_udp) = reserve_address();
        let now = reference_health::unix_now().unwrap();
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "edge".into(),
                endpoint: address.to_string(),
                own_ips: vec![address.ip()],
                references: vec![Target {
                    server_name: "reference.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![Evidence {
                h2_status: Some(200),
                h3_status: Some(200),
            }],
            now,
        )
        .unwrap();
        let health = directory.0.join("health.toml");
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let digest = state.snapshot_sha256().unwrap();
        let old_bundle = directory.0.join("old");
        let new_bundle = directory.0.join("new");
        let old = theia::reality_provision::create(&state, digest, &old_bundle, now).unwrap();
        let new = theia::reality_provision::create(&state, digest, &new_bundle, now).unwrap();
        let config = directory.0.join("server.toml");
        fs::write(
            &config,
            include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap();
        let add = Request::Server(ServerRequest {
            health: health.clone(),
            bundle: old_bundle.clone(),
            health_sha256: digest,
            identity_sha256: old.identity_sha256,
            listen: address,
            grants: vec!["device-a".into()],
        });
        let review = reality_config::prepare(&config, &add, now).unwrap();
        reality_config::apply(&config, &add, review.approval_sha256(), now).unwrap();
        let Config::Server(mut original) = config::read_file(&config).unwrap() else {
            panic!()
        };
        original.server.inbounds.retain(|i| i.id == "edge");
        let old_digest = save(&config, &original);
        let old_manifest = original.server.inbounds[0]
            .reality
            .as_ref()
            .unwrap()
            .manifest_sha256;
        let control = Endpoint::new(&directory.0, sequence);
        drop((reserved_tcp, reserved_udp));
        let mut process = control.launch(&config);
        control.ready(&mut process).await;
        assert!(TcpListener::bind(address).is_err());
        assert!(UdpSocket::bind(address).is_err());
        assert!(matches!(
            control
                .query(C::reality_status("edge", old_manifest).unwrap())
                .await,
            Ok(R::RealityRunning {
                revision: 1,
                generation: 1,
                ..
            })
        ));

        let replace = Request::ReplaceServer(ServerReplacement {
            id: "edge".into(),
            health,
            bundle: new_bundle,
            health_sha256: digest,
            identity_sha256: new.identity_sha256,
        });
        let review = reality_config::prepare(&config, &replace, now).unwrap();
        reality_config::apply(&config, &replace, review.approval_sha256(), now).unwrap();
        let Config::Server(successor) = config::read_file(&config).unwrap() else {
            panic!()
        };
        let new_digest = Sha256::digest(fs::read(&config).unwrap()).into();
        let new_manifest = successor.server.inbounds[0]
            .reality
            .as_ref()
            .unwrap()
            .manifest_sha256;
        let pin = preview(&control, 1, new_digest).await;
        assert!(control
            .query(C::ApplyRestartBound {
                expected_revision: 1,
                candidate_sha256: old_digest,
                tls_sha256: pin,
            })
            .await
            .is_err());
        assert!(control
            .query(C::ApplyRestartBound {
                expected_revision: 1,
                candidate_sha256: new_digest,
                tls_sha256: [0; 32],
            })
            .await
            .is_err());
        assert_eq!(
            control.query(C::Status).await,
            Ok(R::RunningRevision {
                inbounds: 1,
                revision: 1
            })
        );
        assert_eq!(
            control
                .query(C::ApplyRestartBound {
                    expected_revision: 1,
                    candidate_sha256: new_digest,
                    tls_sha256: pin,
                })
                .await,
            Ok(R::RestartApplied { revision: 2 })
        );
        assert!(matches!(
            control
                .query(C::reality_status("edge", new_manifest).unwrap())
                .await,
            Ok(R::RealityRunning {
                generation: 1,
                revision: 1,
                ..
            })
        ));
        assert!(control
            .query(C::reality_status("edge", old_manifest).unwrap())
            .await
            .is_err());
        assert!(control
            .query(C::ApplyRestartRollback {
                expected_revision: 2
            })
            .await
            .is_err());
        assert!(control
            .query(C::ApplyTlsRollback {
                expected_revision: 2
            })
            .await
            .is_err());
        assert!(TcpListener::bind(address).is_err());
        assert!(UdpSocket::bind(address).is_err());

        // Stale saved bytes remain syntactically valid and old material still
        // exists, but cannot even obtain a successful management preview.
        let stale = save(&config, &original);
        assert!(control
            .query(C::CheckRestartBound {
                expected_revision: 2,
                candidate_sha256: stale,
            })
            .await
            .is_err());
        assert_eq!(
            control.query(C::Status).await,
            Ok(R::RunningRevision {
                inbounds: 1,
                revision: 2
            })
        );
        drop(process);

        // A new process with an old valid config and bundle must fail
        // before owning either listener or exposing a management endpoint.
        let rejected_control = Endpoint::new(&directory.0, sequence + 1);
        let mut rejected = rejected_control.launch(&config);
        loop {
            if let Some(exit) = rejected.0.try_wait().unwrap() {
                assert!(!exit.success(), "retired root restarted");
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
        drop(rejected);
        let tcp = TcpListener::bind(address).unwrap();
        let udp = UdpSocket::bind(address).unwrap();
        drop((tcp, udp));

        save(&config, &successor);
        let rebooted = Endpoint::new(&directory.0, sequence + 2);
        let mut process = rebooted.launch(&config);
        rebooted.ready(&mut process).await;
        assert!(matches!(
            rebooted
                .query(C::reality_status("edge", new_manifest).unwrap())
                .await,
            Ok(R::RealityRunning {
                generation: 1,
                revision: 1,
                ..
            })
        ));
        let stale = save(&config, &original);
        assert!(rebooted
            .query(C::CheckRestartBound {
                expected_revision: 1,
                candidate_sha256: stale,
            })
            .await
            .is_err());
        save(&config, &successor);
        assert_eq!(
            rebooted.query(C::Status).await,
            Ok(R::RunningRevision {
                inbounds: 1,
                revision: 1
            })
        );
        assert!(old_bundle.exists());
    })
    .await
    .expect("bounded native F-18 management/restart lifecycle");
}
