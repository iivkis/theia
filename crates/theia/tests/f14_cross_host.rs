//! F-14 M4.4d: real Linux (WSL2 VM) server -> native Windows client.
//! The dedicated CI job supplies a separate Linux kernel/network namespace,
//! real Linux server executable, trusted CA and a per-run 256-bit bearer.
//! This test is intentionally ignored outside that mandatory CI job.
#![cfg(windows)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use theia::{
    client_import,
    config::{self, ClientDocument, Config, SystemProxy, Transport},
    invite::Invitation,
    tui_editor::Editor,
    Role,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

struct Directory(PathBuf);

impl Drop for Directory {
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

fn reserve_address() -> (TcpListener, SocketAddr) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    (socket, address)
}

async fn await_client(address: SocketAddr, client: &mut Running) {
    timeout(Duration::from_secs(12), async {
        loop {
            assert!(
                client.0.try_wait().unwrap().is_none(),
                "native Windows client exited before binding"
            );
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Windows local proxy startup deadline");
}

async fn response_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192, "unbounded HTTP response");
        bytes.push(stream.read_u8().await.expect("HTTP response must arrive"));
    }
    bytes
}

async fn http_connect(proxy: SocketAddr, origin: u16, successful: bool) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request =
        format!("CONNECT 127.0.0.1:{origin} HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let reply = response_head(&mut stream).await;
    if !successful {
        assert!(
            !reply.starts_with(b"HTTP/1.1 200"),
            "unauthorized/invalid TLS tunnel must not return CONNECT 200"
        );
        return;
    }
    assert_eq!(reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let payload = vec![0x5a; 128 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(
        echoed, payload,
        "cross-OS HTTP CONNECT relay corrupted data"
    );
}

async fn socks5_connect(proxy: SocketAddr, origin: u16, successful: bool) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&origin.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    if !successful {
        assert_ne!(reply[1], 0, "unauthorized SOCKS5 tunnel must be denied");
        return;
    }
    assert_eq!(reply[0..2], [5, 0]);
    let payload = vec![0xa5; 128 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "cross-OS SOCKS5 relay corrupted data");
}

struct CrossOsFixture<'a> {
    source: &'a Config,
    endpoint: &'a str,
    token: &'a [u8; 32],
    ca: &'a Path,
    origin: u16,
}

async fn client_scenario(
    fixture: &CrossOsFixture<'_>,
    transport: Transport,
    invalid_token: bool,
    invalid_ca: bool,
) {
    let source = fixture.source;
    let endpoint = fixture.endpoint;
    let token = fixture.token;
    let ca = fixture.ca;
    let origin = fixture.origin;
    let label = format!(
        "{}-{}-{}",
        match transport {
            Transport::H2 => "h2",
            Transport::H3 => "h3",
            Transport::Auto => panic!("explicit H2/H3 required"),
        },
        invalid_token,
        invalid_ca
    );
    let dir = Directory(
        std::env::temp_dir().join(format!("theia-f14-cross-os-{}-{label}", std::process::id())),
    );
    fs::create_dir(&dir.0).unwrap();
    let config_path = dir.0.join("client.toml");
    fs::write(&config_path, include_str!("../../../examples/client.toml")).unwrap();

    // The invitation is issued by production code from the running Linux
    // server's exact grant/digest model, never synthesized from test metadata.
    let mut issued = Invitation::issued_from_server(source, "cross", "cross-user", token).unwrap();
    issued.endpoint = endpoint.to_owned();
    issued.transport = transport;
    let confidential_uri = zeroize::Zeroizing::new(issued.encode().unwrap());
    let invitation = client_import::read_source(&confidential_uri).unwrap();
    assert!(invitation.has_token());
    assert!(!format!("{invitation:?}").contains(&URL_SAFE_NO_PAD.encode(token)));

    let mut editor = Editor::load(Role::Client, &config_path).unwrap();
    let ca_ref = format!("file:{}", ca.display());
    if invalid_token {
        let mut public = Invitation::public_from_server(source, "cross").unwrap();
        public.endpoint = endpoint.to_owned();
        public.transport = transport;
        let link = public.encode().unwrap();
        let decoded = client_import::read_source(&link).unwrap();
        assert!(!decoded.has_token());
        let missing = editor.import_invitation(&decoded, Some(&ca_ref), None);
        assert!(missing.is_err());
        editor
            .import_invitation(
                &decoded,
                Some(&ca_ref),
                Some("env:THEIA_F14_XHOST_WRONG_TOKEN"),
            )
            .unwrap();
    } else {
        editor
            .import_invitation(&invitation, Some(&ca_ref), None)
            .unwrap();
    }
    assert!(
        editor
            .import_invitation(&invitation, Some(&ca_ref), None)
            .is_err(),
        "duplicate profile ID must be rejected"
    );
    let Config::Client(mut client_doc) = config::read_file(&config_path).unwrap() else {
        panic!("import must write a client TOML");
    };
    assert_eq!(client_doc.client.profiles.len(), 2);
    assert_eq!(client_doc.client.active_profile, "home");
    let imported = &client_doc.client.profiles[1];
    assert_eq!(imported.transport, transport);
    if invalid_token {
        assert_eq!(imported.auth_token, "env:THEIA_F14_XHOST_WRONG_TOKEN");
    } else {
        assert!(imported.auth_token.starts_with("file:"));
    }
    assert_eq!(client_doc.client.proxy.system_proxy, SystemProxy::Off);
    assert!(!fs::read_to_string(&config_path)
        .unwrap()
        .contains(&URL_SAFE_NO_PAD.encode(token)));

    client_doc.client.active_profile = invitation.id.clone();
    if invalid_ca {
        let wrong_ca = std::env::var("THEIA_F14_XHOST_WRONG_CA").unwrap();
        client_doc.client.profiles[1].tls_ca = Some(format!("file:{wrong_ca}"));
    }
    let successful = !invalid_token && !invalid_ca;
    run_client(&config_path, client_doc, origin, successful).await;
    if invalid_token {
        // The failed client is now stopped. Use the same saved profile,
        // not a new import or a manual overwrite of its auth reference.
        let mut editor = Editor::load(Role::Client, &config_path).unwrap();
        let before = config::read_file(&config_path).unwrap();
        editor.refresh_credential(&invitation).unwrap();
        let after = config::read_file(&config_path).unwrap();
        let Config::Client(mut expected) = before else {
            panic!("client");
        };
        let Config::Client(updated) = after else {
            panic!("client");
        };
        assert_eq!(
            expected.client.profiles[1].auth_token,
            "env:THEIA_F14_XHOST_WRONG_TOKEN"
        );
        let new_ref = &updated.client.profiles[1].auth_token;
        let new_file = Path::new(new_ref.strip_prefix("file:").unwrap());
        let bytes = zeroize::Zeroizing::new(fs::read_to_string(new_file).unwrap());
        assert!(bytes.as_str() == URL_SAFE_NO_PAD.encode(token));
        expected.client.profiles[1].auth_token = new_ref.clone();
        assert_eq!(updated, expected);
        run_client(&config_path, updated, origin, true).await;
    }
}

// The Linux fixture key never crosses to Windows. Construct a public
// invitation from independently transferred public trust material and
// provision the known per-run bearer via an explicit env reference.
async fn explicit_xhttp_client_scenario(
    fixture: &CrossOsFixture<'_>,
    transport: Transport,
    stream_up: bool,
) {
    let endpoint = fixture.endpoint.parse::<SocketAddr>().unwrap();
    let wrong_ca = std::env::var("THEIA_F14_XHOST_WRONG_CA").unwrap();

    let dir = Directory(std::env::temp_dir().join(format!(
        "theia-f18-cross-os-{}-{transport:?}-{stream_up}",
        std::process::id()
    )));
    fs::create_dir(&dir.0).unwrap();
    let config_path = dir.0.join("client.toml");
    let source = include_str!("../../../examples/client.toml");
    fs::write(&config_path, source).unwrap();
    let Config::Client(doc) = config::parse(source).unwrap() else {
        panic!("client fixture");
    };
    let mut profile = doc.client.profiles[0].clone();
    profile.id = if stream_up {
        "cross-split"
    } else {
        "cross-one"
    }
    .into();
    profile.server = endpoint.to_string();
    profile.server_name = "localhost".into();
    profile.transport = transport;
    profile.xhttp_mode = Some(if stream_up {
        config::XhttpMode::StreamUp
    } else {
        config::XhttpMode::StreamOne
    });
    let uri = Invitation::public_from_profile(&profile)
        .unwrap()
        .encode()
        .unwrap();
    let invitation = client_import::read_source(&uri).unwrap();
    assert_eq!(invitation.tls_profile(), profile.tls_profile);
    assert!(!invitation.has_token());

    let mut editor = Editor::load(Role::Client, &config_path).unwrap();
    let ca = format!("file:{}", fixture.ca.display());
    editor
        .import_invitation(&invitation, Some(&ca), Some("env:THEIA_F18_XHOST_TOKEN"))
        .unwrap();
    let Config::Client(mut imported) = config::read_file(&config_path).unwrap() else {
        panic!("imported client");
    };
    assert_eq!(imported.client.active_profile, "home");
    assert_eq!(imported.client.profiles[1].tls_profile, profile.tls_profile);
    assert_eq!(imported.client.profiles[1].transport, transport);
    imported.client.active_profile = profile.id;
    run_client(&config_path, imported.clone(), fixture.origin, true).await;

    let mut invalid = imported.clone();
    invalid.client.profiles[1].tls_ca = Some(format!("file:{wrong_ca}"));
    run_client(&config_path, invalid, fixture.origin, false).await;
    // A valid CA and bearer must not authorize an unknown inbound route.
    imported.client.profiles[1].path_prefix = Some("/v1/incorrect-cross-host".into());
    run_client(&config_path, imported, fixture.origin, false).await;
}

async fn run_client(
    config_path: &Path,
    mut client_doc: ClientDocument,
    origin: u16,
    successful: bool,
) {
    let (http_socket, http) = reserve_address();
    let (socks_socket, socks) = reserve_address();
    client_doc.client.proxy.http_listen = http.to_string();
    client_doc.client.proxy.socks5_listen = socks.to_string();
    config::atomic_write(config_path, &Config::Client(client_doc)).unwrap();
    drop(http_socket);
    drop(socks_socket);

    let client_bin = std::env::var_os("THEIA_F14_CLIENT_BIN")
        .expect("CI must supply its compiled native Windows client");
    let mut process = Running(
        Command::new(client_bin)
            .args(["client", "run", "--config"])
            .arg(config_path)
            .env_remove("THEIA_AUTH_TOKEN")
            .env(
                "THEIA_F18_XHOST_TOKEN",
                std::env::var("THEIA_F14_XHOST_TOKEN").unwrap(),
            )
            .env(
                "THEIA_F14_XHOST_WRONG_TOKEN",
                URL_SAFE_NO_PAD.encode([0x99; 32]),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    await_client(http, &mut process).await;
    await_client(socks, &mut process).await;
    http_connect(http, origin, successful).await;
    socks5_connect(socks, origin, successful).await;
    assert!(process.0.try_wait().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "required by the dedicated native Windows + Linux VM cross-OS CI job"]
async fn linux_server_windows_client_f14_h2_h3_open_ok() {
    timeout(Duration::from_secs(240), async {
        assert_eq!(std::env::var("THEIA_F14_XHOST_RUN").unwrap(), "yes");
        let endpoint = std::env::var("THEIA_F14_XHOST_ENDPOINT").unwrap();
        let target = endpoint.parse::<SocketAddr>().unwrap();
        assert!(!target.ip().is_loopback() && !target.ip().is_unspecified());
        let origin: u16 = std::env::var("THEIA_F14_XHOST_ORIGIN_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let server_config = std::env::var("THEIA_F14_XHOST_SERVER_CONFIG").unwrap();
        let trusted_ca = PathBuf::from(std::env::var("THEIA_F14_XHOST_CA").unwrap());
        let token_b64 = std::env::var("THEIA_F14_XHOST_TOKEN").unwrap();
        let token: [u8; 32] = URL_SAFE_NO_PAD
            .decode(token_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let config = config::read_file(Path::new(&server_config)).unwrap();
        let fixture = CrossOsFixture {
            source: &config,
            endpoint: &endpoint,
            token: &token,
            ca: &trusted_ca,
            origin,
        };
        for transport in [Transport::H2, Transport::H3] {
            client_scenario(&fixture, transport, false, false).await;
            client_scenario(&fixture, transport, true, false).await;
            client_scenario(&fixture, transport, false, true).await;
            for stream_up in [false, true] {
                explicit_xhttp_client_scenario(&fixture, transport, stream_up).await;
            }
        }
        for stream_up in [false, true] {
            explicit_xhttp_client_scenario(&fixture, Transport::Auto, stream_up).await;
        }
    })
    .await
    .expect("cross-OS Linux/Windows F-14 acceptance deadline");
}
