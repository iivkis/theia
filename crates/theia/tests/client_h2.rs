//! Real M2.2a H2 client against the production M2.1 listener.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{Inbound, ServerPolicy, User},
    protocol::{Address, ErrorCode},
    server::{serve, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];

type ServerTask = JoinHandle<Result<(), theia::server::ServerError>>;

async fn listener(private: bool) -> (String, RootCertStore, ServerTask) {
    let (endpoint, roots, _pem, task) = listener_with_pem(private).await;
    (endpoint, roots, task)
}

async fn listener_with_pem(private: bool) -> (String, RootCertStore, String, ServerTask) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener_with_pem_bound(private, listener)
}

/// Shares the same server fixture when tests need a pre-reserved TCP+UDP port.
/// Windows ephemeral TCP and UDP availability must not be assumed identical.
fn listener_with_pem_bound(
    private: bool,
    listener: TcpListener,
) -> (String, RootCertStore, String, ServerTask) {
    listener_with_pem_bound_mode(private, listener, Default::default())
}

fn listener_with_pem_bound_mode(
    private: bool,
    listener: TcpListener,
    mode: theia::security_profile::SecurityMode,
) -> (String, RootCertStore, String, ServerTask) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let inbound = Inbound {
        id: "test".into(),
        allowed_user_ids: vec!["client".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "unused-test-fixture".into(),
        security_mode: mode,
        tls_key: "unused-test-fixture".into(),
    };
    let user = User {
        id: "client".into(),
        token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
        disabled: false,
    };
    let policy = ServerPolicy {
        allow_private_ips: private,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
    let endpoint = listener.local_addr().unwrap().to_string();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(serve(listener, acceptor, context));
    (endpoint, roots, pem, task)
}

fn token() -> String {
    URL_SAFE_NO_PAD.encode(TOKEN)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_client_opens_dns_target_and_relays_both_fins() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, roots, server) = listener(true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let client = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        let tunnel = client
            .open(Address::Dns("localhost".into()), port)
            .await
            .unwrap();
        let (mut app, local) = tokio::io::duplex(4096);
        let relay = tokio::spawn(tunnel.relay(local));
        let payload: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut received = Vec::new();
        app.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        relay.await.unwrap().unwrap();
        echo.await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_auth_and_acl_failures_never_return_tunnel() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, roots, server) = listener(false).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let addr = Address::Dns("localhost".into());
        let wrong_name =
            H2Client::new(&endpoint, "wrong.example", &token(), roots.clone()).unwrap();
        assert!(matches!(
            wrong_name.open(addr.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut untrusted = RootCertStore::empty();
        untrusted.add(unrelated.cert.der().clone()).unwrap();
        let wrong_ca = H2Client::new(&endpoint, "localhost", &token(), untrusted).unwrap();
        assert!(matches!(
            wrong_ca.open(addr.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let wrong_token = H2Client::new(
            &endpoint,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x43; 32]),
            roots.clone(),
        )
        .unwrap();
        assert!(matches!(
            wrong_token.open(addr.clone(), port).await,
            Err(ClientError::Unauthorized)
        ));
        let valid = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        assert!(matches!(
            valid.open(addr, port).await,
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        ));
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[test]
fn rejects_missing_trust_and_noncanonical_token() {
    assert!(matches!(
        H2Client::new(
            "localhost:443",
            "localhost",
            &token(),
            RootCertStore::empty()
        ),
        Err(ClientError::Configuration)
    ));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    assert!(matches!(
        H2Client::new(
            "localhost:443",
            "localhost",
            &format!("{}=", token()),
            roots
        ),
        Err(ClientError::Configuration)
    ));
}

async fn local_listeners(
    client: H2Client,
) -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    JoinHandle<Result<(), ClientError>>,
) {
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let task = tokio::spawn(theia::local_proxy::serve(http, socks, Arc::new(client)));
    (http_addr, socks_addr, task)
}

async fn response_head(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192);
        head.push(socket.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

async fn socks_connect_request(socket: &mut TcpStream, port: u16) -> [u8; 10] {
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    socket.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 3, 9];
    request.extend_from_slice(b"localhost");
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_connect_and_socks5_relay_real_tcp_with_half_close() {
    timeout(Duration::from_secs(20), async {
        let (endpoint, roots, server) = listener(true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                tasks.spawn(async move {
                    let mut input = Vec::new();
                    socket.read_to_end(&mut input).await.unwrap();
                    socket.write_all(&input).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let client = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        let (http, socks, proxy) = local_listeners(client).await;
        let mut connect = TcpStream::connect(http).await.unwrap();
        let head = format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
        let mut pipelined = head.into_bytes();
        let http_payload = b"pipelined application bytes";
        pipelined.extend_from_slice(http_payload);
        connect.write_all(&pipelined).await.unwrap();
        assert_eq!(
            response_head(&mut connect).await,
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        let mut sock = TcpStream::connect(socks).await.unwrap();
        assert_eq!(socks_connect_request(&mut sock, port).await[1], 0);
        let socks_payload = vec![0x5a; 128 * 1024];
        sock.write_all(&socks_payload).await.unwrap();
        sock.shutdown().await.unwrap();
        connect.shutdown().await.unwrap();
        let mut http_result = Vec::new();
        let mut socks_result = Vec::new();
        connect.read_to_end(&mut http_result).await.unwrap();
        sock.read_to_end(&mut socks_result).await.unwrap();
        assert_eq!(http_result, http_payload);
        assert_eq!(socks_result, socks_payload);
        echo.await.unwrap();
        proxy.abort();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_proxies_never_acknowledge_policy_denial_or_invalid_protocol() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, roots, server) = listener(false).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let client = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        let (http, socks, proxy) = local_listeners(client).await;
        let mut connect = TcpStream::connect(http).await.unwrap();
        connect
            .write_all(
                format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        assert!(response_head(&mut connect)
            .await
            .starts_with("HTTP/1.1 403 "));
        let mut sock = TcpStream::connect(socks).await.unwrap();
        assert_eq!(socks_connect_request(&mut sock, port).await[1], 2);

        let mut malformed = TcpStream::connect(http).await.unwrap();
        malformed
            .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: wrong.example:443\r\n\r\n")
            .await
            .unwrap();
        assert!(response_head(&mut malformed)
            .await
            .starts_with("HTTP/1.1 400 "));
        let mut method = TcpStream::connect(http).await.unwrap();
        method
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        assert!(response_head(&mut method)
            .await
            .starts_with("HTTP/1.1 405 "));
        let mut unsupported = TcpStream::connect(socks).await.unwrap();
        unsupported.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0; 2];
        unsupported.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        proxy.abort();
        server.abort();
    })
    .await
    .unwrap();
}

struct TestDirectory(std::path::PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildProcess(std::process::Child);

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_proxy(address: std::net::SocketAddr, child: &mut ChildProcess) {
    timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "client executable exited before binding"
            );
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("client listener startup deadline");
}

async fn launch_client_with_profile(
    endpoint: String,
    pem: String,
    label: &str,
    transport: theia::config::Transport,
    tls_profile: &str,
) -> (
    TestDirectory,
    ChildProcess,
    std::net::SocketAddr,
    std::net::SocketAddr,
) {
    let dir = TestDirectory(
        std::env::temp_dir().join(format!("theia-{label}-ci-{}", std::process::id())),
    );
    std::fs::create_dir(&dir.0).unwrap();
    let ca_path = dir.0.join("trust.pem");
    std::fs::write(&ca_path, pem).unwrap();

    // Reserve two different ports, then transfer them to the child.
    // Only isolated loopback listeners are used; no OS proxy settings.
    let http_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http = http_reservation.local_addr().unwrap();
    let socks = socks_reservation.local_addr().unwrap();
    let theia::config::Config::Client(mut doc) =
        theia::config::parse(include_str!("../../../examples/client.toml")).unwrap()
    else {
        panic!("client fixture has wrong role");
    };
    let profile = &mut doc.client.profiles[0];
    profile.server = endpoint;
    profile.server_name = "localhost".into();
    profile.transport = transport;
    profile.tls_profile = tls_profile.to_owned();
    profile.tls_ca = Some(format!("file:{}", ca_path.display()));
    profile.auth_token = "env:THEIA_CI_TEST_TOKEN".into();
    doc.client.proxy.http_listen = http.to_string();
    doc.client.proxy.socks5_listen = socks.to_string();
    let config = dir.0.join("client.toml");
    theia::config::atomic_write(&config, &theia::config::Config::Client(doc)).unwrap();
    drop(http_reservation);
    drop(socks_reservation);
    let mut child = ChildProcess(
        std::process::Command::new(env!("CARGO_BIN_EXE_theia"))
            .arg("client")
            .arg("run")
            .arg("--config")
            .arg(&config)
            .env("THEIA_CI_TEST_TOKEN", token())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_proxy(http, &mut child).await;
    wait_for_proxy(socks, &mut child).await;
    (dir, child, http, socks)
}

async fn launch_client(
    endpoint: String,
    pem: String,
    label: &str,
    transport: theia::config::Transport,
) -> (
    TestDirectory,
    ChildProcess,
    std::net::SocketAddr,
    std::net::SocketAddr,
) {
    launch_client_with_profile(endpoint, pem, label, transport, "default").await
}

/// Black-box curl tests run on both native CI runners. No external service,
/// installed system proxy, manually provisioned key or interactive setup.
/// A real server-issued confidential link, independently provided CA and
/// protected client token file must reach OPEN_OK via the *binary* on native
/// Linux and Windows. Import alone never selects an active profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_server_invitation_reaches_real_connect_and_socks5_without_env_token() {
    use theia::{
        config::{self, Config, Transport},
        invite::Invitation,
        tui_editor::Editor,
        Role,
    };
    timeout(Duration::from_secs(40), async {
        let (endpoint, _roots, pem, server) = listener_with_pem(true).await;
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("theia-f14-import-ci-{}", std::process::id())),
        );
        std::fs::create_dir(&directory.0).unwrap();
        let ca_path = directory.0.join("ca.pem");
        std::fs::write(&ca_path, pem).unwrap();
        let ca_ref = format!("file:{}", ca_path.display());
        let config_path = directory.0.join("client.toml");
        std::fs::write(&config_path, include_str!("../../../examples/client.toml")).unwrap();

        let Config::Server(mut source) =
            config::parse(&include_str!("../../../examples/server.toml").replace(
                "REPLACE_WITH_64_LOWERCASE_HEX",
                &format!("{:x}", Sha256::digest(TOKEN)),
            ))
            .unwrap()
        else {
            panic!("server");
        };
        let endpoint_port = endpoint.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        source.server.inbounds[0].server_name = "localhost".into();
        source.server.inbounds[0].h2_listen = format!("127.0.0.1:{endpoint_port}");
        source.server.inbounds[0].quic_listen = format!("127.0.0.1:{endpoint_port}");
        source.server.inbounds[0].allowed_user_ids = vec!["client".into()];
        source.server.users[0].id = "client".into();
        let mut invitation =
            Invitation::issued_from_server(&Config::Server(source), "public", "client", &TOKEN)
                .unwrap();
        // Native loopback fixture is bound on IPv4; keep independent SNI=localhost.
        // A real deployment must advertise an operator-controlled endpoint.
        invitation.endpoint = endpoint.clone();
        let confidential = invitation.encode().unwrap();
        let decoded = theia::client_import::read_source(&confidential).unwrap();
        let mut editor = Editor::load(Role::Client, &config_path).unwrap();
        editor
            .import_invitation(&decoded, Some(&ca_ref), None)
            .unwrap();
        let Config::Client(mut client) = config::read_file(&config_path).unwrap() else {
            panic!("client");
        };
        assert_eq!(client.client.active_profile, "home");
        assert_eq!(client.client.profiles.len(), 2);
        let imported = &client.client.profiles[1];
        assert!(imported.auth_token.starts_with("file:"));
        assert!(!std::fs::read_to_string(&config_path)
            .unwrap()
            .contains(&token()));
        assert_eq!(imported.server, endpoint);
        assert_eq!(imported.tls_ca.as_deref(), Some(ca_ref.as_str()));

        // The user separately selects the imported profile and starts the
        // client. Neither step was part of the import operation itself.
        client.client.active_profile = imported.id.clone();
        client.client.profiles[1].transport = Transport::H2;
        let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http.local_addr().unwrap();
        let socks_addr = socks.local_addr().unwrap();
        client.client.proxy.http_listen = http_addr.to_string();
        client.client.proxy.socks5_listen = socks_addr.to_string();
        config::atomic_write(&config_path, &Config::Client(client)).unwrap();
        drop(http);
        drop(socks);
        let mut binary = ChildProcess(
            std::process::Command::new(env!("CARGO_BIN_EXE_theia"))
                .args(["client", "run", "--config"])
                .arg(&config_path)
                .env_remove("THEIA_AUTH_TOKEN")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for_proxy(http_addr, &mut binary).await;
        wait_for_proxy(socks_addr, &mut binary).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut input = Vec::new();
                socket.read_to_end(&mut input).await.unwrap();
                socket.write_all(&input).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });

        let mut http_proxy = TcpStream::connect(http_addr).await.unwrap();
        http_proxy
            .write_all(
                format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            response_head(&mut http_proxy).await,
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        http_proxy.write_all(b"imported-http").await.unwrap();
        http_proxy.shutdown().await.unwrap();
        let mut echoed_http = Vec::new();
        http_proxy.read_to_end(&mut echoed_http).await.unwrap();
        assert_eq!(echoed_http, b"imported-http");

        let mut socks_proxy = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(socks_connect_request(&mut socks_proxy, port).await[1], 0);
        socks_proxy.write_all(b"imported-socks").await.unwrap();
        socks_proxy.shutdown().await.unwrap();
        let mut echoed_socks = Vec::new();
        socks_proxy.read_to_end(&mut echoed_socks).await.unwrap();
        assert_eq!(echoed_socks, b"imported-socks");

        echo.await.unwrap();
        assert!(binary.0.try_wait().unwrap().is_none());
        drop(binary);
        server.abort();
    })
    .await
    .expect("native F-14 import-to-real-OPEN_OK E2E");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_binary_curl_connect_and_socks5h() {
    check_native_binary_connect_and_socks5("default", "curl").await;
}

#[cfg(feature = "experimental-btls-h2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn named_browser_h2_profile_binary_connect_and_socks5_real_open_ok() {
    // Uses ordinary client.toml selection (not an experimental-only API)
    // in the actual compiled Windows/Linux client. Both local proxy
    // protocols must reach the real SmartTheia OPEN_OK gate.
    check_native_binary_connect_and_socks5("browser-h2-btls-v1", "browser-h2").await;
}

async fn check_native_binary_connect_and_socks5(tls_profile: &str, label: &str) {
    timeout(Duration::from_secs(40), async {
        let (endpoint, _roots, pem, server) = listener_with_pem(true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let body = b"theia-ci-http-origin";
        let origin = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 8192);
                    head.push(socket.read_u8().await.unwrap());
                }
                assert!(head.starts_with(b"GET /ci HTTP/1."));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let (_dir, mut child, http, socks) = launch_client_with_profile(
            endpoint,
            pem,
            label,
            theia::config::Transport::H2,
            tls_profile,
        )
        .await;

        // --disable ignores any user curlrc. --noproxy "" prevents the
        // standard localhost bypass. HTTP mode must actually use CONNECT.
        let curl = if cfg!(windows) { "curl.exe" } else { "curl" };
        for (proxy, tunnel) in [
            (format!("http://{http}"), true),
            (format!("socks5h://{socks}"), false),
        ] {
            let proxy_url = proxy;
            let url = if tunnel {
                format!("http://127.0.0.1:{port}/ci")
            } else {
                format!("http://localhost:{port}/ci")
            };
            let output = tokio::task::spawn_blocking(move || {
                let mut command = std::process::Command::new(curl);
                command
                    .args(["--disable", "--fail", "--silent", "--show-error"])
                    .args(["--max-time", "12", "--noproxy", "", "--proxy", &proxy_url]);
                if tunnel {
                    command.arg("--proxytunnel");
                }
                command
                    .arg(url)
                    .output()
                    .expect("curl must be installed on CI")
            })
            .await
            .unwrap();
            assert!(
                output.status.success(),
                "curl proxy request failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, body);
        }
        origin.await.unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        drop(child);
        server.abort();
    })
    .await
    .expect("bounded executable + curl CI scenario");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mandatory dedicated CI browser-e2e job provisions Playwright and Chromium"]
async fn client_binary_chromium_socks5() {
    let (endpoint, _roots, pem, server) = listener_with_pem(true).await;
    browser_socks_scenario(
        endpoint,
        pem,
        server,
        "browser",
        theia::config::Transport::H2,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mandatory dedicated CI browser-e2e job provisions Playwright and Chromium"]
async fn client_binary_chromium_socks5_over_h3() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let bind = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        theia::quic_transport::server_endpoint(bind, vec![cert.cert.der().clone()], key.into())
            .unwrap();
    let remote = endpoint.local_addr().unwrap().to_string();
    let inbound = Inbound {
        id: "browser-h3".into(),
        allowed_user_ids: vec!["client".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: remote.clone(),
        server_name: "localhost".into(),
        tls_cert: "unused-test-fixture".into(),
        security_mode: Default::default(),
        tls_key: "unused-test-fixture".into(),
    };
    let user = User {
        id: "client".into(),
        token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
        disabled: false,
    };
    let policy = ServerPolicy {
        allow_private_ips: true,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
    let server = tokio::spawn(theia::h3_server::serve(endpoint, context));
    // No TCP/TLS listener exists at the remote endpoint. The explicit H3
    // client must complete its authenticated QUIC tunnel; no H2 fallback.
    browser_socks_scenario(
        remote,
        cert.cert.pem(),
        server,
        "browser-h3",
        theia::config::Transport::H3,
    )
    .await;
}

async fn browser_socks_scenario(
    endpoint: String,
    pem: String,
    server: ServerTask,
    label: &str,
    transport: theia::config::Transport,
) {
    timeout(Duration::from_secs(75), async {
        let (_dir, mut child, _http, socks) = launch_client(endpoint, pem, label, transport).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            let mut requests = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = requests.join_next(), if !requests.is_empty() => {
                        if matches!(result, Some(Ok(true))) {
                            return;
                        }
                    }
                    accepted = target.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        requests.spawn(async move {
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") {
                                if head.len() >= 8192 {
                                    return false;
                                }
                                match socket.read_u8().await {
                                    Ok(byte) => head.push(byte),
                                    Err(_) => return false,
                                }
                            }
                            if !head.starts_with(b"GET /ci-browser HTTP/1.") {
                                return false;
                            }
                            let body = b"<html><body><main id='result'>theia-browser-ci-ok</main></body></html>";
                            let reply = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            socket.write_all(reply.as_bytes()).await.unwrap();
                            socket.write_all(body).await.unwrap();
                            socket.shutdown().await.unwrap();
                            true
                        });
                    }
                }
            }
        });
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/e2e/chromium_socks.py");
        let mut process = ChildProcess(
            std::process::Command::new("python")
                .arg(script)
                .arg(socks.to_string())
                .arg(port.to_string())
                .stdin(std::process::Stdio::null())
                .spawn()
                .expect("CI Python and Playwright must be installed"),
        );
        let status = timeout(Duration::from_secs(60), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("Chromium fixture deadline");
        assert!(status.success(), "Chromium SOCKS5 scenario failed");
        origin.await.unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        drop(child);
        server.abort();
    })
    .await
    .expect("bounded executable + Chromium CI scenario");
}

/// Native H3 counterpart of F-14 imported H2 test: the full confidential
/// invitation is decoded and securely persisted, then the actual single
/// binary is independently started with that file-backed bearer. The test
/// server intentionally uses independently bound H2/H3 ports, so this
/// fixture explicitly produces an H3-only invitation for its UDP endpoint.
async fn launch_imported_h3_client(
    endpoint: String,
    pem: String,
    exported: &std::path::Path,
) -> (
    TestDirectory,
    ChildProcess,
    std::net::SocketAddr,
    std::net::SocketAddr,
) {
    use theia::config::{self, Config, Transport};
    use theia::{tui_editor::Editor, Role};
    let dir = TestDirectory(
        std::env::temp_dir().join(format!("theia-f14-h3-import-ci-{}", std::process::id())),
    );
    std::fs::create_dir(&dir.0).unwrap();
    let ca_path = dir.0.join("trust.pem");
    std::fs::write(&ca_path, pem).unwrap();
    let config_path = dir.0.join("client.toml");
    std::fs::write(&config_path, include_str!("../../../examples/client.toml")).unwrap();

    // Consume a real file produced by the server editor, not a synthesized
    // URI. The endpoint override below is an explicit local fixture edit.
    let invitation = theia::client_import::read_source(exported.to_str().unwrap()).unwrap();
    let issued_token = invitation.token_bytes().unwrap();
    assert_eq!(invitation.transport, Transport::Auto);
    let mut editor = Editor::load(Role::Client, &config_path).unwrap();
    editor
        .import_invitation(
            &invitation,
            Some(&format!("file:{}", ca_path.display())),
            None,
        )
        .unwrap();
    let Config::Client(mut client) = config::read_file(&config_path).unwrap() else {
        panic!("client fixture");
    };
    assert_eq!(client.client.active_profile, "home");
    assert_eq!(client.client.profiles.len(), 2);
    assert_eq!(client.client.profiles[1].transport, Transport::Auto);
    assert!(client.client.profiles[1].auth_token.starts_with("file:"));
    assert!(!std::fs::read_to_string(&config_path)
        .unwrap()
        .contains(&URL_SAFE_NO_PAD.encode(issued_token)));
    client.client.active_profile = invitation.id.clone();
    client.client.profiles[1].transport = Transport::H3;
    client.client.profiles[1].server = endpoint;

    // OS proxy remains off; reserve only private per-process localhost binds.
    let http_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http = http_reservation.local_addr().unwrap();
    let socks = socks_reservation.local_addr().unwrap();
    client.client.proxy.http_listen = http.to_string();
    client.client.proxy.socks5_listen = socks.to_string();
    config::atomic_write(&config_path, &Config::Client(client)).unwrap();
    drop(http_reservation);
    drop(socks_reservation);
    let mut child = ChildProcess(
        std::process::Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(["client", "run", "--config"])
            .arg(config_path)
            .env_remove("THEIA_AUTH_TOKEN")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_proxy(http, &mut child).await;
    wait_for_proxy(socks, &mut child).await;
    (dir, child, http, socks)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_server_and_client_binaries_curl_both_local_proxies() {
    timeout(Duration::from_secs(60), async {
        let dir = TestDirectory(
            std::env::temp_dir().join(format!("theia-h3-server-ci-{}", std::process::id())),
        );
        std::fs::create_dir(&dir.0).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let cert_path = dir.0.join("cert.pem");
        let key_path = dir.0.join("key.pem");
        std::fs::write(&cert_path, &pem).unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            use std::io::Write;
            let mut key = options.open(&key_path).unwrap();
            key.write_all(cert.key_pair.serialize_pem().as_bytes())
                .unwrap();
        }
        // The v1 server issuer requires a common TCP/UDP port. Reserve both
        // before starting the binary; retry only local fixture allocation.
        let (tcp_reservation, udp_reservation) = (0..32)
            .find_map(|_| {
                let tcp = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
                let udp = std::net::UdpSocket::bind(tcp.local_addr().ok()?).ok()?;
                Some((tcp, udp))
            })
            .expect("reserve common TCP/UDP port");
        let tcp = tcp_reservation.local_addr().unwrap();
        let udp = udp_reservation.local_addr().unwrap();
        let source = include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest(TOKEN)),
        );
        let theia::config::Config::Server(mut doc) = theia::config::parse(&source).unwrap() else {
            panic!("server fixture has wrong role");
        };
        let inbound = &mut doc.server.inbounds[0];
        inbound.h2_listen = tcp.to_string();
        inbound.quic_listen = udp.to_string();
        inbound.server_name = "localhost".into();
        inbound.tls_cert = format!("file:{}", cert_path.display());
        inbound.tls_key = format!("file:{}", key_path.display());
        doc.server.policy.allow_private_ips = true;
        let config = dir.0.join("server.toml");
        theia::config::atomic_write(&config, &theia::config::Config::Server(doc)).unwrap();
        let mut issuer = theia::tui_editor::Editor::load(theia::Role::Server, &config).unwrap();
        issuer.issue_user("export-device").unwrap();
        assert!(issuer.save());
        let exported = issuer.export_issued_file().unwrap();
        assert!(issuer.take_issued().is_none());
        drop(tcp_reservation);
        drop(udp_reservation);
        let mut server = ChildProcess(
            std::process::Command::new(env!("CARGO_BIN_EXE_theia"))
                .args(["server", "run", "--config"])
                .arg(config)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        // A successful H2 TCP bind is a readiness barrier: UDP must already
        // have been prepared as part of the same atomic startup.
        wait_for_proxy(tcp, &mut server).await;
        let (_client_dir, mut client, http, socks) =
            launch_imported_h3_client(udp.to_string(), pem, &exported).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let body = b"theia-h3-cli-ci-origin";
        let origin = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 8192);
                    head.push(socket.read_u8().await.unwrap());
                }
                assert!(head.starts_with(b"GET /ci HTTP/1."));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let curl = if cfg!(windows) { "curl.exe" } else { "curl" };
        for (proxy, tunnel) in [
            (format!("http://{http}"), true),
            (format!("socks5h://{socks}"), false),
        ] {
            let url = format!("http://localhost:{port}/ci");
            let output = tokio::task::spawn_blocking(move || {
                let mut command = std::process::Command::new(curl);
                command
                    .args(["--disable", "--fail", "--silent", "--show-error"])
                    .args(["--max-time", "15", "--noproxy", "", "--proxy", &proxy]);
                if tunnel {
                    command.arg("--proxytunnel");
                }
                command.arg(url).output().expect("CI must provide curl")
            })
            .await
            .unwrap();
            assert!(
                output.status.success(),
                "H3 curl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, body);
        }
        origin.await.unwrap();
        assert!(client.0.try_wait().unwrap().is_none());
        assert!(server.0.try_wait().unwrap().is_none());
        drop(client);
        drop(server);
    })
    .await
    .expect("H3 executable E2E deadline");
}

async fn auto_connect(proxy: std::net::SocketAddr, port: u16) -> String {
    // Binding both listeners does not imply Windows/Linux has already
    // published the HTTP accept loop. A transient local ConnectionRefused
    // during fixture startup must not fail this *transport policy* test.
    // Keep the retry strictly on the local TCP handshake; never retry an
    // H3 TLS, bearer or OPEN denial through H2.
    let mut socket = timeout(Duration::from_secs(3), async {
        loop {
            match TcpStream::connect(proxy).await {
                Ok(stream) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("local HTTP proxy connection failed: {error}"),
            }
        }
    })
    .await
    .expect("local HTTP listener must become reachable within 3 seconds");
    socket
        .write_all(
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    response_head(&mut socket).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_falls_back_only_after_udp_silence_and_uses_negative_cache() {
    timeout(Duration::from_secs(25), async {
        // Reserve an available UDP port first, then bind the TCP server to
        // that *same* port. On Windows a random TCP ephemeral port may be
        // excluded for UDP (WSAEACCES/10013), so blind second bind is flaky.
        let mut pair = None;
        for _ in 0..64 {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                pair = Some((udp, tcp));
                break;
            }
        }
        let (udp, tcp) = pair.expect("native CI must provide one shared TCP/UDP loopback port");
        let (endpoint, _roots, pem, server) = listener_with_pem_bound(true, tcp);
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = probes.clone();
        let blackhole = tokio::spawn(async move {
            let mut data = [0; 2048];
            loop {
                udp.recv_from(&mut data).await.unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Deliberately never return any datagram.
            }
        });
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut tcp, _) = target.accept().await.unwrap();
                tcp.shutdown().await.unwrap();
            }
        });
        let (_dir, _child, http, _socks) = launch_client(
            endpoint,
            pem,
            "auto-blackhole",
            theia::config::Transport::Auto,
        )
        .await;
        assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 200 "));
        let first = probes.load(std::sync::atomic::Ordering::SeqCst);
        assert!(first > 0, "auto must actually attempt QUIC before H2");
        assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 200 "));
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            first,
            "negative cache must suppress a new UDP handshake"
        );
        origin.await.unwrap();
        blackhole.abort();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_wrong_h3_certificate_never_retries_working_h2() {
    timeout(Duration::from_secs(20), async {
        let (endpoint, _roots, pem, server) = listener_with_pem(true).await;
        // H2 is trusted by the CLI fixture. H3 uses a different certificate
        // with the same SAN, so only chain validation distinguishes it.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let udp = theia::quic_transport::server_endpoint(
            endpoint.parse().unwrap(),
            vec![der],
            key.into(),
        )
        .unwrap();
        let quic = tokio::spawn(async move {
            let incoming = udp.accept().await.unwrap();
            assert!(theia::quic_transport::accept(incoming).await.is_err());
        });
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (_dir, _child, http, _socks) = launch_client(
            endpoint,
            pem,
            "auto-untrusted",
            theia::config::Transport::Auto,
        )
        .await;
        assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 502 "));
        quic.await.unwrap();
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_denied_h3_bearer_never_retries_working_h2() {
    timeout(Duration::from_secs(20), async {
        // One certificate trusted by both transports, with different test
        // inbound grants so a forbidden H3 request would succeed over H2.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.clone_key().into())
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        // Random Windows TCP ephemeral ports are not necessarily available
        // for UDP/QUIC (WSAEACCES/10013). Keep both real sockets reserved
        // before starting either transport, retrying only local port choice.
        let mut pair = None;
        for _ in 0..64 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let remote = listener.local_addr().unwrap();
            if let Ok(udp) = theia::quic_transport::server_endpoint(
                remote,
                vec![der.clone()],
                key.clone_key().into(),
            ) {
                pair = Some((listener, remote, udp));
                break;
            }
        }
        let (listener, remote, udp) =
            pair.expect("CI must provide a TCP/QUIC port available on native OS");
        let mut inbound = Inbound {
            id: "h2-test".into(),
            allowed_user_ids: vec!["client".into()],
            h2_listen: remote.to_string(),
            quic_listen: remote.to_string(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            security_mode: Default::default(),
            tls_key: "unused".into(),
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        };
        let policy = ServerPolicy {
            allow_private_ips: true,
            max_connections_per_user: 8,
            max_connections_total: 8,
            connect_timeout_ms: 1500,
        };
        let h2_context = Arc::new(ServerContext::new(
            &inbound,
            std::slice::from_ref(&user),
            &policy,
        ));
        inbound.allowed_user_ids.clear();
        let h3_context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
        let h2 = tokio::spawn(serve(
            listener,
            TlsAcceptor::from(Arc::new(tls)),
            h2_context,
        ));
        let h3 = tokio::spawn(theia::h3_server::serve(udp, h3_context));
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (_dir, _child, http, _socks) = launch_client(
            remote.to_string(),
            cert.cert.pem(),
            "auto-denied",
            theia::config::Transport::Auto,
        )
        .await;
        assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 403 "));
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        h2.abort();
        h3.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_auto_rejects_wrong_trusted_h3_pin_and_falls_back_only_on_udp_silence() {
    use theia::security_profile::{CertificatePin, SecurityMode};
    timeout(Duration::from_secs(35), async {
        let mut pair = None;
        for _ in 0..64 {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                pair = Some((udp, tcp));
                break;
            }
        }
        let (reserved, tcp) = pair.expect("shared native port");
        let (endpoint, _roots, pem, server) =
            listener_with_pem_bound_mode(true, tcp, SecurityMode::PinnedCertV1);
        let pin = CertificatePin::from_der(
            rustls_pemfile::certs(&mut pem.as_bytes())
                .next()
                .unwrap()
                .unwrap()
                .as_ref(),
        );
        let profile = pin.profile();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();

        // Prove the fallback branch is a working pinned H2 endpoint.
        let blackhole = tokio::spawn(async move {
            let mut buf = [0; 2048];
            loop {
                reserved.recv_from(&mut buf).await.unwrap();
            }
        });
        {
            let (_dir, _child, http, _) = launch_client_with_profile(
                endpoint.clone(),
                pem.clone(),
                "pinned-auto-silence",
                theia::config::Transport::Auto,
                &profile,
            )
            .await;
            assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 200 "));
            let (mut socket, _) = target.accept().await.unwrap();
            socket.shutdown().await.unwrap();
        }
        blackhole.abort();
        let _ = blackhole.await;

        // Both certs trusted and same hostname, but only H2 is pinned. The
        // QUIC handshake must succeed and its wrong pin must be terminal.
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let udp = theia::quic_transport::server_endpoint(
            endpoint.parse().unwrap(),
            vec![other.cert.der().clone()],
            PrivatePkcs8KeyDer::from(other.key_pair.serialize_der()).into(),
        )
        .unwrap();
        // A fully functional H3 endpoint: skipping the pin would cause
        // a real target dial and HTTP 200, not just a transport timeout.
        let inbound = Inbound {
            id: "test".into(),
            security_mode: SecurityMode::PinnedCertV1,
            allowed_user_ids: vec!["client".into()],
            h2_listen: endpoint.clone(),
            quic_listen: endpoint.clone(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            tls_key: "unused".into(),
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        };
        let policy = ServerPolicy {
            allow_private_ips: true,
            max_connections_per_user: 8,
            max_connections_total: 8,
            connect_timeout_ms: 2000,
        };
        let quic = tokio::spawn(theia::h3_server::serve(
            udp,
            Arc::new(ServerContext::new(&inbound, &[user], &policy)),
        ));
        let combined = format!("{pem}\n{}", other.cert.pem());
        let (_dir, _child, http, _) = launch_client_with_profile(
            endpoint,
            combined,
            "pinned-auto-wrong-pin",
            theia::config::Transport::Auto,
            &profile,
        )
        .await;
        assert!(auto_connect(http, port).await.starts_with("HTTP/1.1 502 "));
        assert!(
            timeout(Duration::from_millis(250), target.accept())
                .await
                .is_err(),
            "wrong H3 pin must not dial using H2"
        );
        quic.abort();
        server.abort();
    })
    .await
    .expect("bounded binary pinned auto policy");
}
