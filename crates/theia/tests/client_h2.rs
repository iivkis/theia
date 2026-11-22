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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

async fn launch_client(
    endpoint: String,
    pem: String,
    label: &str,
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
    profile.transport = theia::config::Transport::H2;
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

/// Black-box curl tests run on both native CI runners. No external service,
/// installed system proxy, manually provisioned key or interactive setup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_binary_curl_connect_and_socks5h() {
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
        let (_dir, mut child, http, socks) = launch_client(endpoint, pem, "curl").await;

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
    timeout(Duration::from_secs(75), async {
        let (endpoint, _roots, pem, server) = listener_with_pem(true).await;
        let (_dir, mut child, _http, socks) = launch_client(endpoint, pem, "browser").await;
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
