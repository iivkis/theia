//! Independent aioquic 1.2.0 against the native QUIC laboratory, both
//! directions and both versions. This is not a production admission test.
#[path = "support/private_pem.rs"]
mod private_pem;

use bytes::{Buf, Bytes};
use rustls::{pki_types::{PrivatePkcs8KeyDer, ServerName}, ClientConfig, RootCertStore, ServerConfig};
use std::{fs, future::poll_fn, net::SocketAddr, path::{Path, PathBuf}, process::{Child, Command}, sync::Arc, time::Duration};
use theia::quic_core::{h3_adapter::NativeConnection, handshake_udp, listener::Listener, wire::Version};
use tokio::net::UdpSocket;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Fixture(Child);
impl Drop for Fixture {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

fn python() -> Command {
    let mut cmd = Command::new("python");
    cmd.arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/e2e/independent_quic_core.py"));
    cmd
}

async fn wait_success(child: &mut Fixture) {
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "independent peer failed");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn native_client(addr: SocketAddr, version: Version, tls: Arc<ClientConfig>, name: &str) -> Result<theia::quic_core::endpoint::LabSession, handshake_udp::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    handshake_udp::connect(socket, addr, version, tls, ServerName::try_from(name.to_owned()).unwrap()).await
}

async fn native_request(session: theia::quic_core::endpoint::LabSession) {
    let (connection, _) = NativeConnection::start(session).unwrap();
    let (mut driver, mut sender) = h3::client::new(connection).await.unwrap();
    let driver = tokio::spawn(async move { let _ = poll_fn(|cx| driver.poll_close(cx)).await; });
    let mut request = sender.send_request(http::Request::builder().method("POST").uri("https://localhost/interop").body(()).unwrap()).await.unwrap();
    request.send_data(Bytes::from_static(b"independent request")).await.unwrap();
    request.finish().await.unwrap();
    assert_eq!(request.recv_response().await.unwrap().status(), 200);
    let mut body = Vec::new();
    while let Some(mut buf) = request.recv_data().await.unwrap() {
        body.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
    }
    assert_eq!(body, b"independent response");
    drop(request);
    drop(sender);
    driver.abort();
}

async fn native_response(session: theia::quic_core::endpoint::LabSession) {
    let (connection, _) = NativeConnection::start(session).unwrap();
    let mut server = h3::server::builder().build::<_, Bytes>(connection).await.unwrap();
    let resolver = server.accept().await.unwrap().unwrap();
    let (req, mut stream) = resolver.resolve_request().await.unwrap();
    assert_eq!(req.method(), http::Method::POST);
    assert_eq!(req.uri().path(), "/interop");
    let mut body = Vec::new();
    while let Some(mut buf) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
    }
    assert_eq!(body, b"independent request");
    stream.send_response(http::Response::builder().status(200).body(()).unwrap()).await.unwrap();
    stream.send_data(Bytes::from_static(b"independent response")).await.unwrap();
    stream.finish().await.unwrap();
    // Keep the connection alive and continue driving H3 until peer closure.
    drop(stream);
    let _ = server.accept().await;
}

fn configs(path: &Path) -> (Arc<ClientConfig>, Arc<ClientConfig>, Arc<ServerConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(path.join("cert.pem"), cert.cert.pem()).unwrap();
    private_pem::write_new_key(&path.join("key.pem"), cert.key_pair.serialize_pem());
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = |roots| {
        let mut cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        Arc::new(cfg)
    };
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into()).unwrap();
    server.alpn_protocols = vec![b"h3".to_vec()];
    server.send_tls13_tickets = 0;
    (client(roots), client(RootCertStore::empty()), Arc::new(server))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned independent aioquic from browser-e2e CI"]
async fn independent_aioquic_v1_v2_bidirectional_h3() {
    let scratch = Scratch(std::env::temp_dir().join(format!("theia-quic-core-interop-{}", std::process::id())));
    fs::create_dir(&scratch.0).unwrap();
    tokio::time::timeout(Duration::from_secs(55), async {
        let (trusted, wrong, tls) = configs(&scratch.0);
        let mut peer = Fixture(python().arg("serve").arg(&scratch.0).spawn().unwrap());
        let ports = loop {
            if let Ok(raw) = fs::read_to_string(scratch.0.join("ready")) {
                break raw.lines().map(|line| line.parse::<u16>().unwrap()).collect::<Vec<_>>();
            }
            assert!(peer.0.try_wait().unwrap().is_none(), "reference server exited before readiness");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(ports.len(), 2);
        for (i, version) in [Version::V1, Version::V2].into_iter().enumerate() {
            let addr = SocketAddr::from(([127, 0, 0, 1], ports[i]));
            assert!(native_client(addr, version, wrong.clone(), "localhost").await.is_err());
            assert!(native_client(addr, version, trusted.clone(), "wrong.example").await.is_err());
            native_request(native_client(addr, version, trusted.clone(), "localhost").await.unwrap()).await;

            let mut listener = Listener::new(UdpSocket::bind("127.0.0.1:0").await.unwrap(), 4).unwrap();
            let port = listener.local_addr().port();
            let mut client = Fixture(python().arg("client").arg(&scratch.0).arg(port.to_string()).arg((i+1).to_string()).spawn().unwrap());
            let session = handshake_udp::accept(listener.accept().await.unwrap(), tls.clone()).await.unwrap();
            let task = tokio::spawn(native_response(session));
            wait_success(&mut client).await;
            task.abort();
            let _ = task.await;
        }
        fs::write(scratch.0.join("done"), b"done").unwrap();
        wait_success(&mut peer).await;
    }).await.expect("independent v1/v2 matrix deadline");
}
