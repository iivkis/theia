//! Opt-in two-host, release-profile transport benchmark. No bearer,
//! arbitrary destination relay, production activation or pass thresholds.
use bytes::{Buf, Bytes};
use h3::quic;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::{
    fs::File,
    future::poll_fn,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use theia::quic_core::{
    h3_adapter::NativeConnection,
    handshake_udp::{self, Congestion},
    listener::Listener,
    negotiation::VersionPolicy,
    scope::NetworkScope,
    wire::Version,
};
use tokio::net::UdpSocket;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const CHUNK: usize = 32 * 1024;

fn native_backend(backend: &str) -> (Version, Congestion) {
    match backend {
        "native-v1" => (Version::V1, Congestion::Bbr),
        "native-v2" => (Version::V2, Congestion::Bbr),
        "native-cubic-v1" => (Version::V1, Congestion::Cubic),
        "native-cubic-v2" => (Version::V2, Congestion::Cubic),
        _ => panic!("invalid native backend"),
    }
}

fn wall_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn certificates(path: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    for cert in certificates(&env("THEIA_BENCH_CA")) {
        store.add(cert).unwrap();
    }
    assert!(!store.is_empty());
    store
}

fn native_tls(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

async fn echo<C>(connection: C, limit: usize)
where
    C: quic::Connection<Bytes> + 'static,
    C::BidiStream: quic::BidiStream<Bytes>,
{
    let mut server = h3::server::builder()
        .build::<_, Bytes>(connection)
        .await
        .unwrap();
    let resolver = server.accept().await.unwrap().unwrap();
    let (request, mut stream) = resolver.resolve_request().await.unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), "/transport-benchmark");
    let mut body = Vec::new();
    while let Some(mut buf) = stream.recv_data().await.unwrap() {
        assert!(body.len().saturating_add(buf.remaining()) <= limit);
        body.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
    }
    assert_eq!(body.len(), limit);
    stream
        .send_response(http::Response::builder().status(200).body(()).unwrap())
        .await
        .unwrap();
    for chunk in body.chunks(CHUNK) {
        stream
            .send_data(Bytes::copy_from_slice(chunk))
            .await
            .unwrap();
    }
    stream.finish().await.unwrap();
    drop(stream);
    // Client verifies exact bytes and closes. No second request or relay.
    let _ = tokio::time::timeout(Duration::from_secs(3), server.accept()).await;
}

async fn exchange<C>(connection: C, payload: &[u8]) -> (u128, u128, u128, u128)
where
    C: quic::Connection<Bytes> + 'static,
    C::BidiStream: quic::BidiStream<Bytes>,
{
    let start = Instant::now();
    let (mut driver, mut sender) = h3::client::new(connection).await.unwrap();
    let request = async {
        let mut stream = sender
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri("https://benchmark.invalid/transport-benchmark")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        let opened = start.elapsed().as_micros().max(1);
        let start = Instant::now();
        let wall_start = wall_ns();
        for chunk in payload.chunks(CHUNK) {
            stream
                .send_data(Bytes::copy_from_slice(chunk))
                .await
                .unwrap();
        }
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut offset = 0;
        while let Some(mut buf) = stream.recv_data().await.unwrap() {
            let data = buf.copy_to_bytes(buf.remaining());
            let end = offset + data.len();
            assert_eq!(payload.get(offset..end), Some(data.as_ref()));
            offset = end;
        }
        assert_eq!(offset, payload.len());
        let relay = start.elapsed().as_micros().max(1);
        (opened, relay, wall_start, wall_ns())
    };
    tokio::pin!(request);
    tokio::select! {
        biased;
        result = &mut request => result,
        error = poll_fn(|cx| driver.poll_close(cx)) => panic!("H3 driver closed during benchmark: {error:?}"),
    }
}

async fn server(backend: &str, bind: SocketAddr, peer: IpAddr, count: usize, size: usize) {
    let certs = certificates(&env("THEIA_BENCH_CERT"));
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(env("THEIA_BENCH_KEY")).unwrap(),
    ))
    .unwrap()
    .unwrap();
    if backend == "quinn" {
        let endpoint = theia::quic_transport::server_endpoint(bind, certs, key).unwrap();
        println!("BENCH_READY");
        for _ in 0..count {
            let incoming = loop {
                let incoming = endpoint.accept().await.unwrap();
                if incoming.remote_address().ip() == peer {
                    break incoming;
                }
                incoming.refuse();
            };
            let connection = theia::quic_transport::accept(incoming).await.unwrap();
            echo(h3_quinn::Connection::new(connection), size).await;
        }
        endpoint.close(0u32.into(), b"benchmark complete");
        endpoint.wait_idle().await;
    } else {
        let mut tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.send_tls13_tickets = 0;
        let (version, congestion) = native_backend(backend);
        let scope = NetworkScope::pinned([bind.ip(); 2], [peer; 2]).unwrap();
        let mut listener = Listener::with_scope(
            UdpSocket::bind(bind).await.unwrap(),
            8,
            VersionPolicy::exact(version),
            scope,
        )
        .unwrap();
        println!("BENCH_READY");
        let tls = Arc::new(tls);
        for _ in 0..count {
            let session = handshake_udp::accept_with_congestion(
                listener.accept().await.unwrap(),
                tls.clone(),
                congestion,
            )
            .await
            .unwrap();
            let (connection, _) = NativeConnection::start(session).unwrap();
            echo(connection, size).await;
        }
    }
    println!("BENCH_COMPLETE,{count}");
}

async fn client(backend: &str, bind: SocketAddr, peer: SocketAddr, count: usize, size: usize) {
    let name = env("THEIA_BENCH_NAME");
    let roots = roots();
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    for sample in 0..count {
        let start = Instant::now();
        let (handshake, opened, relay, wall_start, wall_end) = if backend == "quinn" {
            let endpoint = theia::quic_transport::client_endpoint(bind, roots.clone()).unwrap();
            let connection = theia::quic_transport::connect(&endpoint, peer, &name)
                .await
                .unwrap();
            let elapsed = start.elapsed().as_micros().max(1);
            let (opened, relay, wall_start, wall_end) =
                exchange(h3_quinn::Connection::new(connection), &data).await;
            endpoint.close(0u32.into(), b"benchmark complete");
            endpoint.wait_idle().await;
            (elapsed, opened, relay, wall_start, wall_end)
        } else {
            let (version, congestion) = native_backend(backend);
            let scope = NetworkScope::pinned([bind.ip(); 2], [peer.ip(); 2]).unwrap();
            let (actual, session) = handshake_udp::connect_versions_scoped_with_congestion(
                bind,
                peer,
                VersionPolicy::exact(version),
                native_tls(roots.clone()),
                ServerName::try_from(name.clone()).unwrap(),
                scope,
                congestion,
            )
            .await
            .unwrap();
            assert_eq!(actual, version);
            let elapsed = start.elapsed().as_micros().max(1);
            let (connection, _) = NativeConnection::start(session).unwrap();
            let (opened, relay, wall_start, wall_end) = exchange(connection, &data).await;
            (elapsed, opened, relay, wall_start, wall_end)
        };
        println!("BENCH_SAMPLE,{backend},{sample},{size},{handshake},{opened},{relay},{wall_start},{wall_end}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicitly provisioned two-host transport benchmark"]
async fn native_quic_two_host_release() {
    assert!(!cfg!(debug_assertions), "use the release test executable");
    let backend = env("THEIA_BENCH_BACKEND");
    assert!(matches!(
        backend.as_str(),
        "quinn" | "native-v1" | "native-v2" | "native-cubic-v1" | "native-cubic-v2"
    ));
    let role = env("THEIA_BENCH_ROLE");
    let bind: SocketAddr = env("THEIA_BENCH_BIND").parse().unwrap();
    let peer: SocketAddr = env("THEIA_BENCH_PEER").parse().unwrap();
    assert!(!bind.ip().is_unspecified() && !bind.ip().is_loopback() && !peer.ip().is_loopback());
    assert_ne!(bind.ip(), peer.ip());
    assert_eq!(bind.is_ipv4(), peer.is_ipv4());
    let count: usize = env("THEIA_BENCH_SAMPLES").parse().unwrap();
    let size: usize = env("THEIA_BENCH_BYTES").parse().unwrap();
    assert!((1..=100).contains(&count) && (1..=MAX_BYTES).contains(&size));
    tokio::time::timeout(Duration::from_secs(3600), async {
        if role == "server" {
            assert_ne!(bind.port(), 0);
            server(&backend, bind, peer.ip(), count, size).await;
        } else {
            assert_eq!(role, "client");
            assert_eq!(bind.port(), 0);
            assert_ne!(peer.port(), 0);
            client(&backend, bind, peer, count, size).await;
        }
    })
    .await
    .unwrap();
}
