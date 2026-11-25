//! Independent loopback HTTP peers exercise real graceful GOAWAY frames,
//! not a mocked pool predicate. The production client must preserve already
//! admitted streams and obtain a fresh carrier for subsequent OPEN.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::{Buf, Bytes};
use http::{Request, Response};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{collections::HashMap, sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    h3_client::H3Client,
    protocol::{self, Address, Decoder, Frame},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];
const TARGET: u16 = 12345;

fn check_request<T>(request: &Request<T>, split: bool) -> Option<(u32, bool)> {
    assert_eq!(request.headers()["authorization"].to_str().unwrap(), format!("Bearer {}", URL_SAFE_NO_PAD.encode(TOKEN)));
    if !split {
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/v1/theia-example/session");
        return None;
    }
    let upload = match request.uri().path() {
        "/v1/theia-example/stream-up/upload" => {
            assert_eq!(request.method(), http::Method::POST);
            true
        }
        "/v1/theia-example/stream-up/download" => {
            assert_eq!(request.method(), http::Method::GET);
            false
        }
        _ => panic!("unexpected split route"),
    };
    let id = request.headers()["theia-pair-id"].to_str().unwrap().parse::<u32>().unwrap();
    assert!(id > 0);
    Some((id, upload))
}

// One independent pair map per physical HTTP connection. Never correlate
// legs from distinct connections, including the GOAWAY replacement.
fn pair<T>(pending: &mut HashMap<u32, (bool, T)>, id: u32, upload: bool, leg: T) -> Option<(T, T)> {
    if let Some((previous_upload, previous)) = pending.remove(&id) {
        assert_ne!(previous_upload, upload);
        Some(if upload { (leg, previous) } else { (previous, leg) })
    } else {
        assert!(pending.insert(id, (upload, leg)).is_none());
        None
    }
}

#[derive(Default)]
struct Echo {
    stage: u8,
    decoder: Decoder,
}
impl Echo {
    fn reply(&mut self, frame: Frame) -> Frame {
        match (self.stage, frame) {
            (0, Frame::Hello { version: protocol::VERSION, .. }) => {
                self.stage = 1;
                Frame::HelloAck { version: protocol::VERSION, accepted_capabilities: 0 }
            }
            (1, Frame::OpenTcp { address: Address::V4([127, 0, 0, 1]), port: TARGET }) => {
                self.stage = 2;
                Frame::OpenOk
            }
            (2, Frame::Data(bytes)) => Frame::Data(bytes),
            (2, Frame::Fin) => {
                self.stage = 3;
                Frame::Fin
            }
            (_, frame) => panic!("unexpected fixture frame: {frame:?}"),
        }
    }
    fn finish(&mut self) {
        assert_eq!(self.stage, 3);
        self.decoder.finish().unwrap();
    }
}

type H2Leg = (Request<h2::RecvStream>, h2::server::SendResponse<Bytes>);
async fn h2_echo((request, mut respond): H2Leg, down: Option<H2Leg>) {
    let mut incoming = request.into_body();
    let mut outgoing = if let Some((download, mut down)) = down {
        let mut empty = download.into_body();
        assert!(empty.data().await.is_none());
        assert!(empty.trailers().await.unwrap().is_none());
        respond.send_response(Response::builder().status(200).body(()).unwrap(), true).unwrap();
        down.send_response(Response::builder().status(200).body(()).unwrap(), false).unwrap()
    } else {
        respond.send_response(Response::builder().status(200).body(()).unwrap(), false).unwrap()
    };
    let mut echo = Echo::default();
    while let Some(chunk) = incoming.data().await {
        let chunk = chunk.unwrap();
        let size = chunk.len();
        for frame in echo.decoder.feed(&chunk).unwrap() {
            let reply = echo.reply(frame);
            // Test data fits the initial HTTP/2 window; actual wire framing
            // and flow-credit release still use the native h2 implementation.
            outgoing.send_data(Bytes::from(protocol::encode(&reply).unwrap()), false).unwrap();
        }
        incoming.flow_control().release_capacity(size).unwrap();
    }
    assert!(incoming.trailers().await.unwrap().is_none());
    echo.finish();
    outgoing.send_data(Bytes::new(), true).unwrap();
}

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3Leg = (Request<()>, H3Stream);
async fn h3_echo((_request, mut stream): H3Leg, down: Option<H3Leg>) {
    let (mut tx, mut rx) = if let Some((_download, mut down)) = down {
        assert!(down.recv_data().await.unwrap().is_none());
        assert!(down.recv_trailers().await.unwrap().is_none());
        stream.send_response(Response::builder().status(200).body(()).unwrap()).await.unwrap();
        stream.finish().await.unwrap();
        down.send_response(Response::builder().status(200).body(()).unwrap()).await.unwrap();
        let (_, rx) = stream.split();
        let (tx, _) = down.split();
        (tx, rx)
    } else {
        stream.send_response(Response::builder().status(200).body(()).unwrap()).await.unwrap();
        stream.split()
    };
    let mut echo = Echo::default();
    while let Some(mut chunk) = rx.recv_data().await.unwrap() {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        for frame in echo.decoder.feed(&bytes).unwrap() {
            let reply = echo.reply(frame);
            tx.send_data(Bytes::from(protocol::encode(&reply).unwrap())).await.unwrap();
        }
    }
    assert!(rx.recv_trailers().await.unwrap().is_none());
    echo.finish();
    tx.finish().await.unwrap();
}

type Drain = (oneshot::Receiver<()>, oneshot::Sender<()>);

async fn h2_peer(listener: TcpListener, acceptor: TlsAcceptor, drain: Drain, requests: mpsc::UnboundedSender<usize>, split: bool) {
    let mut connections = JoinSet::new();
    let mut drain = Some(drain);
    // Exactly two physical connections: two admitted streams on the first,
    // then one on the replacement. Unexpected requests fail the assertion.
    for index in 0..2 {
        let (tcp, _) = listener.accept().await.unwrap();
        let acceptor = acceptor.clone();
        let requests = requests.clone();
        let mut command = drain.take();
        connections.spawn(async move {
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let mut handlers = JoinSet::new();
            let mut pending = HashMap::new();
            let mut accepted = 0;
            let expected = if index == 0 { 2 } else { 1 };
            loop {
                tokio::select! {
                    biased;
                    _ = async { (&mut command.as_mut().unwrap().0).await.unwrap(); }, if command.is_some() => {
                        assert_eq!(accepted, expected);
                        assert!(pending.is_empty());
                        connection.graceful_shutdown();
                        command.take().unwrap().1.send(()).unwrap();
                    }
                    result = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap().unwrap();
                        if accepted == expected && handlers.is_empty() {
                            connection.graceful_shutdown();
                        }
                    }
                    request = connection.accept() => match request {
                        Some(Ok((request, respond))) => {
                            assert!(accepted < expected, "new stream on retired H2 carrier");
                            let kind = check_request(&request, split);
                            let leg = (request, respond);
                            if let Some((id, upload)) = kind {
                                if let Some((up, down)) = pair(&mut pending, id, upload, leg) {
                                    accepted += 1;
                                    requests.send(index).unwrap();
                                    handlers.spawn(h2_echo(up, Some(down)));
                                }
                            } else {
                                accepted += 1;
                                requests.send(index).unwrap();
                                handlers.spawn(h2_echo(leg, None));
                            }
                        }
                        Some(Err(error)) => panic!("H2 fixture connection: {error}"),
                        None => break,
                    }
                }
            }
            assert_eq!(accepted, expected);
            assert!(pending.is_empty());
            while let Some(result) = handlers.join_next().await { result.unwrap(); }
        });
    }
    while let Some(result) = connections.join_next().await { result.unwrap(); }
}

async fn h3_peer(endpoint: quinn::Endpoint, drain: Drain, requests: mpsc::UnboundedSender<usize>, split: bool) {
    let mut connections = JoinSet::new();
    let mut drain = Some(drain);
    for index in 0..2 {
        let incoming = endpoint.accept().await.unwrap();
        let requests = requests.clone();
        let mut command = drain.take();
        connections.spawn(async move {
            let quic = theia::quic_transport::accept(incoming).await.unwrap();
            let mut connection = h3::server::Connection::new(h3_quinn::Connection::new(quic.clone())).await.unwrap();
            let mut handlers = JoinSet::new();
            let mut pending = HashMap::new();
            let mut accepted = 0;
            let expected = if index == 0 { 2 } else { 1 };
            loop {
                tokio::select! {
                    biased;
                    _ = async { (&mut command.as_mut().unwrap().0).await.unwrap(); }, if command.is_some() => {
                        assert_eq!(accepted, expected);
                        assert!(pending.is_empty());
                        connection.shutdown(0).await.unwrap();
                        command.take().unwrap().1.send(()).unwrap();
                    }
                    result = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap().unwrap();
                        if accepted == expected && handlers.is_empty() {
                            // Client finishes both wire directions before
                            // its leases/endpoint are dropped.
                            break;
                        }
                    }
                    request = connection.accept() => match request {
                        Ok(Some(resolver)) => {
                            let (request, stream) = resolver.resolve_request().await.unwrap();
                            assert!(accepted < expected, "new stream on retired H3 carrier");
                            let kind = check_request(&request, split);
                            let leg = (request, stream);
                            if let Some((id, upload)) = kind {
                                if let Some((up, down)) = pair(&mut pending, id, upload, leg) {
                                    accepted += 1;
                                    requests.send(index).unwrap();
                                    handlers.spawn(h3_echo(up, Some(down)));
                                }
                            } else {
                                accepted += 1;
                                requests.send(index).unwrap();
                                handlers.spawn(h3_echo(leg, None));
                            }
                        }
                        Ok(None) => break,
                        Err(error) => panic!("H3 fixture connection: {error}"),
                    }
                }
            }
            assert_eq!(accepted, expected);
            assert!(pending.is_empty());
            while let Some(result) = handlers.join_next().await { result.unwrap(); }
            // Wait for the client to release its final lease rather than
            // closing QUIC ahead of delivery of the last response FIN.
            let _ = timeout(Duration::from_secs(3), quic.closed()).await;
        });
    }
    while let Some(result) = connections.join_next().await { result.unwrap(); }
}

async fn exchange(app: &mut DuplexStream, bytes: &[u8]) {
    app.write_all(bytes).await.unwrap();
    let mut actual = vec![0; bytes.len()];
    app.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, bytes);
}
async fn finish(mut app: DuplexStream, relay: JoinHandle<Result<(), ClientError>>) {
    app.shutdown().await.unwrap();
    let mut tail = Vec::new();
    app.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
    relay.await.unwrap().unwrap();
}

macro_rules! assert_drain {
    ($client:expr, $requests:expr, $drain:expr, $sent:expr) => {{
        let client = $client;
        let address = Address::V4([127, 0, 0, 1]);
        let first = client.open(address.clone(), TARGET).await.unwrap();
        let second = client.open(address.clone(), TARGET).await.unwrap();
        assert!(first.shares_transport_with(&second), "precondition: real connection reuse");
        assert_eq!($requests.recv().await, Some(0));
        assert_eq!($requests.recv().await, Some(0));
        let (mut left, first_io) = tokio::io::duplex(4096);
        let (mut right, second_io) = tokio::io::duplex(4096);
        let first_relay = tokio::spawn(first.relay(first_io));
        let second_relay = tokio::spawn(second.relay(second_io));
        exchange(&mut left, b"before goaway").await;
        $drain.send(()).unwrap();
        $sent.await.unwrap();
        // Drive real application traffic after the peer initiated GOAWAY.
        // In H2 the native graceful shutdown includes a PING round-trip;
        // allow this bounded loopback control exchange to complete.
        exchange(&mut left, b"after goaway").await;
        exchange(&mut right, b"second live stream").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let replacement = client.open(address, TARGET).await.unwrap();
        assert_eq!($requests.recv().await, Some(1));
        let (mut fresh, fresh_io) = tokio::io::duplex(4096);
        let fresh_relay = tokio::spawn(replacement.relay(fresh_io));
        exchange(&mut fresh, b"new verified connection").await;
        exchange(&mut left, b"old still live").await;
        exchange(&mut right, b"parallel old still live").await;
        tokio::join!(finish(left, first_relay), finish(right, second_relay), finish(fresh, fresh_relay));
        drop(client);
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_h2_goaway_drains_live_streams_without_reusing_carrier() {
    timeout(Duration::from_secs(18), async {
        tokio::join!(h2_scenario(false), h2_scenario(true));
    }).await.expect("bounded native H2 GOAWAY matrix");
}

async fn h2_scenario(split: bool) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into()).unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (drain, command) = oneshot::channel();
        let (sent, ack) = oneshot::channel();
        let (witness, mut requests) = mpsc::unbounded_channel();
        let peer = tokio::spawn(h2_peer(listener, TlsAcceptor::from(Arc::new(tls)), (command, sent), witness, split));
        let client = H2Client::new(&address.to_string(), "localhost", &URL_SAFE_NO_PAD.encode(TOKEN), roots).unwrap().with_stream_up(split).unwrap().with_connection_pool();
        assert_drain!(client, requests, drain, ack);
        peer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_h3_goaway_drains_live_streams_without_reusing_carrier() {
    timeout(Duration::from_secs(18), async {
        tokio::join!(h3_scenario(false), h3_scenario(true));
    }).await.expect("bounded native H3 GOAWAY matrix");
}

async fn h3_scenario(split: bool) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let endpoint = theia::quic_transport::server_endpoint("127.0.0.1:0".parse().unwrap(),
            vec![certificate.cert.der().clone()], PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let (drain, command) = oneshot::channel();
        let (sent, ack) = oneshot::channel();
        let (witness, mut requests) = mpsc::unbounded_channel();
        let peer = tokio::spawn(h3_peer(endpoint, (command, sent), witness, split));
        let client = H3Client::new(address, "localhost", &URL_SAFE_NO_PAD.encode(TOKEN), roots).unwrap().with_stream_up(split).unwrap().with_connection_pool();
        assert_drain!(client, requests, drain, ack);
        peer.await.unwrap();
}
