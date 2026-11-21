//! Deterministic synthetic UDP transmit loss over real Quinn QUIC/TLS.
//! This is a recovery/telemetry smoke test, NOT a throughput or BBR fairness benchmark.
//! No OS-wide network settings, privileged netem, external servers, or unsafe TLS verifiers.
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, UdpPoller,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use theia_m0_1_feasibility::{configure_client_bbr, configure_server_bbr};

const ALPN: &[u8] = b"theia-bbr-loss-spike";
const PAYLOAD_LEN: usize = 768 * 1024;
const CHUNK_SIZE: usize = 4096;

/// Wrap Quinn's actual UDP socket. Once armed, every Nth attempted UDP transmit
/// is silently dropped with an Ok return, exactly as a real network loss would
/// appear to the QUIC sender. This counts *transmits*, not every QUIC packet.
/// A max_transmit_segments of 1 disables UDP GSO to make each dropped attempt
/// correspond to one datagram. No sleeps or random number generators involved.
#[derive(Debug)]
struct DeterministicLoss {
    inner: Arc<dyn AsyncUdpSocket>,
    drop_every: u64,
    armed: AtomicBool,
    attempts: AtomicU64,
    dropped: AtomicU64,
}

impl DeterministicLoss {
    fn new(inner: Arc<dyn AsyncUdpSocket>, drop_every: u64) -> Self {
        Self {
            inner,
            drop_every,
            armed: AtomicBool::new(false),
            attempts: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

impl AsyncUdpSocket for DeterministicLoss {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if self.armed.load(Ordering::Relaxed) {
            let sequence = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            if self.drop_every > 0 && sequence % self.drop_every == 0 {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // Intentionally disable UDP GSO for deterministic one-datagram drops.
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct Sample {
    drop_every: u64,
    attempted_datagrams: u64,
    dropped_datagrams: u64,
    sent_packets: u64,
    lost_packets: u64,
    congestion_events: u64,
    rtt: Duration,
    elapsed: Duration,
}

/// Build a real TLS 1.3 QUIC connection with ordinary certificate verification.
fn endpoints(drop_every: u64) -> (Endpoint, Endpoint, SocketAddr, Arc<DeterministicLoss>) {
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
    let cert = identity.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der());

    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 supported")
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .expect("test server identity");
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).expect("QUIC TLS config"),
    ));
    configure_server_bbr(&mut server_config);

    let runtime = Arc::new(TokioRuntime);
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind loopback UDP");
    udp.set_nonblocking(true).expect("non-blocking UDP");
    let io = runtime.wrap_udp_socket(udp).expect("Quinn Tokio socket");
    let loss = Arc::new(DeterministicLoss::new(io, drop_every));
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        loss.clone(),
        runtime,
    )
    .expect("server endpoint");
    let address = server.local_addr().expect("bound UDP endpoint");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("test trust anchor");
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 supported")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).expect("QUIC client TLS"),
    ));
    configure_client_bbr(&mut client_config);
    let mut client =
        Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind client endpoint");
    client.set_default_client_config(client_config);
    (server, client, address, loss)
}

async fn run_scenario(drop_every: u64) -> Sample {
    tokio::time::timeout(Duration::from_secs(40), async move {
        let (server, client, address, loss) = endpoints(drop_every);
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming QUIC");
            let connection = incoming.await.expect("verified QUIC TLS");
            assert!(
                connection
                    .congestion_state()
                    .into_any()
                    .downcast::<quinn::congestion::Bbr>()
                    .is_ok(),
                "server must use BBR"
            );
            // Arm only after handshake; isolate data transport recovery from
            // random handshake retransmission and keep the test reproducible.
            loss.armed.store(true, Ordering::Relaxed);
            let started = Instant::now();
            let mut outgoing = connection.open_uni().await.expect("open data stream");
            let payload = vec![0x5a; CHUNK_SIZE];
            for _ in 0..(PAYLOAD_LEN / CHUNK_SIZE) {
                outgoing
                    .write_all(&payload)
                    .await
                    .expect("write all through loss");
            }
            outgoing.finish().expect("send FIN");
            let mut acknowledgement = connection.accept_uni().await.expect("client ack stream");
            assert_eq!(
                acknowledgement.read_to_end(16).await.expect("read ack"),
                b"received",
            );
            let elapsed = started.elapsed();
            let stats = connection.stats().path;
            // Keep endpoint active until client confirms the scenario is complete.
            client_done_rx
                .await
                .expect("client received complete stream");
            Sample {
                drop_every,
                attempted_datagrams: loss.attempts.load(Ordering::Relaxed),
                dropped_datagrams: loss.dropped.load(Ordering::Relaxed),
                sent_packets: stats.sent_packets,
                lost_packets: stats.lost_packets,
                congestion_events: stats.congestion_events,
                rtt: stats.rtt,
                elapsed,
            }
        });

        let connection = client
            .connect(address, "localhost")
            .unwrap()
            .await
            .expect("verify certificate + SNI");
        assert!(
            connection
                .congestion_state()
                .into_any()
                .downcast::<quinn::congestion::Bbr>()
                .is_ok(),
            "client must also use BBR"
        );
        let mut incoming = connection.accept_uni().await.expect("server data");
        let content = incoming
            .read_to_end(PAYLOAD_LEN + 1)
            .await
            .expect("reassembled stream");
        assert_eq!(content.len(), PAYLOAD_LEN);
        assert!(
            content.iter().all(|&byte| byte == 0x5a),
            "payload must be byte-exact"
        );
        let mut ack = connection.open_uni().await.expect("ack stream");
        ack.write_all(b"received").await.expect("send ack");
        ack.finish().expect("ack FIN");
        client_done_tx.send(()).expect("server still waiting");
        let sample = server_task.await.expect("server task");
        client.close(0u32.into(), b"complete");
        sample
    })
    .await
    .expect("QUIC loss scenario exceeded 40 seconds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_bbr_recovers_byte_exactly_from_synthetic_udp_loss() {
    // Two scenarios on distinct loopback endpoints. Do not compare raw timing:
    // public CI runners have uncontrolled scheduling and CPU contention.
    let clean = run_scenario(0).await;
    let lossy = run_scenario(20).await; // drop every twentieth data-phase datagram

    assert_eq!(
        clean.dropped_datagrams, 0,
        "clean socket must not drop anything"
    );
    assert!(
        lossy.dropped_datagrams >= 1,
        "test must actually inject losses"
    );
    assert!(lossy.attempted_datagrams >= lossy.dropped_datagrams);
    assert!(lossy.sent_packets > 0);
    // QUIC's loss detection can report retransmissions independently of
    // the injected drop counter; log both without assuming they are identical.
    eprintln!("BBR synthetic loss samples; not benchmark results: clean={clean:?} lossy={lossy:?}");
}
