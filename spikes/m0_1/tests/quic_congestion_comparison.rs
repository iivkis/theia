//! CI-only BBR vs CUBIC QUIC comparison on an identical synthetic link.
//! DATA-phase UDP loss/delay/jitter are deterministic at the datagram-attempt
//! level; Linux/Windows runner scheduling is not. Not a release performance gate.
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, Runtime, TokioRuntime, UdpPoller,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{
    io::{self, IoSliceMut, Write},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};

const ALPN: &[u8] = b"theia-congestion-ci";
const PAYLOAD_LEN: usize = 512 * 1024;
const CHUNK_SIZE: usize = 4096;
const MAX_PENDING_DATAGRAMS: usize = 2048;

#[derive(Clone, Copy, Debug)]
enum Controller {
    Bbr,
    Cubic,
}

impl Controller {
    fn name(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
        }
    }

    fn configure(self, config: &mut quinn::TransportConfig) {
        match self {
            Self::Bbr => config.congestion_controller_factory(Arc::new(
                quinn::congestion::BbrConfig::default(),
            )),
            Self::Cubic => config.congestion_controller_factory(Arc::new(
                quinn::congestion::CubicConfig::default(),
            )),
        };
    }

    fn assert_active(self, connection: &Connection) {
        let controller = connection.congestion_state().into_any();
        match self {
            Self::Bbr => assert!(
                controller.downcast::<quinn::congestion::Bbr>().is_ok(),
                "BBR must be the actual active sender"
            ),
            Self::Cubic => assert!(
                controller.downcast::<quinn::congestion::Cubic>().is_ok(),
                "CUBIC must be the actual active sender"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Condition {
    name: &'static str,
    drop_every: u64,
    delay_ms: u64,
    jitter_ms: u64,
}

const CONDITIONS: [Condition; 4] = [
    Condition {
        name: "baseline",
        drop_every: 0,
        delay_ms: 0,
        jitter_ms: 0,
    },
    Condition {
        name: "loss_5pct_attempts",
        drop_every: 20,
        delay_ms: 0,
        jitter_ms: 0,
    },
    Condition {
        name: "delay_jitter",
        drop_every: 0,
        delay_ms: 8,
        jitter_ms: 8,
    },
    Condition {
        name: "loss_delay_jitter",
        drop_every: 20,
        delay_ms: 8,
        jitter_ms: 8,
    },
];

/// Source-side impairment only after TLS verification, with no OS settings.
/// Delayed sends own their copied datagram; the bound prevents unbounded memory.
/// A Tokio task and timer for each delayed datagram add scheduler variance.
#[derive(Debug)]
struct Impairment {
    inner: Arc<dyn AsyncUdpSocket>,
    condition: Condition,
    armed: AtomicBool,
    attempts: AtomicU64,
    dropped: AtomicU64,
    delayed: AtomicU64,
    pending: Arc<AtomicUsize>,
}

impl Impairment {
    fn new(inner: Arc<dyn AsyncUdpSocket>, condition: Condition) -> Self {
        Self {
            inner,
            condition,
            armed: AtomicBool::new(false),
            attempts: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            delayed: AtomicU64::new(0),
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsyncUdpSocket for Impairment {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, packet: &Transmit<'_>) -> io::Result<()> {
        if !self.armed.load(Ordering::Relaxed) {
            return self.inner.try_send(packet);
        }
        let sequence = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if self.condition.drop_every > 0 && sequence % self.condition.drop_every == 0 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if self.condition.delay_ms == 0 && self.condition.jitter_ms == 0 {
            return self.inner.try_send(packet);
        }
        if self.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_DATAGRAMS {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let inner = self.inner.clone();
        let pending = self.pending.clone();
        let payload = packet.contents.to_vec();
        let destination = packet.destination;
        let ecn = packet.ecn;
        let segment_size = packet.segment_size;
        let src_ip = packet.src_ip;
        let jitter = if self.condition.jitter_ms == 0 {
            0
        } else {
            // Deterministic per-attempt jitter. Still subject to OS timers.
            (sequence.wrapping_mul(7) % (self.condition.jitter_ms + 1))
        };
        let delay = Duration::from_millis(self.condition.delay_ms + jitter);
        self.delayed.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            sleep(delay).await;
            let packet = Transmit {
                destination,
                ecn,
                contents: &payload,
                segment_size,
                src_ip,
            };
            for _ in 0..50 {
                match inner.try_send(&packet) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        sleep(Duration::from_millis(1)).await;
                    }
                    Err(_) => break,
                }
            }
            pending.fetch_sub(1, Ordering::SeqCst);
        });
        Ok(())
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
        // A dropped attempt corresponds to one UDP datagram, not a GSO batch.
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct Sample {
    controller: &'static str,
    condition: Condition,
    repetition: usize,
    elapsed: Duration,
    rtt: Duration,
    attempts: u64,
    dropped: u64,
    delayed: u64,
    sent_packets: u64,
    lost_packets: u64,
    congestion_events: u64,
}

impl Sample {
    fn csv(&self) -> String {
        let throughput_mbps =
            (PAYLOAD_LEN as f64 * 8.0) / self.elapsed.as_secs_f64() / 1_000_000.0;
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.4}\n",
            self.controller,
            self.condition.name,
            self.repetition,
            PAYLOAD_LEN,
            self.condition.drop_every,
            self.condition.delay_ms,
            self.condition.jitter_ms,
            self.attempts,
            self.dropped,
            self.delayed,
            self.sent_packets,
            self.lost_packets,
            self.congestion_events,
            self.rtt.as_micros(),
            throughput_mbps,
        )
    }
}

fn endpoints(
    controller: Controller,
    condition: Condition,
) -> (Endpoint, Endpoint, SocketAddr, Arc<Impairment>) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = identity.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    controller.configure(&mut transport);
    server_config.transport_config(Arc::new(transport));
    let runtime = Arc::new(TokioRuntime);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_nonblocking(true).unwrap();
    let io = runtime.wrap_udp_socket(udp).unwrap();
    let impairment = Arc::new(Impairment::new(io, condition));
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        impairment.clone(),
        runtime,
    )
    .unwrap();
    let remote = server.local_addr().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    controller.configure(&mut transport);
    client_config.transport_config(Arc::new(transport));
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    (server, client, remote, impairment)
}

async fn trial(controller: Controller, condition: Condition, repetition: usize) -> Sample {
    timeout(Duration::from_secs(35), async move {
        let (server, client, remote, impairment) = endpoints(controller, condition);
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
        let send_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming verified QUIC");
            let conn = incoming.await.expect("TLS1.3 server handshake");
            controller.assert_active(&conn);
            impairment.armed.store(true, Ordering::Relaxed);
            let start = Instant::now();
            let mut stream = conn.open_uni().await.unwrap();
            let chunk = [0x5a; CHUNK_SIZE];
            for _ in 0..(PAYLOAD_LEN / CHUNK_SIZE) {
                stream.write_all(&chunk).await.expect("application payload");
            }
            stream.finish().expect("FIN");
            let mut acknowledgement = conn.accept_uni().await.expect("client reply");
            assert_eq!(acknowledgement.read_to_end(16).await.unwrap(), b"received");
            let elapsed = start.elapsed();
            let stats = conn.stats().path;
            ack_rx.await.expect("acknowledged client shutdown");
            Sample {
                controller: controller.name(),
                condition,
                repetition,
                elapsed,
                rtt: stats.rtt,
                attempts: impairment.attempts.load(Ordering::Relaxed),
                dropped: impairment.dropped.load(Ordering::Relaxed),
                delayed: impairment.delayed.load(Ordering::Relaxed),
                sent_packets: stats.sent_packets,
                lost_packets: stats.lost_packets,
                congestion_events: stats.congestion_events,
            }
        });
        let conn = client.connect(remote, "localhost").unwrap().await.unwrap();
        controller.assert_active(&conn);
        let mut stream = conn.accept_uni().await.unwrap();
        let payload = stream.read_to_end(PAYLOAD_LEN + 1).await.unwrap();
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert!(payload.iter().all(|&byte| byte == 0x5a));
        let mut reply = conn.open_uni().await.unwrap();
        reply.write_all(b"received").await.unwrap();
        reply.finish().unwrap();
        ack_tx.send(()).unwrap();
        let sample = send_task.await.unwrap();
        assert!(sample.sent_packets > 0);
        if condition.drop_every > 0 {
            assert!(sample.dropped > 0, "loss injection must activate");
        } else {
            assert_eq!(sample.dropped, 0);
        }
        if condition.delay_ms > 0 {
            assert!(sample.delayed > 0, "delay injection must activate");
        }
        client.close(0u32.into(), b"done");
        sample
    })
    .await
    .expect("QUIC comparison trial must complete within the deadline")
}

/// Benchmark job is required by CI and writes one raw CSV row per completed
/// trial, including partial results if a subsequent trial fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "dedicated Linux/Windows comparison job records raw metrics"]
async fn comparison_records_all_controller_scenarios_ci_only() {
    let path = std::env::var("THEIA_BBR_RESULTS_PATH")
        .expect("dedicated CI job must specify an artifact destination");
    let mut report = std::fs::File::create(path).expect("create raw comparison CSV");
    writeln!(
        report,
        "controller,condition,repetition,payload_bytes,drop_every,delay_ms,jitter_ms,attempted_datagrams,injected_drops,delayed_datagrams,sent_packets,lost_packets,congestion_events,rtt_us,throughput_mbps"
    )
    .unwrap();
    report.flush().unwrap();
    for repetition in 0..2 {
        for condition in CONDITIONS {
            // Interleave the algorithms within each identical impairment.
            for controller in [Controller::Bbr, Controller::Cubic] {
                let sample = trial(controller, condition, repetition).await;
                let record = sample.csv();
                report.write_all(record.as_bytes()).unwrap();
                report.flush().unwrap();
                eprintln!(
                    "congestion comparison: controller={} condition={} repeat={} throughput_Mbps={:.4} elapsed_ms={} injected_drops={} rtt_us={}",
                    sample.controller,
                    sample.condition.name,
                    sample.repetition,
                    (PAYLOAD_LEN as f64 * 8.0) / sample.elapsed.as_secs_f64() / 1_000_000.0,
                    sample.elapsed.as_millis(),
                    sample.dropped,
                    sample.rtt.as_micros()
                );
            }
        }
    }
}

#[test]
fn synthetic_conditions_are_predeclared_and_nonzero() {
    assert_eq!(CONDITIONS.len(), 4);
    assert_eq!(PAYLOAD_LEN % CHUNK_SIZE, 0);
    assert!(CONDITIONS.iter().any(|case| case.drop_every > 0));
    assert!(CONDITIONS.iter().any(|case| case.jitter_ms > 0));
    assert!(CONDITIONS.iter().any(|case| case.delay_ms > 0));
}
