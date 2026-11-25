//! Production H2/H3 data-plane liveness on actual loopback TCP and TLS/QUIC.
//! All asymmetric, half-close, idle and sustained traffic cases run concurrently
//! over real sockets in the mandatory ordinary and instrumented native suites.
//! The complete matrix has a 55s deadline. Virtual-time unit tests cover >300s
//! of relay progress separately; that is not a real 300s network soak.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{Inbound, ServerPolicy, User},
    h3_client::H3Client,
    protocol::Address,
    server::{self, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::{sleep, timeout, Instant},
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];

#[derive(Clone, Copy, Debug)]
enum Transport {
    H2,
    H3,
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Upload,
    Download,
    UploadAfterRemoteFin,
    DownloadAfterLocalFin,
    Idle,
    LongUpload,
    LongDownload,
}

struct Fixture {
    h2: SocketAddr,
    h3: SocketAddr,
    roots: RootCertStore,
}

impl Fixture {
    async fn start() -> (Self, JoinSet<Result<(), server::ServerError>>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = cert.key_pair.serialize_der();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.clone()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h2 = tcp.local_addr().unwrap();
        let udp = theia::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der],
            PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let h3 = udp.local_addr().unwrap();
        let inbound = Inbound {
            id: "test".into(),
            allowed_user_ids: vec!["client".into()],
            h2_listen: h2.to_string(),
            quic_listen: h3.to_string(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            security_mode: Default::default(),
            reality: None,
            tls_key: "unused".into(),
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        };
        let policy = ServerPolicy {
            allow_private_ips: true,
            max_connections_per_user: 16,
            max_connections_total: 16,
            connect_timeout_ms: 2000,
        };
        let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
        let mut servers = JoinSet::new();
        servers.spawn(server::serve(
            tcp,
            TlsAcceptor::from(Arc::new(tls)),
            context.clone(),
        ));
        servers.spawn(theia::h3_server::serve(udp, context));
        (Self { h2, h3, roots }, servers)
    }

    async fn exercise(&self, transport: Transport, case: Case) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let token = URL_SAFE_NO_PAD.encode(TOKEN);
        let address = Address::V4([127, 0, 0, 1]);
        let (mut app, local) = tokio::io::duplex(4096);
        let relay = match transport {
            Transport::H2 => {
                let client = H2Client::new(
                    &self.h2.to_string(),
                    "localhost",
                    &token,
                    self.roots.clone(),
                )
                .unwrap();
                let tunnel = client.open(address, port).await.unwrap();
                tokio::spawn(tunnel.relay(local))
            }
            Transport::H3 => {
                let client =
                    H3Client::new(self.h3, "localhost", &token, self.roots.clone()).unwrap();
                let tunnel = client.open(address, port).await.unwrap();
                tokio::spawn(tunnel.relay(local))
            }
        };
        let (mut remote, _) = target.accept().await.unwrap();
        if matches!(case, Case::Idle) {
            let started = Instant::now();
            let result = timeout(Duration::from_secs(40), relay)
                .await
                .expect("fully idle tunnel must terminate")
                .unwrap();
            assert!(
                matches!(
                    result,
                    Err(ClientError::Timeout
                        | ClientError::Protocol
                        | ClientError::Http2
                        | ClientError::Http3
                        | ClientError::Io)
                ),
                "{transport:?}: {result:?}"
            );
            assert!(
                started.elapsed() >= Duration::from_secs(20),
                "{transport:?}: premature idle failure"
            );
            return;
        }

        let upload = matches!(
            case,
            Case::Upload | Case::UploadAfterRemoteFin | Case::LongUpload
        );
        let early_fin = matches!(
            case,
            Case::UploadAfterRemoteFin | Case::DownloadAfterLocalFin
        );
        if early_fin {
            let mut empty = Vec::new();
            if upload {
                remote.shutdown().await.unwrap();
                app.read_to_end(&mut empty).await.unwrap();
            } else {
                app.shutdown().await.unwrap();
                remote.read_to_end(&mut empty).await.unwrap();
            }
            assert!(empty.is_empty());
        }

        let started = Instant::now();
        // Keep the opposite direction silent (or already half-closed).
        // Sustained cases transfer additional blocks for over 40 real seconds.
        let long = matches!(case, Case::LongUpload | Case::LongDownload);
        let (blocks, interval) = if long {
            (23, Duration::from_secs(2))
        } else {
            (7, Duration::from_millis(5500))
        };
        for index in 0..blocks as u8 {
            if index != 0 {
                sleep(interval).await;
            }
            let payload = [index; 4096];
            let mut received = [0; 4096];
            timeout(Duration::from_secs(5), async {
                if upload {
                    app.write_all(&payload).await.unwrap();
                    remote.read_exact(&mut received).await.unwrap();
                } else {
                    remote.write_all(&payload).await.unwrap();
                    app.read_exact(&mut received).await.unwrap();
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{transport:?}/{case:?}: stalled at block {index}"));
            assert_eq!(received, payload);
        }
        assert!(started.elapsed() > Duration::from_secs(if long { 40 } else { 30 }));
        if upload {
            app.shutdown().await.unwrap();
            let mut end = Vec::new();
            remote.read_to_end(&mut end).await.unwrap();
            assert!(end.is_empty());
            if !early_fin {
                remote.shutdown().await.unwrap();
                app.read_to_end(&mut end).await.unwrap();
                assert!(end.is_empty());
            }
        } else {
            remote.shutdown().await.unwrap();
            let mut end = Vec::new();
            app.read_to_end(&mut end).await.unwrap();
            assert!(end.is_empty());
            if !early_fin {
                app.shutdown().await.unwrap();
                remote.read_to_end(&mut end).await.unwrap();
                assert!(end.is_empty());
            }
        }
        relay.await.unwrap().unwrap();
    }
}

async fn exercise_matrix(selected: &[Case], limit: Duration) {
    timeout(limit, async {
        let (fixture, _servers) = Fixture::start().await;
        let fixture = Arc::new(fixture);
        let mut cases = JoinSet::new();
        for transport in [Transport::H2, Transport::H3] {
            for &case in selected {
                let fixture = fixture.clone();
                cases.spawn(async move {
                    fixture.exercise(transport, case).await;
                });
            }
        }
        while let Some(result) = cases.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("bounded concurrent native liveness matrix");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_h2_h3_asymmetric_traffic_half_close_and_idle() {
    exercise_matrix(
        &[
            Case::Upload,
            Case::Download,
            Case::UploadAfterRemoteFin,
            Case::DownloadAfterLocalFin,
            Case::Idle,
            Case::LongUpload,
            Case::LongDownload,
        ],
        Duration::from_secs(55),
    )
    .await;
}
