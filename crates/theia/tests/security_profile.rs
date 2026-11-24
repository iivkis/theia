//! Native real TLS/QUIC pinned identity and mutually exclusive HTTP routes.
//! No third-party endpoints; each peer uses isolated loopback certificates.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{Inbound, ServerPolicy, User},
    h3_client::H3Client,
    protocol::Address,
    security_profile::{CertificatePin, SecurityMode},
    server::{self, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];

struct Fixture {
    h2: SocketAddr,
    h3: SocketAddr,
    roots: RootCertStore,
    pin: CertificatePin,
    other_pin: CertificatePin,
    _servers: JoinSet<Result<(), server::ServerError>>,
}

impl Fixture {
    async fn start(mode: SecurityMode) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = cert.key_pair.serialize_der();
        let pin = CertificatePin::from_der(der.as_ref());
        let other_pin = CertificatePin::from_der(other.cert.der().as_ref());
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        // Both leaf identities have valid chain and SAN with these roots;
        // the pin alone distinguishes the two trusted certificates.
        roots.add(other.cert.der().clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], PrivatePkcs8KeyDer::from(key.clone()).into())
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h2 = tcp.local_addr().unwrap();
        let udp = theia::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der],
            PrivatePkcs8KeyDer::from(key).into(),
        ).unwrap();
        let h3 = udp.local_addr().unwrap();
        let inbound = Inbound {
            id: "test".into(),
            security_mode: mode,
            allowed_user_ids: vec!["client".into()],
            h2_listen: h2.to_string(),
            quic_listen: h3.to_string(),
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
        let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
        let mut servers = JoinSet::new();
        servers.spawn(server::serve(tcp, TlsAcceptor::from(Arc::new(tls)), context.clone()));
        servers.spawn(theia::h3_server::serve(udp, context));
        Self { h2, h3, roots, pin, other_pin, _servers: servers }
    }

    fn h2(&self, pin: Option<CertificatePin>, name: &str, token: &[u8; 32]) -> H2Client {
        H2Client::new(&self.h2.to_string(), name, &URL_SAFE_NO_PAD.encode(token), self.roots.clone()).unwrap()
            .with_certificate_pin(pin).unwrap()
    }

    fn h3(&self, pin: Option<CertificatePin>, name: &str, token: &[u8; 32]) -> H3Client {
        H3Client::new(self.h3, name, &URL_SAFE_NO_PAD.encode(token), self.roots.clone()).unwrap()
            .with_certificate_pin(pin).unwrap()
    }

    async fn errors(&self, pin: Option<CertificatePin>, name: &str, token: &[u8; 32], port: u16, expected: ClientError) {
        let address = Address::V4([127, 0, 0, 1]);
        assert_eq!(self.h2(pin, name, token).open(address.clone(), port).await.err(), Some(expected));
        assert_eq!(self.h3(pin, name, token).open(address, port).await.err(), Some(expected));
    }

    async fn transfer(&self, pin: Option<CertificatePin>, target: &TcpListener) {
        let port = target.local_addr().unwrap().port();
        let address = Address::V4([127, 0, 0, 1]);
        for h3 in [false, true] {
            let (mut app, local) = tokio::io::duplex(4096);
            let relay = if h3 {
                let tunnel = self.h3(pin, "localhost", &TOKEN).open(address.clone(), port).await.unwrap();
                tokio::spawn(tunnel.relay(local))
            } else {
                let tunnel = self.h2(pin, "localhost", &TOKEN).open(address.clone(), port).await.unwrap();
                tokio::spawn(tunnel.relay(local))
            };
            let (mut remote, _) = target.accept().await.unwrap();
            let payload = b"verified pinned tunnel";
            app.write_all(payload).await.unwrap();
            app.shutdown().await.unwrap();
            let mut data = Vec::new();
            remote.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, payload);
            remote.write_all(&data).await.unwrap();
            remote.shutdown().await.unwrap();
            let mut reply = Vec::new();
            app.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
            relay.await.unwrap().unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_h3_pinned_identity_and_mode_are_fail_closed() {
    timeout(Duration::from_secs(30), async {
        let pinned = Fixture::start(SecurityMode::PinnedCertV1).await;
        let plain = Fixture::start(SecurityMode::Plain).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();

        // Trusted certificate with wrong pin, wrong hostname with right
        // pin, bad bearer, and both directions of mode mismatch.
        pinned.errors(Some(pinned.other_pin), "localhost", &TOKEN, port, ClientError::Tls).await;
        // H3 may categorize an ordinary chain/SAN error as its own
        // transport handshake error; it must not return a usable tunnel.
        assert!(pinned.h2(Some(pinned.pin), "wrong.example", &TOKEN).open(Address::V4([127,0,0,1]), port).await.is_err());
        assert!(pinned.h3(Some(pinned.pin), "wrong.example", &TOKEN).open(Address::V4([127,0,0,1]), port).await.is_err());
        pinned.errors(Some(pinned.pin), "localhost", &[0x43; 32], port, ClientError::Unauthorized).await;
        pinned.errors(None, "localhost", &TOKEN, port, ClientError::Rejected(404)).await;
        plain.errors(Some(plain.pin), "localhost", &TOKEN, port, ClientError::Rejected(404)).await;
        assert!(timeout(Duration::from_millis(250), target.accept()).await.is_err());

        pinned.transfer(Some(pinned.pin), &target).await;
        plain.transfer(None, &target).await;
    }).await.expect("bounded H2/H3 identity and mode matrix");
}
