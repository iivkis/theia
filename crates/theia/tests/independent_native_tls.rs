//! Independent peer matrix: real production client constructors, strict trust,
//! exact ALPN and no HTTP body before admission. Controlled loopback only.
#[path = "support/private_pem.rs"]
mod private_pem;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::RootCertStore;
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};
use theia::{
    client::{ClientError, H2Client},
    h3_client::H3Client,
    protocol::Address,
};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture(Child);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native browser CI supplies pinned independent hyper-h2 and aioquic"]
async fn native_clients_require_pki_and_exact_alpn() {
    let scratch = Scratch(
        std::env::temp_dir().join(format!("theia-native-independent-{}", std::process::id())),
    );
    fs::create_dir(&scratch.0).unwrap();
    tokio::time::timeout(Duration::from_secs(55), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(scratch.0.join("cert.pem"), cert.cert.pem()).unwrap();
        private_pem::write_new_key(&scratch.0.join("key.pem"), cert.key_pair.serialize_pem());
        let mut trusted = RootCertStore::empty();
        trusted.add(cert.cert.der().clone()).unwrap();
        let mut wrong = RootCertStore::empty();
        wrong.add(unrelated.cert.der().clone()).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/e2e/independent_native_tls.py");
        let mut fixture = Fixture(
            Command::new("python")
                .arg(script)
                .arg(&scratch.0)
                .spawn()
                .unwrap(),
        );
        let ports = loop {
            if let Ok(raw) = fs::read_to_string(scratch.0.join("ready")) {
                break raw
                    .lines()
                    .map(|line| line.parse::<u16>().unwrap())
                    .collect::<Vec<_>>();
            }
            assert!(
                fixture.0.try_wait().unwrap().is_none(),
                "fixture exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(ports.len(), 4);
        assert!(ports.iter().all(|&port| port != 0));
        let endpoint = |index: usize| SocketAddr::from(([127, 0, 0, 1], ports[index]));
        let token = URL_SAFE_NO_PAD.encode([0x42; 32]);
        let target = Address::V4([127, 0, 0, 1]);

        // Each negative handshake must terminate before sending an HTTP
        // request to the independent peer, even with the correct credential.
        for (index, name, roots) in [
            (0, "localhost", wrong.clone()),
            (0, "wrong.example", trusted.clone()),
            (1, "localhost", trusted.clone()),
        ] {
            let client = H2Client::new(&endpoint(index).to_string(), name, &token, roots).unwrap();
            assert!(matches!(
                client.open(target.clone(), 443).await,
                Err(ClientError::Tls)
            ));
        }
        for (index, name, roots) in [
            (2, "localhost", wrong),
            (2, "wrong.example", trusted.clone()),
            (3, "localhost", trusted.clone()),
        ] {
            let client = H3Client::new(endpoint(index), name, &token, roots).unwrap();
            assert!(matches!(
                client.open(target.clone(), 443).await,
                Err(ClientError::Tls)
            ));
        }
        // Only correct trust and ALPN reach independent HTTP admission. The
        // peer denies the request and the client must not initiate HELLO/OPEN.
        let h2 = H2Client::new(
            &endpoint(0).to_string(),
            "localhost",
            &token,
            trusted.clone(),
        )
        .unwrap();
        assert!(matches!(
            h2.open(target.clone(), 443).await,
            Err(ClientError::Unauthorized)
        ));
        let h3 = H3Client::new(endpoint(2), "localhost", &token, trusted).unwrap();
        assert!(matches!(
            h3.open(target, 443).await,
            Err(ClientError::Unauthorized)
        ));
        fs::write(scratch.0.join("done"), b"done").unwrap();
        loop {
            if let Some(status) = fixture.0.try_wait().unwrap() {
                assert!(status.success(), "independent peer matrix failed");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded independent native TLS matrix");
}
