//! CI-only F-18 H2 identity research on real HTTP/2 DATA, not a wire
//! protocol or production security mode. All sockets are loopback only.
#![forbid(unsafe_code)]

#[path = "support/f18_research_identity.rs"]
mod lab;

use bytes::Bytes;
use lab::{Branch, Failure, ReplayWindow, Transcript};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{
    pki_types::{PrivatePkcs8KeyDer, ServerName},
    RootCertStore,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroize;

const LABEL: &[u8] = b"EXPORTER-Theia-F18-H2-DATA-research-only";
const CONTEXT: &[u8] = b"verified-tls-h2-lab";
const DEADLINE: Duration = Duration::from_secs(20);
const CHALLENGE: usize = 32;
const PROOF: usize = 96;

fn keypair() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn nonce() -> [u8; 32] {
    let mut value = [0; 32];
    SystemRandom::new().fill(&mut value).unwrap();
    value
}

fn tls_pair() -> (TlsAcceptor, TlsConnector) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![der.clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    (
        TlsAcceptor::from(Arc::new(server)),
        TlsConnector::from(Arc::new(client)),
    )
}

// Require END_STREAM and exactly N bytes; never accumulate oversized data.
async fn exact_body<const N: usize>(mut body: h2::RecvStream) -> Option<[u8; N]> {
    let mut result = [0; N];
    let mut offset = 0;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.ok()?;
        if chunk.len() > N - offset {
            return None;
        }
        result[offset..offset + chunk.len()].copy_from_slice(&chunk);
        offset += chunk.len();
        body.flow_control().release_capacity(chunk.len()).ok()?;
    }
    (offset == N).then_some(result)
}

async fn respond(
    request: http::Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    signer: Arc<Ed25519KeyPair>,
    mut exporter: [u8; 32],
    port: u16,
) {
    let challenge = exact_body::<CHALLENGE>(request.into_body()).await;
    let transcript = challenge.and_then(|challenge| {
        Transcript::new(
            Branch::H2,
            "localhost",
            port,
            challenge,
            nonce(),
            exporter,
            10_000,
        )
        .ok()
    });
    if let Some(mut transcript) = transcript {
        let signature = signer.sign(&transcript.encode());
        let mut proof = Vec::with_capacity(PROOF);
        proof.extend_from_slice(&transcript.server_nonce);
        proof.extend_from_slice(signature.as_ref());
        let response = http::Response::builder().status(200).body(()).unwrap();
        let mut stream = reply.send_response(response, false).unwrap();
        stream.send_data(Bytes::from(proof), true).unwrap();
        transcript.exporter.zeroize();
    } else {
        let response = http::Response::builder().status(400).body(()).unwrap();
        reply.send_response(response, true).unwrap();
    }
    exporter.zeroize();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_h2_data_proof_rejects_malformed_challenges_and_wrong_identity() {
    timeout(DEADLINE, async {
        let signer = Arc::new(keypair());
        let pinned: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let wrong_key = keypair();
        let wrong_pin: [u8; 32] = wrong_key.public_key().as_ref().try_into().unwrap();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = listener.local_addr().unwrap();
        let port = remote.port();
        let (done_tx, mut done_rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.unwrap();
            let conn = tls.get_ref().1;
            assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));
            let mut exporter = conn
                .export_keying_material([0u8; 32], LABEL, Some(CONTEXT))
                .unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let mut handlers = JoinSet::new();
            let mut accepted = 0;
            loop {
                tokio::select! {
                    done = &mut done_rx => {
                        done.unwrap();
                        break;
                    }
                    completed = handlers.join_next(), if !handlers.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                    next = connection.accept() => {
                        let (request, response) = next.unwrap().unwrap();
                        assert_eq!(request.method(), http::Method::POST);
                        assert_eq!(request.uri().path(), "/f18/research-only");
                        accepted += 1;
                        assert!(accepted <= 4);
                        handlers.spawn(respond(request, response, signer.clone(), exporter, port));
                    }
                }
            }
            assert_eq!(accepted, 4);
            while let Some(result) = handlers.join_next().await {
                result.unwrap();
            }
            exporter.zeroize();
        });

        let socket = TcpStream::connect(remote).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap();
        let conn = tls.get_ref().1;
        assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));
        let mut exporter = conn
            .export_keying_material([0u8; 32], LABEL, Some(CONTEXT))
            .unwrap();
        let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        // Short, oversized and all-zero challenges must not produce a proof.
        for malformed in [vec![1; 31], vec![1; 33], vec![0; 32]] {
            sender = sender.ready().await.unwrap();
            let (response, mut stream) = sender
                .send_request(
                    http::Request::post("https://localhost/f18/research-only")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            stream.send_data(Bytes::from(malformed), true).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
            assert!(exact_body::<0>(response.into_body()).await.is_some());
        }

        // A valid sibling stream still works. Exercise fragmented DATA.
        let challenge = nonce();
        sender = sender.ready().await.unwrap();
        let (response, mut stream) = sender
            .send_request(
                http::Request::post("https://localhost/f18/research-only")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        stream
            .send_data(Bytes::copy_from_slice(&challenge[..16]), false)
            .unwrap();
        stream
            .send_data(Bytes::copy_from_slice(&challenge[16..]), true)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut proof = exact_body::<PROOF>(response.into_body()).await.unwrap();
        let mut transcript = Transcript::new(
            Branch::H2,
            "localhost",
            port,
            challenge,
            proof[..32].try_into().unwrap(),
            exporter,
            10_000,
        )
        .unwrap();
        let mut verifier = ReplayWindow::new(1).unwrap();
        assert_eq!(
            verifier.accept(&wrong_pin, &transcript, &proof[32..], 10_000),
            Err(Failure::InvalidProof)
        );
        transcript.branch = Branch::H3;
        assert_eq!(
            verifier.accept(&pinned, &transcript, &proof[32..], 10_000),
            Err(Failure::InvalidProof)
        );
        transcript.branch = Branch::H2;
        proof[32] ^= 1;
        assert_eq!(
            verifier.accept(&pinned, &transcript, &proof[32..], 10_000),
            Err(Failure::InvalidProof)
        );
        proof[32] ^= 1;
        assert_eq!(
            verifier.accept(&pinned, &transcript, &proof[32..], 10_000),
            Ok(())
        );
        assert_eq!(
            verifier.accept(&pinned, &transcript, &proof[32..], 10_001),
            Err(Failure::Replay)
        );
        transcript.exporter.zeroize();
        exporter.zeroize();
        proof.zeroize();
        done_tx.send(()).unwrap();
        server_task.await.unwrap();
        driver.abort();
    })
    .await
    .expect("bounded real H2 DATA identity research fixture");
}
