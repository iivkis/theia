//! F-18 M3.5a2, research-only *actual UDP datagram* QUIC v1 Initial
//! observations and an Ed25519 identity proof carried in a real HTTP/3 DATA
//! stream. Strict TLS1.3 CA/SAN/ALPN and active BBR come from the existing
//! production QUIC composition root; no new production security mode.
//!
//! No packet bytes, connection IDs, raw ClientHello, SNI, keys or transcripts
//! are persisted or emitted. QUIC Initial CRYPTO content remains encrypted;
//! this parser checks only the exposed long-header metadata, NOT browser-like
//! fingerprint equivalence or a modified REALITY TLS handshake.
#![forbid(unsafe_code)]

#[path = "support/f13_evidence.rs"]
mod f13_evidence;
#[path = "support/f18_research_identity.rs"]
mod identity;

use bytes::{Buf, Bytes};
use identity::{Branch, Failure, ReplayWindow, Transcript};
use quinn::Endpoint;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::SocketAddr, time::Duration};
use theia::quic_transport::{accept, client_endpoint, connect, server_endpoint};
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle, time::timeout};
use zeroize::Zeroize;

const DEADLINE: Duration = Duration::from_secs(24);
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Theia-M3.5a2-QUIC-research-only";
const EXPORTER_CONTEXT: &[u8] = b"identity-proof-h3-test-only";

/// Only public QUIC long-header dimensions are retained, never CID content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InitialShape {
    version: u32,
    destination_cid_len: u8,
    source_cid_len: u8,
    token_len: u64,
    packet_len: usize,
    datagram_len: usize,
}

fn read_varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *data.get(*offset)?;
    let width = 1usize << (first >> 6);
    let end = offset.checked_add(width)?;
    let bytes = data.get(*offset..end)?;
    let mut value = u64::from(first & 0x3f);
    for &byte in &bytes[1..] {
        value = value.checked_mul(256)?.checked_add(u64::from(byte))?;
    }
    *offset = end;
    Some(value)
}

/// Parse only the unencrypted QUIC v1 Initial long header (RFC 9000 section
/// 17.2.2). Protected packet number and encrypted CRYPTO are never decoded.
/// A short, truncated, non-v1 or malformed datagram is *not* evidence.
fn parse_initial(datagram: &[u8]) -> Option<InitialShape> {
    if datagram.len() < 1200 {
        return None;
    }
    let first = *datagram.first()?;
    // Both long-header and fixed bit set; v1 Initial packet type = 00.
    if first & 0xf0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(datagram.get(1..5)?.try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut offset = 5usize;
    let destination_cid_len = *datagram.get(offset)?;
    offset += 1;
    if destination_cid_len > 20 {
        return None;
    }
    offset = offset.checked_add(usize::from(destination_cid_len))?;
    datagram.get(0..offset)?;
    let source_cid_len = *datagram.get(offset)?;
    offset += 1;
    if source_cid_len > 20 {
        return None;
    }
    offset = offset.checked_add(usize::from(source_cid_len))?;
    datagram.get(0..offset)?;
    let token_len = read_varint(datagram, &mut offset)?;
    offset = offset.checked_add(usize::try_from(token_len).ok()?)?;
    datagram.get(0..offset)?;
    let protected_len = usize::try_from(read_varint(datagram, &mut offset)?).ok()?;
    // Protected packet number is 1..4 bytes and AEAD tag is 16 bytes.
    if protected_len < 17 {
        return None;
    }
    let packet_len = offset.checked_add(protected_len)?;
    datagram.get(0..packet_len)?;
    Some(InitialShape {
        version,
        destination_cid_len,
        source_cid_len,
        token_len,
        packet_len,
        datagram_len: datagram.len(),
    })
}

#[test]
fn exposed_quic_initial_parser_rejects_truncated_and_noncanonical_packet_shapes() {
    // Fabricated metadata-only fixture. Not a valid encrypted QUIC packet.
    // First packet: header 26 bytes + protected length 1174 = 1200 bytes.
    let mut sample = vec![0xc0, 0, 0, 0, 1, 8];
    sample.extend_from_slice(&[1; 8]);
    sample.push(8);
    sample.extend_from_slice(&[2; 8]);
    sample.push(0); // token length 0
    sample.extend_from_slice(&[0x44, 0x96]); // QUIC two-byte varint 1174
    sample.resize(1200, 0);
    let parsed = parse_initial(&sample).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.destination_cid_len, 8);
    assert_eq!(parsed.source_cid_len, 8);
    assert_eq!(parsed.token_len, 0);
    assert_eq!(parsed.packet_len, 1200);
    assert_eq!(parsed.datagram_len, 1200);
    assert!(parse_initial(&sample[..1199]).is_none());

    for (at, replacement) in [
        (0, 0x40),  // short header
        (0, 0xd0),  // 0-RTT, not Initial
        (0, 0xe0),  // Handshake, not Initial
        (4, 0x02),  // unexpected QUIC version
        (5, 21),    // destination CID longer than RFC allows
        (14, 21),   // source CID longer than RFC allows
        (23, 0xff), // unsupported enormous token length
        (24, 0xff), // unsupported enormous packet length
    ] {
        let mut corrupted = sample.clone();
        corrupted[at] = replacement;
        assert!(
            parse_initial(&corrupted).is_none(),
            "malformed visible header cannot become evidence"
        );
    }
    assert!(parse_initial(&[]).is_none());
    assert!(parse_initial(&[0xc0; 50]).is_none());
}

/// A deliberately bounded localhost-only UDP forwarder. No external probes,
/// untrusted target resolution, pcap, persistent raw CID bytes or logs.
async fn udp_witness(
    server_address: SocketAddr,
) -> (
    SocketAddr,
    oneshot::Receiver<Option<InitialShape>>,
    JoinHandle<()>,
) {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = front.local_addr().unwrap();
    let (initial_tx, initial_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut client = None;
        let mut initial_tx = Some(initial_tx);
        let mut from_client = [0u8; 65_536];
        let mut from_server = [0u8; 65_536];
        // Stop on unusual packet floods rather than silently dropping live
        // traffic into an unbounded test-side allocation or network loop.
        for _ in 0..512 {
            tokio::select! {
                packet = front.recv_from(&mut from_client) => {
                    let Ok((length, source)) = packet else { break };
                    if client.is_none() {
                        client = Some(source);
                    }
                    if client != Some(source) {
                        continue;
                    }
                    if let Some(sender) = initial_tx.take() {
                        let _ = sender.send(parse_initial(&from_client[..length]));
                    }
                    if upstream.send_to(&from_client[..length], server_address).await.is_err() {
                        break;
                    }
                }
                packet = upstream.recv_from(&mut from_server) => {
                    let Ok((length, source)) = packet else { break };
                    if source != server_address {
                        continue;
                    }
                    let Some(destination) = client else { continue };
                    if front.send_to(&from_server[..length], destination).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (proxy_address, initial_rx, handle)
}

fn signed_key() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    SystemRandom::new().fill(&mut nonce).unwrap();
    nonce
}

fn endpoints() -> (Endpoint, Endpoint, SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![der.clone()],
        key.into(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let client = client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
    let address = server.local_addr().unwrap();
    (server, client, address)
}

/// Real QUIC v1 Initial crossing actual localhost UDP sockets and a real
/// HTTP/3 POST DATA challenge/response over verified QUIC/TLS1.3/ALPN=h3.
/// This is still a *separate* research route, not a SmartTheia auth opcode,
/// production F-18 security mode or REALITY wire handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_initial_h3_data_and_exporter_pinned_identity_are_distinct_evidence() {
    timeout(DEADLINE, async {
        let (server, client, destination) = endpoints();
        let (proxy_addr, first_datagram, proxy_task) = udp_witness(destination).await;
        let signer = signed_key();
        let pinned: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let client_nonce = random_nonce();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let service_port = destination.port();

        let server_task = tokio::spawn(async move {
            let connection = accept(server.accept().await.unwrap()).await.unwrap();
            let mut exporter = [0u8; 32];
            connection
                .export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)
                .unwrap();
            let mut http3 =
                h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let resolver = http3.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/f18/research-only");
            let mut challenge = Vec::with_capacity(32);
            while challenge.len() < 32 {
                let mut data = stream
                    .recv_data()
                    .await
                    .unwrap()
                    .expect("bounded client challenge");
                let chunk_len = data.remaining();
                assert!(chunk_len > 0 && chunk_len <= 32 - challenge.len());
                challenge.extend_from_slice(&data.copy_to_bytes(chunk_len));
            }
            let nonce: [u8; 32] = challenge.try_into().unwrap();
            assert!(stream.recv_data().await.unwrap().is_none());
            let server_nonce = random_nonce();
            let transcript = Transcript::new(
                Branch::H3,
                "localhost",
                service_port,
                nonce,
                server_nonce,
                exporter,
                10_000,
            )
            .unwrap();
            let signature = signer.sign(&transcript.encode());
            let mut response = Vec::with_capacity(96);
            response.extend_from_slice(&server_nonce);
            response.extend_from_slice(signature.as_ref());
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream.send_data(Bytes::from(response)).await.unwrap();
            stream.finish().await.unwrap();
            exporter.zeroize();
            done_rx.await.unwrap();
            connection.close(0u32.into(), b"research completed");
        });

        // Reuses the strict existing production composition root: full
        // authenticated handshake, ALPN=h3, configured active BBR and no 0-RTT.
        let connection = connect(&client, proxy_addr, "localhost").await.unwrap();
        let mut exporter = [0u8; 32];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut request = sender
            .send_request(
                http::Request::post("https://localhost/f18/research-only")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        request
            .send_data(Bytes::copy_from_slice(&client_nonce))
            .await
            .unwrap();
        request.finish().await.unwrap();
        assert_eq!(request.recv_response().await.unwrap().status(), 200);
        let mut reply = Vec::with_capacity(96);
        while let Some(mut data) = request.recv_data().await.unwrap() {
            let chunk_len = data.remaining();
            assert!(chunk_len > 0 && chunk_len <= 96 - reply.len());
            reply.extend_from_slice(&data.copy_to_bytes(chunk_len));
        }
        assert_eq!(reply.len(), 96);
        let server_nonce: [u8; 32] = reply[..32].try_into().unwrap();
        let transcript = Transcript::new(
            Branch::H3,
            "localhost",
            service_port,
            client_nonce,
            server_nonce,
            exporter,
            10_000,
        )
        .unwrap();

        let mut verifier = ReplayWindow::new(8).unwrap();
        let attacker_key = signed_key();
        let wrong_pin: [u8; 32] = attacker_key.public_key().as_ref().try_into().unwrap();
        assert_eq!(
            verifier.accept(&wrong_pin, &transcript, &reply[32..], 10_000),
            Err(Failure::InvalidProof)
        );
        let mut h2_attempt = transcript.clone();
        h2_attempt.branch = Branch::H2;
        assert_eq!(
            verifier.accept(&pinned, &h2_attempt, &reply[32..], 10_000),
            Err(Failure::InvalidProof)
        );
        assert_eq!(
            verifier.accept(&pinned, &transcript, &reply[32..], 10_000),
            Ok(())
        );
        assert_eq!(
            verifier.accept(&pinned, &transcript, &reply[32..], 10_001),
            Err(Failure::Replay)
        );

        let initial = first_datagram
            .await
            .unwrap()
            .expect("first UDP datagram must be QUIC v1 Initial");
        assert_eq!(initial.version, 1);
        assert_eq!(
            initial.token_len, 0,
            "fresh unresumed client must not invent retry token"
        );
        assert!(initial.datagram_len >= 1200);
        assert!(initial.packet_len <= initial.datagram_len);
        // No assertion that a real browser has the same CID sizes, extensions,
        // QUIC transport parameters, Initial encryption or HTTP/3 SETTINGS.
        assert!(initial.destination_cid_len <= 20);
        assert!(initial.source_cid_len <= 20);

        exporter.zeroize();
        done_tx.send(()).unwrap();
        server_task.await.unwrap();
        driver_task.abort();
        client.close(0u32.into(), b"done");
        proxy_task.abort();
    })
    .await
    .expect("bounded QUIC Initial and real H3 proof fixture finished");
}

fn emit_initial(name: &str, initial: InitialShape) {
    let json = format!(
        "{{\"version\":{},\"destination_cid_len\":{},\"source_cid_len\":{},\"token_len\":{},\"packet_len\":{},\"datagram_len\":{}}}",
        initial.version, initial.destination_cid_len, initial.source_cid_len,
        initial.token_len, initial.packet_len, initial.datagram_len
    );
    f13_evidence::emit(name, &json);
}

// Server-side negotiated facts, not an estimate of encrypted packet contents.
// No SNI text, header names/values, key material, or raw frames are retained.
fn emit_h3_session(name: &str, connection: &quinn::Connection, request: &http::Request<()>) {
    let handshake = connection.handshake_data().unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap();
    assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
    let json = format!(
        "{{\"alpn_h3\":true,\"sni_present\":{},\"ordinary_fields\":{}}}",
        handshake.server_name.is_some(), request.headers().len()
    );
    f13_evidence::emit(name, &json);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_native_h3_client_initial_reference() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use theia::{client::ClientError, h3_client::H3Client, protocol::Address};
    timeout(DEADLINE, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let (front, initial, proxy) = udp_witness(endpoint.local_addr().unwrap()).await;
        let (done, finished) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let connection = accept(endpoint.accept().await.unwrap()).await.unwrap();
            let mut http3: h3::server::Connection<_, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let (request, mut stream) = http3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/theia-example/session");
            emit_h3_session("native-h3-session.json", &connection, &request);
            stream
                .send_response(http::Response::builder().status(403).body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            finished.await.unwrap();
            connection.close(0u32.into(), b"fixture done");
        });
        let client = H3Client::new(
            front,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x42; 32]),
            roots,
        )
        .unwrap();
        assert!(matches!(
            client.open(Address::V4([127, 0, 0, 1]), 443).await,
            Err(ClientError::Unauthorized)
        ));
        let observation = initial
            .await
            .unwrap()
            .expect("actual native client QUIC Initial");
        assert_eq!(observation.version, 1);
        emit_initial("native-h3-initial.json", observation);
        done.send(()).unwrap();
        server.await.unwrap();
        proxy.abort();
    })
    .await
    .expect("bounded native H3 first-flight observation");
}

/// Independent real-browser HTTP/3 reference. The only certificate exception
/// is the ephemeral fixture SPKI. No browser proxy, TCP listener or H2 fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native browser-e2e CI supplies pinned Chromium"]
async fn actual_chromium_h3_initial_reference() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha2::{Digest, Sha256};
    timeout(Duration::from_secs(55), async {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let spki = STANDARD.encode(Sha256::digest(cert.key_pair.public_key_der()));
        let endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        ).unwrap();
        let (front, first, proxy) = udp_witness(endpoint.local_addr().unwrap()).await;
        let server = tokio::spawn(async move {
            let mut connection = None;
            for _ in 0..8 {
                let incoming = endpoint.accept().await.expect("browser QUIC incoming");
                if let Ok(value) = accept(incoming).await {
                    connection = Some(value);
                    break;
                }
            }
            let connection = connection.expect("Chromium negotiated h3");
            let mut http3 = h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                .await.unwrap();
            let resolver = http3.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().path(), "/ci-chromium-h3-reference");
            emit_h3_session("browser-h3-session.json", &connection, &request);
            assert!(stream.recv_data().await.unwrap().is_none());
            stream.send_response(http::Response::builder().status(200)
                .header("content-type", "text/html; charset=utf-8").body(()).unwrap())
                .await.unwrap();
            stream.send_data(Bytes::from_static(b"<html><main id='h3-reference'>chromium-h3</main></html>"))
                .await.unwrap();
            stream.finish().await.unwrap();
            // Keep the connection and H3 control stream driven until the
            // browser finishes the isolated navigation and closes.
            while let Ok(Some(resolver)) = http3.accept().await {
                if let Ok((_, mut stream)) = resolver.resolve_request().await {
                    let _ = stream.send_response(http::Response::builder().status(404).body(()).unwrap()).await;
                    let _ = stream.finish().await;
                }
            }
        });
        let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/e2e/chromium_h3_reference.py");
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("python").arg(script).arg(front.to_string()).arg(spki).output()
        }).await.unwrap().expect("pinned Chromium launcher");
        assert!(output.status.success(), "independent Chromium H3 navigation failed");
        let initial = first.await.unwrap().expect("browser sent valid QUIC v1 Initial");
        emit_initial("browser-h3-initial.json", initial);
        assert!(initial.datagram_len >= 1200);
        assert!(initial.packet_len <= initial.datagram_len);
        eprintln!("Actual Chromium H3 Initial: version={} dcid_len={} scid_len={} token_len={} packet_len={} datagram_len={}; reference only, not fingerprint parity",
            initial.version, initial.destination_cid_len, initial.source_cid_len,
            initial.token_len, initial.packet_len, initial.datagram_len);
        server.abort();
        proxy.abort();
    }).await.expect("bounded Chromium H3 reference deadline");
}
