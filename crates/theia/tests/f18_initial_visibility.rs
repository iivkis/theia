//! F-18 M3.5a3: a passive observer can recover the *real* Quinn Initial
//! TLS ClientHello using Quinn's audited public packet/header crypto APIs.
//! Test-only, loopback-only: NO production decryption, network scanner,
//! custom HKDF/AEAD, raw packet logging, or private certificate material.
//!
//! A successful decode is *negative* camouflage evidence, not REALITY.
#![forbid(unsafe_code)]

use bytes::BytesMut;
use quinn::{
    crypto::{rustls::QuicServerConfig, ServerConfig as _},
    ConnectionId,
};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{sync::Arc, time::Duration};
use theia::quic_transport::{accept, client_endpoint, connect, server_endpoint};
use tokio::{net::UdpSocket, sync::oneshot, time::timeout};
use zeroize::Zeroize;

const DEADLINE: Duration = Duration::from_secs(18);
const MAX_FIRST_DATAGRAM: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelloShape {
    tls13: bool,
    h3_alpn: bool,
    sni_present: bool,
    quic_transport_parameters: bool,
    alps_present: bool,
    grease_extension: bool,
    cipher_count: usize,
    extension_count: usize,
}

fn varint(data: &[u8], at: &mut usize) -> Option<usize> {
    let first = *data.get(*at)?;
    let size = 1usize << (first >> 6);
    let end = at.checked_add(size)?;
    let bytes = data.get(*at..end)?;
    let mut value = usize::from(first & 0x3f);
    for &byte in &bytes[1..] {
        value = value.checked_mul(256)?.checked_add(usize::from(byte))?;
    }
    *at = end;
    Some(value)
}

fn u16_at(bytes: &[u8], at: &mut usize) -> Option<usize> {
    let end = at.checked_add(2)?;
    let value = u16::from_be_bytes(bytes.get(*at..end)?.try_into().ok()?);
    *at = end;
    Some(usize::from(value))
}

fn field<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = at.checked_add(len)?;
    let result = bytes.get(*at..end)?;
    *at = end;
    Some(result)
}

fn is_grease(code: usize) -> bool {
    code <= 0xffff && (code & 0x0f0f) == 0x0a0a && (code >> 8) as u8 == (code & 0xff) as u8
}

/// Bounded parsing of one decrypted client TLS handshake message. No SNI
/// value or random/session-ID contents are retained or returned.
fn hello_shape(handshake: &[u8]) -> Option<HelloShape> {
    if handshake.first().copied()? != 1 || handshake.len() < 4 {
        return None;
    }
    let declared = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if declared.checked_add(4)? != handshake.len() || declared > 8192 {
        return None;
    }
    let body = &handshake[4..];
    let mut at = 0;
    if field(body, &mut at, 2)? != [0x03, 0x03] {
        return None;
    }
    field(body, &mut at, 32)?; // random
    let session_len = usize::from(*field(body, &mut at, 1)?.first()?);
    field(body, &mut at, session_len)?;
    let cipher_bytes = u16_at(body, &mut at)?;
    if cipher_bytes == 0 || cipher_bytes % 2 != 0 {
        return None;
    }
    field(body, &mut at, cipher_bytes)?;
    let compression_len = usize::from(*field(body, &mut at, 1)?.first()?);
    field(body, &mut at, compression_len)?;
    let extension_len = u16_at(body, &mut at)?;
    let extensions = field(body, &mut at, extension_len)?;
    if at != body.len() {
        return None;
    }
    let mut cursor = 0;
    let mut answer = HelloShape {
        tls13: false,
        h3_alpn: false,
        sni_present: false,
        quic_transport_parameters: false,
        alps_present: false,
        grease_extension: false,
        cipher_count: cipher_bytes / 2,
        extension_count: 0,
    };
    while cursor < extensions.len() {
        let kind = u16_at(extensions, &mut cursor)?;
        let len = u16_at(extensions, &mut cursor)?;
        let payload = field(extensions, &mut cursor, len)?;
        answer.extension_count += 1;
        match kind {
            0 => answer.sni_present = !payload.is_empty(),
            16 => {
                let mut p = 0;
                let protocols_len = u16_at(payload, &mut p)?;
                let protocols = field(payload, &mut p, protocols_len)?;
                if p != payload.len() {
                    return None;
                }
                let mut q = 0;
                while q < protocols.len() {
                    let len = usize::from(*field(protocols, &mut q, 1)?.first()?);
                    let proto = field(protocols, &mut q, len)?;
                    answer.h3_alpn |= proto == b"h3";
                }
            }
            43 => {
                let mut p = 0;
                let versions_len = usize::from(*field(payload, &mut p, 1)?.first()?);
                let versions = field(payload, &mut p, versions_len)?;
                if p != payload.len() || versions_len % 2 != 0 {
                    return None;
                }
                answer.tls13 = versions.as_chunks::<2>().0.contains(&[0x03, 0x04]);
            }
            57 => answer.quic_transport_parameters = !payload.is_empty(),
            0x4469 | 0x44cd => answer.alps_present = true,
            _ => {}
        }
        answer.grease_extension |= is_grease(kind);
    }
    Some(answer)
}

/// Parse the protected QUIC v1 Initial public header and return its CID,
/// truncated packet boundary and protected packet-number offset. The verifier
/// must still AEAD-authenticate everything before parsing the CRYPTO payload.
fn initial_bounds(datagram: &[u8]) -> Option<(ConnectionId, usize, usize)> {
    if datagram.len() < 1200 || datagram.len() > MAX_FIRST_DATAGRAM {
        return None;
    }
    if datagram.first()? & 0xf0 != 0xc0 || datagram.get(1..5)? != [0, 0, 0, 1] {
        return None;
    }
    let mut at = 5;
    let cid_len = usize::from(*field(datagram, &mut at, 1)?.first()?);
    if cid_len > 20 {
        return None;
    }
    let destination_cid = ConnectionId::new(field(datagram, &mut at, cid_len)?);
    let source_len = usize::from(*field(datagram, &mut at, 1)?.first()?);
    if source_len > 20 {
        return None;
    }
    field(datagram, &mut at, source_len)?;
    let token = varint(datagram, &mut at)?;
    field(datagram, &mut at, token)?;
    let encrypted_len = varint(datagram, &mut at)?;
    if encrypted_len < 20 {
        return None;
    }
    let packet_len = at.checked_add(encrypted_len)?;
    datagram.get(at..packet_len)?;
    Some((destination_cid, at, packet_len))
}

/// Quinn crypto derives Initial keys from PUBLIC destination CID and QUIC
/// version. This is deliberately an observer's view, with no connection keys
/// or server private key. The TLS server config provides only the provider.
fn decrypt_initial(datagram: &[u8], quic_crypto: &QuicServerConfig) -> Option<Vec<u8>> {
    let (cid, pn_offset, packet_len) = initial_bounds(datagram)?;
    let keys = quic_crypto.initial_keys(1, &cid).ok()?;
    let mut packet = datagram[..packet_len].to_vec();
    // Header protection is removed by Quinn's crypto implementation, not
    // by custom AES/HKDF. Use *remote* keys from the server perspective.
    keys.header.remote.decrypt(pn_offset, &mut packet);
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    let header_len = pn_offset.checked_add(pn_len)?;
    let pn_bytes = packet.get(pn_offset..header_len)?;
    let packet_number = pn_bytes
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let mut ciphertext = BytesMut::from(packet.get(header_len..)?);
    let clear = keys
        .packet
        .remote
        .decrypt(packet_number, &packet[..header_len], &mut ciphertext)
        .ok()
        .map(|()| ciphertext.to_vec());
    packet.zeroize();
    ciphertext.as_mut().zeroize();
    clear
}

/// QUIC CRYPTO has offset and length (RFC 9000). A fresh first ClientHello
/// must start at offset zero. This parser accepts only CRYPTO and PADDING
/// frames for this initial-flight probe; it is not a general QUIC parser.
fn extract_first_crypto(plain: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    let mut result = None;
    while at < plain.len() {
        let frame = varint(plain, &mut at)?;
        match frame {
            0 => {} // PADDING
            6 => {
                let offset = varint(plain, &mut at)?;
                let len = varint(plain, &mut at)?;
                let body = field(plain, &mut at, len)?;
                if offset == 0 && result.is_none() {
                    result = Some(body);
                }
            }
            _ => return None,
        }
    }
    result
}

#[test]
fn initial_and_tls_decoders_reject_truncated_or_unverified_data() {
    for bad in [
        vec![],
        vec![0xc0; 100],
        vec![0x40; 1200],
        vec![0xd0; 1200],
        vec![0xc0; 1200],
    ] {
        assert!(initial_bounds(&bad).is_none());
    }
    assert!(hello_shape(&[]).is_none());
    assert!(hello_shape(&[1, 0, 0, 9, 0]).is_none());
    assert!(extract_first_crypto(&[6, 0, 5, 1]).is_none());
    assert!(extract_first_crypto(&[7, 0, 5, 1, 2, 3, 4, 5]).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn true_wire_initial_exposes_tls13_sni_h3_alpn_and_quic_params_without_server_secret() {
    timeout(DEADLINE, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key_bytes = cert.key_pair.serialize_der();
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key_bytes.clone()).into(),
        )
        .unwrap();
        let destination = server.local_addr().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();

        // Same crypto provider, but an INDEPENDENT certificate and key:
        // successful decrypt proves Initial keys are publicly derivable and
        // DO NOT require the live server's private key or trusted CA.
        let independent = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut crypto_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![independent.cert.der().clone()],
            PrivatePkcs8KeyDer::from(independent.key_pair.serialize_der()).into(),
        )
        .unwrap();
        crypto_tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicServerConfig::try_from(crypto_tls).unwrap();

        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let witness_addr = front.local_addr().unwrap();
        let (first_tx, first_rx) = oneshot::channel::<Vec<u8>>();
        let relay = tokio::spawn(async move {
            let mut first = Some(first_tx);
            let mut peer = None;
            let mut upstream = [0u8; 65_536];
            let mut downstream = [0u8; 65_536];
            for _ in 0..256 {
                tokio::select! {
                    received = front.recv_from(&mut upstream) => {
                        let Ok((len, address)) = received else { break };
                        if peer.is_none() { peer = Some(address); }
                        if peer != Some(address) { continue; }
                        if let Some(sender) = first.take() {
                            let _ = sender.send(upstream[..len].to_vec());
                        }
                        if back.send_to(&upstream[..len], destination).await.is_err() {
                            break;
                        }
                    }
                    received = back.recv_from(&mut downstream) => {
                        let Ok((len, sender)) = received else { break };
                        if sender != destination { continue; }
                        if let Some(address) = peer {
                            if front.send_to(&downstream[..len], address).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let (service_done_tx, service_done_rx) = oneshot::channel::<()>();
        let service = tokio::spawn(async move {
            let conn = accept(server.accept().await.unwrap()).await.unwrap();
            let _ = service_done_rx.await;
            conn.close(0u32.into(), b"research-only");
        });
        let connection = connect(&client, witness_addr, "localhost").await.unwrap();

        let mut datagram = first_rx.await.unwrap();
        let mut plaintext = decrypt_initial(&datagram, &crypto)
            .expect("Quinn must decrypt actual first client packet using public Initial keys");
        let shape = hello_shape(
            extract_first_crypto(&plaintext).expect("Initial must contain TLS ClientHello CRYPTO"),
        )
        .expect("complete first-flight TLS1.3 ClientHello");
        assert!(shape.tls13);
        assert!(shape.h3_alpn);
        assert!(shape.sni_present);
        assert!(shape.quic_transport_parameters);
        assert!(shape.cipher_count > 0);
        assert!(shape.extension_count > 3);
        // This is visibility evidence, NOT a claim of matching a browser.
        assert!(
            !shape.alps_present,
            "baseline rustls H3 changed; re-evaluate F-13 fingerprint"
        );
        assert!(
            !shape.grease_extension,
            "baseline rustls H3 changed; re-evaluate F-13 fingerprint"
        );

        // AEAD must reject a modified ciphertext instead of furnishing
        // untrusted/partial CRYPTO bytes to the observer's parser.
        let (_, _, packet_len) = initial_bounds(&datagram).unwrap();
        datagram[packet_len - 1] ^= 1;
        assert!(decrypt_initial(&datagram, &crypto).is_none());
        datagram.zeroize();
        plaintext.zeroize();
        connection.close(0u32.into(), b"done");
        let _ = service_done_tx.send(());
        service.await.unwrap();
        relay.abort();
        client.close(0u32.into(), b"done");
    })
    .await
    .expect("research-only first QUIC Initial visibility fixture met deadline");
}
