//! TLS 1.3 factories using the existing rustls QUIC API.
//! No packet I/O, application admission, transport parameter validation or
//! address validation is performed by these factories.
use super::wire::Version;
use rustls::{pki_types::ServerName, quic, ClientConfig, Error, ServerConfig};
use std::sync::Arc;

fn version(value: Version) -> quic::Version {
    match value {
        Version::V1 => quic::Version::V1,
        Version::V2 => quic::Version::V2,
    }
}

pub fn client(
    config: Arc<ClientConfig>,
    wire_version: Version,
    name: ServerName<'static>,
    params: Vec<u8>,
) -> Result<quic::Connection, Error> {
    if config.enable_early_data {
        return Err(Error::General("Theia QUIC forbids 0-RTT".into()));
    }
    quic::ClientConnection::new(config, version(wire_version), name, params)
        .map(quic::Connection::Client)
}

pub fn server(
    config: Arc<ServerConfig>,
    wire_version: Version,
    params: Vec<u8>,
) -> Result<quic::Connection, Error> {
    if config.max_early_data_size != 0 {
        return Err(Error::General("Theia QUIC forbids 0-RTT".into()));
    }
    quic::ServerConnection::new(config, version(wire_version), params)
        .map(quic::Connection::Server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};

    fn configs() -> (ClientConfig, ServerConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth().with_single_cert(vec![der.clone()], key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(der).unwrap();
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        server.alpn_protocols = vec![b"h3".to_vec()];
        client.alpn_protocols = vec![b"h3".to_vec()];
        (client, server)
    }

    // In-memory TLS handshake only. No encrypted QUIC packet is exchanged.
    fn transfer(source: &mut quic::Connection, dest: &mut quic::Connection) -> Result<bool, Error> {
        let mut changed = false;
        for _ in 0..8 {
            let mut bytes = Vec::new();
            let keys = source.write_hs(&mut bytes);
            if !bytes.is_empty() {
                dest.read_hs(&bytes)?;
                changed = true;
            }
            if keys.is_none() && bytes.is_empty() {
                break;
            }
        }
        Ok(changed)
    }

    #[test]
    fn tls13_v1_v2_and_hostname_verification() {
        for v in [Version::V1, Version::V2] {
            let (cc, sc) = configs();
            let mut c = client(Arc::new(cc), v, ServerName::try_from("localhost").unwrap(), vec![1, 1, 1]).unwrap();
            let mut s = server(Arc::new(sc), v, vec![1, 1, 2]).unwrap();
            for _ in 0..16 {
                let outgoing = transfer(&mut c, &mut s).unwrap();
                let incoming = transfer(&mut s, &mut c).unwrap();
                if !outgoing && !incoming { break; }
            }
            assert!(!c.is_handshaking());
            assert!(!s.is_handshaking());
            assert_eq!(c.alpn_protocol(), Some(b"h3".as_slice()));
            assert_eq!(s.alpn_protocol(), Some(b"h3".as_slice()));
            assert_eq!(c.quic_transport_parameters(), Some([1, 1, 2].as_slice()));
            assert_eq!(s.quic_transport_parameters(), Some([1, 1, 1].as_slice()));
            assert_eq!(
                c.export_keying_material([0; 32], b"test", None).unwrap(),
                s.export_keying_material([0; 32], b"test", None).unwrap(),
            );

            let (cc, sc) = configs();
            let mut c = client(Arc::new(cc), v, ServerName::try_from("wrong.invalid").unwrap(), vec![]).unwrap();
            let mut s = server(Arc::new(sc), v, vec![]).unwrap();
            transfer(&mut c, &mut s).unwrap();
            assert!(transfer(&mut s, &mut c).is_err());
        }
    }

    #[test]
    fn rejects_early_data_configuration() {
        let (mut cc, mut sc) = configs();
        cc.enable_early_data = true;
        sc.max_early_data_size = u32::MAX;
        assert!(client(Arc::new(cc), Version::V1, ServerName::try_from("localhost").unwrap(), vec![]).is_err());
        assert!(server(Arc::new(sc), Version::V2, vec![]).is_err());
    }
    #[test]
    fn crypto_driver_reassembles_and_separates_tls_levels() {
        use crate::quic_core::handshake::{Driver, Level};
        for v in [Version::V1, Version::V2] {
            let (cc, sc) = configs();
            let mut c = Driver::new(client(Arc::new(cc), v, ServerName::try_from("localhost").unwrap(), vec![1, 1, 1]).unwrap());
            let mut s = Driver::new(server(Arc::new(sc), v, vec![1, 1, 2]).unwrap());
            let first = c.poll_output().unwrap().unwrap();
            assert_eq!(first.level, Level::Initial);
            let split = first.data.len() / 2;
            s.receive(first.level, split as u64, &first.data[split..]).unwrap();
            assert!(s.poll_output().unwrap().is_none());
            s.receive(first.level, 0, &first.data[..split]).unwrap();
            // Synchronize each side's key transitions before passing the
            // next level's data, as a real packet engine must do.
            for _ in 0..16 {
                while let Some(f) = s.poll_output().unwrap() {
                    if !f.data.is_empty() { c.receive(f.level, f.offset, &f.data).unwrap(); }
                    if f.keys.is_some() {
                        while let Some(reply) = c.poll_output().unwrap() {
                            if !reply.data.is_empty() { s.receive(reply.level, reply.offset, &reply.data).unwrap(); }
                        }
                    }
                }
                while let Some(f) = c.poll_output().unwrap() {
                    if !f.data.is_empty() { s.receive(f.level, f.offset, &f.data).unwrap(); }
                }
                if c.tls_complete() && s.tls_complete() { break; }
            }
            assert!(c.tls_complete() && s.tls_complete());
            assert_eq!(c.negotiated_alpn(), Some(b"h3".as_slice()));
            assert_eq!(c.peer_parameters(), Some([1, 1, 2].as_slice()));
        }
    }

    #[tokio::test]
    async fn tls_application_keys_protect_bidirectional_loopback_streams() {
        use crate::quic_core::endpoint::LabSession;
        use rustls::quic::{KeyChange, Keys};
        use std::time::{Duration, Instant};
        use tokio::net::UdpSocket;

        fn move_hs(source: &mut quic::Connection, target: &mut quic::Connection,
                   application: &mut Option<Keys>) -> bool {
            let mut activity = false;
            for _ in 0..8 {
                let mut bytes = Vec::new();
                let change = source.write_hs(&mut bytes);
                let changed = change.is_some();
                if let Some(KeyChange::OneRtt { keys, .. }) = change { *application = Some(keys); }
                if !bytes.is_empty() { target.read_hs(&bytes).unwrap(); activity = true; }
                if !changed && bytes.is_empty() { break; }
            }
            activity
        }

        for version in [Version::V1, Version::V2] {
            let (cc, sc) = configs();
            let mut c = client(Arc::new(cc), version, ServerName::try_from("localhost").unwrap(), vec![1, 1, 1]).unwrap();
            let mut s = server(Arc::new(sc), version, vec![1, 1, 2]).unwrap();
            let mut ck = None;
            let mut sk = None;
            for _ in 0..16 {
                let a = move_hs(&mut c, &mut s, &mut ck);
                let b = move_hs(&mut s, &mut c, &mut sk);
                if !a && !b { break; }
            }
            assert!(!c.is_handshaking() && !s.is_handshaking());
            let ca = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let caddr = ca.local_addr().unwrap();
            let saddr = sa.local_addr().unwrap();
            let mut c = LabSession::connect(ca, saddr, false, [1; 8], [2; 8], ck.unwrap()).await.unwrap();
            let mut s = LabSession::connect(sa, caddr, true, [2; 8], [1; 8], sk.unwrap()).await.unwrap();
            let ci = c.open_uni().unwrap();
            let si = s.open_uni().unwrap();
            c.queue(ci, b"client stream", true).unwrap();
            s.queue(si, b"server stream", true).unwrap();
            let wait = Duration::from_secs(1);
            assert!(c.flush(Instant::now()).await.unwrap());
            assert!(s.recv(wait).await.unwrap());
            let mut data = [0; 13];
            assert_eq!(s.read(ci, &mut data).unwrap(), 13);
            assert_eq!(&data, b"client stream");
            assert!(s.finished(ci));
            assert!(s.flush(Instant::now()).await.unwrap()); // ACK first
            assert!(c.recv(wait).await.unwrap());
            assert_eq!(c.pending(), 0);
            assert!(s.flush(Instant::now()).await.unwrap());
            assert!(c.recv(wait).await.unwrap());
            assert_eq!(c.read(si, &mut data).unwrap(), 13);
            assert_eq!(&data, b"server stream");
            assert!(c.finished(si));
            assert!(c.flush(Instant::now()).await.unwrap());
            assert!(s.recv(wait).await.unwrap());
            assert_eq!(s.pending(), 0);
        }
    }

    #[tokio::test]
    async fn actual_udp_handshake_and_stream_v1_v2() {
        use crate::quic_core::handshake_udp::{establish, Config};
        use std::time::{Duration, Instant};
        use tokio::net::UdpSocket;

        for version in [Version::V1, Version::V2] {
            let (cc, mut sc) = configs();
            sc.send_tls13_tickets = 0;
            let ca = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let caddr = ca.local_addr().unwrap();
            let saddr = sa.local_addr().unwrap();
            let (c, s) = tokio::join!(
                establish(ca, saddr, version, [1; 8], [2; 8], Config::Client {
                    tls: Arc::new(cc), name: ServerName::try_from("localhost").unwrap(),
                }),
                establish(sa, caddr, version, [2; 8], [1; 8], Config::Server(Arc::new(sc))),
            );
            let mut c = c.unwrap();
            let mut s = s.unwrap();
            assert!(s.handshake_confirmed());
            assert!(!c.handshake_confirmed());
            assert!(c.update_keys().is_err());
            async fn pump(from: &mut crate::quic_core::endpoint::LabSession, to: &mut crate::quic_core::endpoint::LabSession) {
                for _ in 0..50 {
                    if from.flush(Instant::now()).await.unwrap() {
                        // Allow for stale handshake packets before the next 1-RTT.
                        for _ in 0..8 {
                            if to.recv(Duration::from_millis(100)).await.unwrap() { return; }
                        }
                        panic!("no protected application packet received");
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("scheduler did not send");
            }
            pump(&mut s, &mut c).await;
            assert!(c.handshake_confirmed());
            pump(&mut c, &mut s).await;
            let stream = c.open_bidi().unwrap();
            c.queue(stream, b"udp handshake", true).unwrap();
            pump(&mut c, &mut s).await;
            let mut out = [0; 13];
            assert_eq!(s.read(stream, &mut out).unwrap(), 13);
            assert_eq!(&out, b"udp handshake");
            assert!(s.finished(stream));
            pump(&mut s, &mut c).await;
            c.update_keys().unwrap();
            let second = c.open_uni().unwrap();
            c.queue(second, b"new key", true).unwrap();
            pump(&mut c, &mut s).await;
            assert_eq!(s.read(second, &mut out).unwrap(), 7);
            assert_eq!(&out[..7], b"new key");
            pump(&mut s, &mut c).await;
            s.queue(stream, b"response", true).unwrap();
            pump(&mut s, &mut c).await;
            assert_eq!(c.read(stream, &mut out).unwrap(), 8);
            assert_eq!(&out[..8], b"response");
            pump(&mut c, &mut s).await;
            let ongoing = c.open_bidi().unwrap();
            c.queue(ongoing, b"before", false).unwrap();
            pump(&mut c, &mut s).await;
            assert_eq!(s.read(ongoing, &mut out).unwrap(), 6);
            assert_eq!(&out[..6], b"before");
            pump(&mut s, &mut c).await;

            let moved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let moved_addr = moved.local_addr().unwrap();
            c.rebind(moved, Instant::now()).await.unwrap();
            let wait = Duration::from_secs(1);
            // The first authenticated packet only initiates validation.
            assert!(!s.recv(wait).await.unwrap());
            assert_eq!(s.peer_addr(), caddr);
            assert!(c.recv(wait).await.unwrap()); // challenge, sends response
            assert!(s.recv(wait).await.unwrap()); // authenticated response
            assert_eq!(s.peer_addr(), moved_addr);
            pump(&mut s, &mut c).await; // ACK the response
            pump(&mut c, &mut s).await; // ACK the challenge
            c.queue(ongoing, b"after", true).unwrap();
            pump(&mut c, &mut s).await;
            assert_eq!(s.read(ongoing, &mut out).unwrap(), 5);
            assert_eq!(&out[..5], b"after");
            assert!(s.finished(ongoing));
            pump(&mut s, &mut c).await;
            s.queue(ongoing, b"still open", true).unwrap();
            pump(&mut s, &mut c).await;
            assert_eq!(c.read(ongoing, &mut out).unwrap(), 10);
            assert_eq!(&out[..10], b"still open");
            use crate::quic_core::lifecycle::ShutdownPhase;
            c.close(42, Instant::now()).unwrap();
            assert!(c.open_uni().is_err());
            pump(&mut c, &mut s).await;
            assert_eq!(c.shutdown_phase(), ShutdownPhase::Closing);
            assert_eq!(s.shutdown_phase(), ShutdownPhase::Draining);
            assert!(s.open_bidi().is_err());
            assert!(!s.flush(Instant::now()).await.unwrap());
            let deadline = s.deadline().unwrap();
            assert!(!s.flush(deadline).await.unwrap());
            assert_eq!(s.shutdown_phase(), ShutdownPhase::Closed);
        }
    }

    #[test]
    fn bidi_and_replenishment_respects_direction_and_consumption() {
        use crate::quic_core::{flow::ReceiveFlow, send_flow::SendFlow};
        let mut send = SendFlow::new(false, 1, 4, 4).unwrap();
        send.enable_bidi(1, 1).unwrap();
        let id = send.open_bidi().unwrap();
        assert_eq!(id, 0);
        let mut receive = ReceiveFlow::new(true, 1, 1, 4, 4, 4).unwrap();
        receive.enable_local_bidi(1).unwrap();
        assert!(receive.insert(1, 0, b"x", false).is_err());
        receive.insert(id, 0, b"abcd", false).unwrap();
        let mut bytes = [0; 2];
        assert_eq!(receive.read_replenish(id, &mut bytes), Ok((2, 6, 6)));
        assert_eq!(&bytes, b"ab");
        receive.insert(id, 4, b"ef", true).unwrap();
        assert_eq!(receive.used(), 6);
        receive.register_local_bidi(1).unwrap();
        assert!(receive.insert(3, 0, b"x", false).is_err());
        send.register_peer_bidi(1).unwrap();
        assert!(send.register_peer_bidi(3).is_err());
        assert!(send.encode(1, b"ok", true).is_ok());
    }

    #[test]
    fn application_key_update_retains_packet_numbers_and_reordered_old_keys() {
        use crate::quic_core::{key_update::{Receiver, Sender}, packet::Error};
        use rustls::quic::{KeyChange, Keys, Secrets};
        use std::time::{Duration, Instant};

        fn move_hs(source: &mut quic::Connection, target: &mut quic::Connection,
                   application: &mut Option<(Keys, Secrets)>) -> bool {
            let mut activity = false;
            for _ in 0..8 {
                let mut bytes = Vec::new();
                let change = source.write_hs(&mut bytes);
                let changed = change.is_some();
                if let Some(KeyChange::OneRtt { keys, next }) = change { *application = Some((keys, next)); }
                if !bytes.is_empty() { target.read_hs(&bytes).unwrap(); activity = true; }
                if !changed && bytes.is_empty() { break; }
            }
            activity
        }

        for version in [Version::V1, Version::V2] {
            let (cc, sc) = configs();
            let mut c = client(Arc::new(cc), version, ServerName::try_from("localhost").unwrap(), vec![1, 1, 1]).unwrap();
            let mut s = server(Arc::new(sc), version, vec![1, 1, 2]).unwrap();
            let mut ck = None;
            let mut sk = None;
            for _ in 0..16 {
                let a = move_hs(&mut c, &mut s, &mut ck);
                let b = move_hs(&mut s, &mut c, &mut sk);
                if !a && !b { break; }
            }
            assert!(!c.is_handshaking() && !s.is_handshaking());
            let (ck, cn) = ck.unwrap();
            let (sk, sn) = sk.unwrap();
            let mut tx = Sender::new(ck.local, cn);
            let mut rx = Receiver::new(sk.remote, sn);
            let cid = [7; 8];
            let now = Instant::now();
            let end = now + Duration::from_secs(3);
            let (pn, first) = tx.seal(&cid, b"a").unwrap();
            assert_eq!(pn, 0);
            assert_eq!(rx.open(&cid, &first, now, end, true).unwrap().payload, b"a");
            assert!(tx.update(true).is_err());
            tx.acknowledged(pn);
            assert!(tx.update(false).is_err());
            let (_, old) = tx.seal(&cid, b"old").unwrap();
            tx.update(true).unwrap();
            assert!(tx.update(true).is_err());
            let (pn, new) = tx.seal(&cid, b"new").unwrap();
            assert_eq!(pn, 2);
            let mut corrupt = new.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert_eq!(rx.open(&cid, &corrupt, now, end, true), Err(Error::Crypto));
            assert_eq!(rx.open(&cid, &new, now, end, true).unwrap().number, 2);
            assert_eq!(rx.open(&cid, &old, now, end, true).unwrap().payload, b"old");
            assert_eq!(rx.open(&cid, &old, now, end, true), Err(Error::Duplicate));
            rx.expire(end);
            assert_eq!(rx.open(&cid, &old, end, end, true), Err(Error::TooOld));
            tx.acknowledged(pn);
            tx.update(true).unwrap();
            let (pn, next) = tx.seal(&cid, b"next").unwrap();
            assert_eq!(pn, 3);
            assert_eq!(rx.open(&cid, &next, end, end + Duration::from_secs(3), true).unwrap().payload, b"next");
        }
    }

}
