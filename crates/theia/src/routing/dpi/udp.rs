//! UDP classification and independent reachability probes. No application-payload mutation.
use super::quic;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
const STUN_LIMIT: usize = 16;
const STUN_TTL: Duration = Duration::from_secs(30);
const CLASSIFY_BUDGET: Duration = Duration::from_millis(30);
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stun {
    method: u16,
    class: u8,
    transaction: [u8; 12],
}
pub(crate) fn stun(data: &[u8]) -> Option<Stun> {
    let header = data.get(..20)?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if kind & 0xc000 != 0 || len % 4 != 0 || len + 20 != data.len() || header[4..8] != COOKIE {
        return None;
    }
    let mut rest = &data[20..];
    let mut count = 0;
    while !rest.is_empty() {
        let h = rest.get(..4)?;
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        rest = rest.get(4 + ((len + 3) & !3)..)?;
        count += 1;
        if count > 256 {
            return None;
        }
    }
    Some(Stun {
        method: (kind & 0xf) | ((kind >> 1) & 0x70) | ((kind >> 2) & 0xf80),
        class: (((kind >> 4) & 1) | ((kind >> 7) & 2)) as u8,
        transaction: header[8..20].try_into().ok()?,
    })
}
impl Stun {
    pub(crate) fn matches_response(self, response: Self) -> bool {
        self.class == 0
            && matches!(response.class, 2 | 3)
            && self.method == response.method
            && self.transaction == response.transaction
    }
}
/// A deliberately narrow STUN Binding subset. TURN, ICE credentials and
/// unknown attributes are never admitted by the local Binding strategy.
pub(crate) fn plain_binding(data: &[u8]) -> Option<Stun> {
    let message = stun(data)?;
    if message.method != 1 || message.class != 0 || data.len() > 512 {
        return None;
    }
    let mut rest = &data[20..];
    let mut software = false;
    while !rest.is_empty() {
        let kind = u16::from_be_bytes(rest[..2].try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(rest[2..4].try_into().ok()?));
        let end = 4 + ((len + 3) & !3);
        match kind {
            0x8022 if !software && len <= 128 => software = true,
            0x8028 if len == 4 && end == rest.len() && fingerprint(data) => {}
            _ => return None,
        }
        rest = &rest[end..];
    }
    Some(message)
}

fn fingerprint(data: &[u8]) -> bool {
    let Some(end) = data.len().checked_sub(8) else {
        return false;
    };
    if data[end..end + 4] != [0x80, 0x28, 0, 4] {
        return false;
    }
    let mut crc = flate2::Crc::new();
    crc.update(&data[..end]);
    (crc.sum() ^ 0x5354554e).to_be_bytes() == data[end + 4..]
}

fn binding_success(data: &[u8]) -> Option<Stun> {
    let message = stun(data)?;
    if message.method != 1 || message.class != 2 || data.len() > 512 {
        return None;
    }
    let mut rest = &data[20..];
    let mut mapped = false;
    while !rest.is_empty() {
        let kind = u16::from_be_bytes(rest[..2].try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(rest[2..4].try_into().ok()?));
        let end = 4 + ((len + 3) & !3);
        let value = &rest[4..4 + len];
        match kind {
            0x0020
                if !mapped
                    && ((len == 8 && value.starts_with(&[0, 1]))
                        || (len == 20 && value.starts_with(&[0, 2]))) =>
            {
                if (u16::from_be_bytes(value[2..4].try_into().ok()?) ^ 0x2112) == 0 {
                    return None;
                }
                mapped = true;
            }
            0x8028 if len == 4 && end == rest.len() && fingerprint(data) => {}
            // Unknown comprehension-required attributes or integrity fields
            // cannot be validated by this deliberately credential-free mode.
            0x0000..=0x7fff | 0x8028 => return None,
            _ => {}
        }
        rest = &rest[end..];
    }
    mapped.then_some(message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingStrategy {
    Fingerprint,
    Plain,
}

/// RFC 8489 optional FINGERPRINT on an otherwise unprotected Binding request.
/// Existing attributes, transaction ID, and already-present FINGERPRINT are
/// preserved. No MESSAGE-INTEGRITY, TURN or ICE messages can enter this path.
pub(crate) fn prepare_binding(
    data: &[u8],
    strategy: BindingStrategy,
) -> Option<std::borrow::Cow<'_, [u8]>> {
    plain_binding(data)?;
    // Walk validated TLVs: a SOFTWARE value can contain arbitrary bytes
    // resembling the final attribute header, but is not a FINGERPRINT.
    let mut rest = &data[20..];
    let mut has_fingerprint = false;
    while !rest.is_empty() {
        let kind = u16::from_be_bytes(rest[..2].try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(rest[2..4].try_into().ok()?));
        has_fingerprint |= kind == 0x8028;
        rest = &rest[4 + ((len + 3) & !3)..];
    }
    if strategy == BindingStrategy::Plain || has_fingerprint {
        return Some(std::borrow::Cow::Borrowed(data));
    }
    let len = u16::try_from(data.len().checked_sub(20)?.checked_add(8)?).ok()?;
    if usize::from(len) + 20 > 512 {
        return None;
    }
    let mut result = Vec::with_capacity(data.len() + 8);
    result.extend_from_slice(data);
    result[2..4].copy_from_slice(&len.to_be_bytes());
    let mut crc = flate2::Crc::new();
    crc.update(&result);
    result.extend([0x80, 0x28, 0, 4]);
    result.extend((crc.sum() ^ 0x5354554e).to_be_bytes());
    Some(std::borrow::Cow::Owned(result))
}

/// One independent CSPRNG Binding request to the connected peer. This is
/// reachability evidence only; no STUN MESSAGE-INTEGRITY key is available.
pub(super) async fn probe_stun(
    socket: &tokio::net::UdpSocket,
    strategy: BindingStrategy,
) -> Option<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut request = [0u8; 20];
    request[1] = 1;
    request[4..8].copy_from_slice(&COOKIE);
    SystemRandom::new().fill(&mut request[8..]).ok()?;
    let expected = plain_binding(&request)?;
    let packet = prepare_binding(&request, strategy)?;
    crate::udp_relay::send_datagram(socket, &packet)
        .await
        .ok()?;
    let mut response = [0; 513];
    // The caller imposes the absolute time budget. Also bound invalid input.
    for _ in 0..8 {
        let n = socket.recv(&mut response).await.ok()?;
        if binding_success(&response[..n]).is_some_and(|actual| expected.matches_response(actual)) {
            return Some(());
        }
    }
    None
}

/// Correlate only application requests actually admitted to the local
/// Binding relay, independent of the passive SOCKS observer and probe.
#[derive(Default)]
pub(crate) struct BindingTransactions(VecDeque<(Stun, Instant)>);
impl BindingTransactions {
    pub(crate) fn admit(&mut self, data: &[u8]) -> bool {
        let Some(message) = plain_binding(data) else {
            return false;
        };
        let now = Instant::now();
        self.0.retain(|(_, expires)| *expires > now);
        if self.0.iter().any(|(old, _)| *old == message) {
            return true;
        }
        if self.0.len() >= STUN_LIMIT {
            return false;
        }
        self.0.push_back((message, now + STUN_TTL));
        true
    }

    pub(crate) fn accept(&mut self, data: &[u8]) -> bool {
        let now = Instant::now();
        self.0.retain(|(_, expires)| *expires > now);
        let Some(response) = binding_success(data) else {
            return false;
        };
        let Some(index) = self
            .0
            .iter()
            .position(|(request, _)| request.matches_response(response))
        else {
            return false;
        };
        self.0.remove(index);
        true
    }
}

/// Classification is not peer authentication. QUIC versions remain distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    Pending,
    QuicH3(String),
    QuicV2H3(String),
    StunBinding,
    Stun,
    Other,
}

#[derive(Default)]
pub(crate) struct Observer {
    quic: quic::Observer,
    done: bool,
    stun_flow: bool,
    classification_deadline: Option<tokio::time::Instant>,
    requests: VecDeque<(Stun, Instant)>,
}
impl Observer {
    fn request(&mut self, message: Stun) {
        if message.class != 0 {
            return;
        }
        let now = Instant::now();
        self.requests
            .retain(|(old, expires)| *old != message && *expires > now);
        if self.requests.len() >= STUN_LIMIT {
            self.requests.pop_front();
        }
        self.requests.push_back((message, now + STUN_TTL));
    }
    pub(crate) fn classification_deadline(&self) -> tokio::time::Instant {
        self.classification_deadline
            .unwrap_or_else(tokio::time::Instant::now)
    }

    pub(crate) fn outgoing(&mut self, data: &[u8]) -> Candidate {
        if self.stun_flow {
            if let Some(message) = stun(data) {
                self.request(message);
            }
            return Candidate::Stun;
        }
        if self.done {
            return Candidate::Other;
        }
        if let Some(message) = stun(data) {
            self.request(message);
            self.stun_flow = true;
            self.done = true;
            crate::traffic::udp_stun_flow();
            return if plain_binding(data).is_some() {
                Candidate::StunBinding
            } else {
                Candidate::Stun
            };
        }
        let deadline = *self
            .classification_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + CLASSIFY_BUDGET);
        if tokio::time::Instant::now() >= deadline {
            self.done = true;
            return Candidate::Other;
        }
        let result = self.quic.observe(data);
        if tokio::time::Instant::now() >= deadline {
            self.done = true;
            return Candidate::Other;
        }
        match result {
            quic::Result::Pending => Candidate::Pending,
            quic::Result::Hello { name, version, h3 } => {
                self.done = true;
                crate::traffic::udp_quic_flow();
                match (version, h3) {
                    (crate::reality_quic_wire::V1, true) => Candidate::QuicH3(name),
                    (crate::reality_quic_wire::V2, true) => Candidate::QuicV2H3(name),
                    _ => Candidate::Other,
                }
            }
            quic::Result::Unsupported => {
                self.done = true;
                Candidate::Other
            }
        }
    }
    pub(crate) fn incoming(&mut self, data: &[u8]) {
        if !self.stun_flow {
            return;
        }
        self.requests
            .retain(|(_, expires)| *expires > Instant::now());
        if let Some(response) = stun(data) {
            if let Some(index) = self
                .requests
                .iter()
                .position(|(request, _)| request.matches_response(response))
            {
                self.requests.remove(index);
                crate::traffic::udp_stun_response();
            }
        }
    }
}

/// Only a pending initial flight waits; other UDP does not incur this delay.
/// The flow task never consumes queued application datagrams during detection.
pub(crate) async fn await_candidate(
    mut classification: tokio::sync::watch::Receiver<Candidate>,
    deadline: tokio::time::Instant,
) -> Candidate {
    let initial = classification.borrow_and_update().clone();
    // A complete candidate published within the observer's deadline remains
    // valid even if the worker is scheduled late. Pending input gets no
    // fresh classification budget when the worker starts.
    if initial != Candidate::Pending {
        return initial;
    }
    if tokio::time::Instant::now() >= deadline {
        return Candidate::Other;
    }
    let ready = tokio::time::timeout_at(
        deadline,
        classification.wait_for(|value| *value != Candidate::Pending),
    )
    .await;
    match ready {
        Ok(Ok(value)) => value.clone(),
        _ => Candidate::Other,
    }
}
/// Probe independently with an ordinary, strictly verified QUIC connection.
/// The application flight is never sent by this probe. A successful probe
/// demonstrates reachability for this name/IP/ALPN, not evasion or app identity.
pub(super) async fn probe_quic(
    name: &str,
    address: std::net::SocketAddr,
    scope: Option<crate::network_scope::Scope>,
    config: std::sync::Arc<rustls::ClientConfig>,
    version: crate::quic_core::wire::Version,
) -> Option<()> {
    use crate::quic_core::{dial, negotiation::VersionPolicy};
    let mut tls = (*config).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let name = rustls::pki_types::ServerName::try_from(name.to_owned()).ok()?;
    let (negotiated, session) = dial::connect(
        address,
        name,
        std::sync::Arc::new(tls),
        scope.map(|scope| scope.bind_address()),
        VersionPolicy::exact(version),
        Duration::from_secs(5),
    )
    .await
    .ok()?;
    if negotiated != version {
        return None;
    }
    dial::close_probe(session).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn independent_quic_probe_verifies_name_and_h3() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let config = super::super::tls::tls_config(roots).unwrap();
        let endpoint = crate::quinn_reference::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(connection) = incoming.await {
                    // Keep the fixture alive until the independently
                    // authenticated client closes; avoid handshake-close races.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        connection.closed(),
                    )
                    .await;
                }
            }
        });
        let deadline = std::time::Duration::from_secs(5);
        assert!(tokio::time::timeout(
            deadline,
            probe_quic(
                "localhost",
                addr,
                None,
                config.clone(),
                crate::quic_core::wire::Version::V1
            )
        )
        .await
        .unwrap()
        .is_some());
        assert!(tokio::time::timeout(
            deadline,
            probe_quic(
                "wrong.invalid",
                addr,
                None,
                config,
                crate::quic_core::wire::Version::V1
            )
        )
        .await
        .unwrap()
        .is_none());
        serving.abort();
    }

    #[tokio::test]
    async fn independent_v2_only_probe_never_negotiates_v1_or_reuses_v1_evidence() {
        use crate::quic_core::lifecycle::ShutdownPhase;
        use crate::quic_core::{
            handshake_udp, listener::Listener, negotiation::VersionPolicy, wire::Version,
        };
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::sync::Arc;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let client_tls = super::super::tls::tls_config(roots).unwrap();
        let mut server_tls = crate::transport_policy::Carrier::H3
            .server_tls(
                vec![der],
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        server_tls.send_tls13_tickets = 0;
        let server_tls = Arc::new(server_tls);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let mut listener =
            Listener::with_versions(socket, 4, VersionPolicy::exact(Version::V2)).unwrap();
        tokio::time::timeout(Duration::from_secs(12), async {
            let server = async {
                let candidate = listener.accept().await.unwrap();
                let mut session = handshake_udp::accept(candidate, server_tls).await.unwrap();
                while session.shutdown_phase() == ShutdownPhase::Open {
                    session.flush(Instant::now()).await.unwrap();
                    session.recv(Duration::from_millis(10)).await.unwrap();
                }
            };
            let client = async {
                // A v2-only server may return VN; exact-v1 must still fail.
                assert!(
                    probe_quic("localhost", addr, None, client_tls.clone(), Version::V1)
                        .await
                        .is_none()
                );
                assert!(probe_quic("localhost", addr, None, client_tls, Version::V2)
                    .await
                    .is_some());
            };
            tokio::select! {
                _ = server => panic!("server closed before verified v2 probe completed"),
                () = client => {}
            }
        })
        .await
        .unwrap();
    }

    fn h3_hello() -> Vec<u8> {
        let mut hello = super::super::tls::fixture("example.org");
        // Fixture has exactly one extension block containing SNI. Add h3 ALPN.
        let ext = [0, 16, 0, 5, 0, 3, 2, b'h', b'3'];
        let ext_len = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let n = u16::from_be_bytes([hello[ext_len], hello[ext_len + 1]]) + ext.len() as u16;
        hello[ext_len..ext_len + 2].copy_from_slice(&n.to_be_bytes());
        hello.extend(ext);
        let record_len = (hello.len() - 5) as u16;
        hello[3..5].copy_from_slice(&record_len.to_be_bytes());
        let body_len = (hello.len() - 9) as u32;
        hello[6..9].copy_from_slice(&body_len.to_be_bytes()[1..]);
        hello.split_off(5)
    }

    #[tokio::test]
    async fn fragmented_classification_is_bounded_and_sticky() {
        let hello = h3_hello();
        let packets =
            crate::reality_quic_wire::test_initial_parts(crate::reality_quic_wire::V1, &hello);
        let mut observer = Observer::default();
        assert_eq!(observer.outgoing(&packets[0]), Candidate::Pending);
        let (tx, rx) = tokio::sync::watch::channel(Candidate::Pending);
        let complete = observer.outgoing(&packets[1]);
        assert_eq!(complete, Candidate::QuicH3("example.org".into()));
        tx.send(complete.clone()).unwrap();
        assert_eq!(
            await_candidate(rx, observer.classification_deadline()).await,
            complete
        );
        let (_tx, rx) = tokio::sync::watch::channel(Candidate::Pending);
        assert_eq!(
            await_candidate(rx, tokio::time::Instant::now()).await,
            Candidate::Other
        );
    }

    #[tokio::test]
    async fn late_initial_fragment_cannot_authorize_local_candidate() {
        let hello = h3_hello();
        let packets =
            crate::reality_quic_wire::test_initial_parts(crate::reality_quic_wire::V1, &hello);
        let mut observer = Observer::default();
        assert_eq!(observer.outgoing(&packets[0]), Candidate::Pending);
        observer.classification_deadline = Some(tokio::time::Instant::now());
        assert_eq!(observer.outgoing(&packets[1]), Candidate::Other);
        assert_eq!(observer.outgoing(&packets[1]), Candidate::Other);
    }

    #[test]
    fn quic_candidate_requires_h3_and_distinguishes_v1_v2() {
        let hello = h3_hello();
        for version in [crate::reality_quic_wire::V1, crate::reality_quic_wire::V2] {
            let packet = crate::reality_quic_wire::test_initial(version, &hello);
            let expected = if version == crate::reality_quic_wire::V1 {
                Candidate::QuicH3("example.org".into())
            } else {
                Candidate::QuicV2H3("example.org".into())
            };
            assert_eq!(Observer::default().outgoing(&packet), expected);
        }
        let plain = super::super::tls::fixture("example.org");
        let packet =
            crate::reality_quic_wire::test_initial(crate::reality_quic_wire::V1, &plain[5..]);
        assert_eq!(Observer::default().outgoing(&packet), Candidate::Other);
    }

    #[test]
    fn stun_concurrent_transactions_retransmission_and_expiry() {
        let mut observer = Observer::default();
        let request = |id: u8| {
            let mut bytes = vec![0, 1, 0, 0];
            bytes.extend(COOKIE);
            bytes.extend([id; 12]);
            bytes
        };
        for id in 0..=STUN_LIMIT as u8 {
            assert_eq!(
                observer.outgoing(&request(id)),
                if id == 0 {
                    Candidate::StunBinding
                } else {
                    Candidate::Stun
                }
            );
        }
        assert_eq!(observer.requests.len(), STUN_LIMIT);
        observer.outgoing(&request(1));
        assert_eq!(observer.requests.len(), STUN_LIMIT);
        let mut response = request(1);
        response[0] = 1;
        observer.incoming(&response);
        observer.incoming(&response);
        assert_eq!(observer.requests.len(), STUN_LIMIT - 1);
        observer
            .requests
            .iter_mut()
            .for_each(|(_, expiry)| *expiry = Instant::now());
        observer.incoming(&response);
        assert!(observer.requests.is_empty());
    }

    fn binding_response(request: &[u8]) -> Vec<u8> {
        let mut response = request[..20].to_vec();
        response[0] = 1;
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response.extend([0, 0x20, 0, 8, 0, 1, 0x21, 0x13, 1, 2, 3, 4]);
        response
    }

    #[test]
    fn optional_fingerprint_preserves_transaction_and_is_idempotent() {
        let mut request = vec![0, 1, 0, 0];
        request.extend(COOKIE);
        request.extend([7; 12]);
        let packet = prepare_binding(&request, BindingStrategy::Fingerprint).unwrap();
        assert_eq!(packet.len(), request.len() + 8);
        assert_eq!(plain_binding(&packet), plain_binding(&request));
        assert!(fingerprint(&packet));
        assert!(matches!(
            prepare_binding(&packet, BindingStrategy::Fingerprint),
            Some(std::borrow::Cow::Borrowed(_))
        ));
        assert_eq!(
            prepare_binding(&request, BindingStrategy::Plain)
                .unwrap()
                .as_ref(),
            request.as_slice()
        );
        let mut bad = packet.into_owned();
        *bad.last_mut().unwrap() ^= 1;
        assert!(prepare_binding(&bad, BindingStrategy::Fingerprint).is_none());
    }

    #[test]
    fn binding_admission_rejects_credentials_and_unmatched_responses() {
        let mut request = vec![0, 1, 0, 0];
        request.extend(COOKIE);
        request.extend([7; 12]);
        let mut credential = request.clone();
        credential[3] = 8;
        credential.extend([0, 6, 0, 1, b'x', 0, 0, 0]);
        assert_eq!(Observer::default().outgoing(&credential), Candidate::Stun);
        assert!(plain_binding(&credential).is_none());
        let mut tracker = BindingTransactions::default();
        assert!(tracker.admit(&request));
        let response = binding_response(&request);
        let mut wrong = response.clone();
        wrong[19] ^= 1;
        assert!(!tracker.accept(&wrong));
        assert!(tracker.accept(&response));
        assert!(!tracker.accept(&response));
        assert!(!tracker.admit(&credential));
        assert!(plain_binding(&[]).is_none());
    }

    #[tokio::test]
    async fn active_binding_probe_ignores_wrong_transaction_and_malformed_mapping() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = crate::udp_relay::connect(target.local_addr().unwrap())
            .await
            .unwrap();
        let server = async {
            let mut buf = [0; 512];
            let (n, peer) = target.recv_from(&mut buf).await.unwrap();
            assert!(fingerprint(&buf[..n]));
            let response = binding_response(&buf[..n]);
            let mut wrong = response.clone();
            wrong[19] ^= 1;
            target.send_to(&wrong, peer).await.unwrap();
            wrong = response.clone();
            wrong[25] = 3;
            target.send_to(&wrong, peer).await.unwrap();
            target.send_to(&response, peer).await.unwrap();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(probe_stun(&socket, BindingStrategy::Fingerprint), server)
        })
        .await
        .unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn plain_probe_is_independent_and_invalid_responses_do_not_pass() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = crate::udp_relay::connect(target.local_addr().unwrap())
            .await
            .unwrap();
        let server = async {
            let mut buf = [0; 512];
            let (n, peer) = target.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 20);
            assert!(plain_binding(&buf[..n]).is_some());
            let mut wrong = binding_response(&buf[..n]);
            wrong[19] ^= 1;
            for _ in 0..8 {
                target.send_to(&wrong, peer).await.unwrap();
            }
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(probe_stun(&socket, BindingStrategy::Plain), server)
        })
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn stun_lengths_padding_and_transaction() {
        let mut req = vec![0, 1, 0, 0];
        req.extend(COOKIE);
        req.extend([7; 12]);
        let mut res = req.clone();
        res[0] = 1;
        assert!(stun(&req).unwrap().matches_response(stun(&res).unwrap()));
        res[19] ^= 1;
        assert!(!stun(&req).unwrap().matches_response(stun(&res).unwrap()));
        let mut attr = req.clone();
        attr[3] = 8;
        attr.extend([0x80, 0x22, 0, 1, b'x', 0, 0, 0]);
        assert!(stun(&attr).is_some());
        attr[23] = 9;
        assert!(stun(&attr).is_none());
        for n in 0..req.len() {
            assert!(stun(&req[..n]).is_none());
        }
        let mut observer = Observer::default();
        assert_eq!(observer.outgoing(&req), Candidate::StunBinding);
        res[19] ^= 1;
        observer.incoming(&res);
        assert!(observer.requests.is_empty());
    }
}
