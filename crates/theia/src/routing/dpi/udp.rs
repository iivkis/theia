//! Passive UDP classification. No integrity-field or encrypted-payload mutation.
use super::quic;
use std::{collections::VecDeque, time::{Duration, Instant}};
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
/// Classification is not peer authentication. Only a complete bounded initial
/// QUIC v1 flight offering h3 may request independent authenticated evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    Pending,
    QuicH3(String),
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
        if message.class != 0 { return; }
        let now = Instant::now();
        self.requests.retain(|(old, expires)| *old != message && *expires > now);
        if self.requests.len() >= STUN_LIMIT { self.requests.pop_front(); }
        self.requests.push_back((message, now + STUN_TTL));
    }
    pub(crate) fn classification_deadline(&self) -> tokio::time::Instant {
        self.classification_deadline.unwrap_or_else(tokio::time::Instant::now)
    }

    pub(crate) fn outgoing(&mut self, data: &[u8]) -> Candidate {
        if self.stun_flow {
            if let Some(message) = stun(data) { self.request(message); }
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
            return Candidate::Stun;
        }
        let deadline = *self.classification_deadline.get_or_insert_with(
            || tokio::time::Instant::now() + CLASSIFY_BUDGET,
        );
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
                if version == crate::reality_quic_wire::V1 && h3 {
                    Candidate::QuicH3(name)
                } else {
                    Candidate::Other
                }
            }
            quic::Result::Unsupported => {
                self.done = true;
                Candidate::Other
            }
        }
    }
    pub(crate) fn incoming(&mut self, data: &[u8]) {
        if !self.stun_flow { return; }
        self.requests.retain(|(_, expires)| *expires > Instant::now());
        if let Some(response) = stun(data) {
            if let Some(index) = self.requests.iter().position(|(request, _)| request.matches_response(response)) {
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
    if initial != Candidate::Pending { return initial; }
    if tokio::time::Instant::now() >= deadline { return Candidate::Other; }
    let ready = tokio::time::timeout_at(deadline, classification.wait_for(|value| *value != Candidate::Pending)).await;
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
) -> Option<()> {
    let mut tls = (*config).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).ok()?;
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    config.transport_config(crate::quic_transport::transport_config());
    let bind = match scope {
        Some(scope) => scope.bind_address(),
        None => (if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).parse().ok()?,
    };
    let mut endpoint = quinn::Endpoint::client(bind).ok()?;
    endpoint.set_default_client_config(config);
    let connection = crate::quic_transport::connect(&endpoint, address, name).await.ok()?;
    connection.close(quinn::VarInt::from_u32(0), b"");
    Some(())
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
        let endpoint = crate::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(), vec![der],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        ).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(connection) = incoming.await {
                    // Keep the fixture alive until the independently
                    // authenticated client closes; avoid handshake-close races.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), connection.closed()).await;
                }
            }
        });
        let deadline = std::time::Duration::from_secs(5);
        assert!(tokio::time::timeout(deadline, probe_quic("localhost", addr, None, config.clone())).await.unwrap().is_some());
        assert!(tokio::time::timeout(deadline, probe_quic("wrong.invalid", addr, None, config)).await.unwrap().is_none());
        serving.abort();
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
        let packets = crate::reality_quic_wire::test_initial_parts(crate::reality_quic_wire::V1, &hello);
        let mut observer = Observer::default();
        assert_eq!(observer.outgoing(&packets[0]), Candidate::Pending);
        let (tx, rx) = tokio::sync::watch::channel(Candidate::Pending);
        let complete = observer.outgoing(&packets[1]);
        assert_eq!(complete, Candidate::QuicH3("example.org".into()));
        tx.send(complete.clone()).unwrap();
        assert_eq!(await_candidate(rx, observer.classification_deadline()).await, complete);
        let (_tx, rx) = tokio::sync::watch::channel(Candidate::Pending);
        assert_eq!(await_candidate(rx, tokio::time::Instant::now()).await, Candidate::Other);
    }

    #[tokio::test]
    async fn late_initial_fragment_cannot_authorize_local_candidate() {
        let hello = h3_hello();
        let packets = crate::reality_quic_wire::test_initial_parts(crate::reality_quic_wire::V1, &hello);
        let mut observer = Observer::default();
        assert_eq!(observer.outgoing(&packets[0]), Candidate::Pending);
        observer.classification_deadline = Some(tokio::time::Instant::now());
        assert_eq!(observer.outgoing(&packets[1]), Candidate::Other);
        assert_eq!(observer.outgoing(&packets[1]), Candidate::Other);
    }

    #[test]
    fn quic_candidate_requires_v1_h3_and_complete_initial() {
        let hello = h3_hello();
        for version in [crate::reality_quic_wire::V1, crate::reality_quic_wire::V2] {
            let packet = crate::reality_quic_wire::test_initial(version, &hello);
            let expected = if version == crate::reality_quic_wire::V1 { Candidate::QuicH3("example.org".into()) } else { Candidate::Other };
            assert_eq!(Observer::default().outgoing(&packet), expected);
        }
        let plain = super::super::tls::fixture("example.org");
        let packet = crate::reality_quic_wire::test_initial(crate::reality_quic_wire::V1, &plain[5..]);
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
            assert_eq!(observer.outgoing(&request(id)), Candidate::Stun);
        }
        assert_eq!(observer.requests.len(), STUN_LIMIT);
        observer.outgoing(&request(1));
        assert_eq!(observer.requests.len(), STUN_LIMIT);
        let mut response = request(1);
        response[0] = 1;
        observer.incoming(&response);
        observer.incoming(&response);
        assert_eq!(observer.requests.len(), STUN_LIMIT - 1);
        observer.requests.iter_mut().for_each(|(_, expiry)| *expiry = Instant::now());
        observer.incoming(&response);
        assert!(observer.requests.is_empty());
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
        assert_eq!(observer.outgoing(&req), Candidate::Stun);
        res[19] ^= 1;
        observer.incoming(&res);
        assert!(observer.requests.is_empty());
    }
}
