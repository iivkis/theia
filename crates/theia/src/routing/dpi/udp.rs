//! Passive UDP classification. No integrity-field or encrypted-payload mutation.
use super::quic;
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
/// Classification is not peer authentication. Only a complete first QUIC
/// v1 ClientHello offering h3 may request independent authenticated evidence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    QuicH3(String),
    Stun,
    Other,
}

#[derive(Default)]
pub(crate) struct Observer {
    quic: quic::Observer,
    done: bool,
    request: Option<Stun>,
}
impl Observer {
    pub(crate) fn outgoing(&mut self, data: &[u8]) -> Candidate {
        if self.done {
            return Candidate::Other;
        }
        if let Some(message) = stun(data) {
            self.request = Some(message);
            self.done = true;
            crate::traffic::udp_stun_flow();
            return Candidate::Stun;
        }
        match self.quic.observe(data) {
            quic::Result::Pending => {}
            quic::Result::Hello { name, version, h3 } => {
                self.done = true;
                crate::traffic::udp_quic_flow();
                if version == crate::reality_quic_wire::V1 && h3 {
                    return Candidate::QuicH3(name);
                }
            }
            quic::Result::Unsupported => self.done = true,
        }
        Candidate::Other
    }
    pub(crate) fn incoming(&mut self, data: &[u8]) {
        if self.request.is_some_and(|request| {
            stun(data).is_some_and(|response| request.matches_response(response))
        }) {
            self.request = None;
            crate::traffic::udp_stun_response();
        }
    }
}
/// Probe independently with an ordinary, strictly verified QUIC connection.
/// The application flight is never sent by this probe. A successful probe
/// demonstrates reachability for this name/IP/ALPN, not evasion or app identity.
pub(super) async fn probe_quic(
    name: &str,
    address: std::net::SocketAddr,
    config: std::sync::Arc<rustls::ClientConfig>,
) -> Option<()> {
    let mut tls = (*config).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).ok()?;
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    config.transport_config(crate::quic_transport::transport_config());
    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut endpoint = quinn::Endpoint::client(bind.parse().ok()?).ok()?;
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
                let _ = incoming.await;
            }
        });
        let deadline = std::time::Duration::from_secs(5);
        assert!(tokio::time::timeout(deadline, probe_quic("localhost", addr, config.clone())).await.unwrap().is_some());
        assert!(tokio::time::timeout(deadline, probe_quic("wrong.invalid", addr, config)).await.unwrap().is_none());
        serving.abort();
    }

    #[test]
    fn quic_candidate_requires_v1_h3_and_complete_initial() {
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
        for version in [crate::reality_quic_wire::V1, crate::reality_quic_wire::V2] {
            let packet = crate::reality_quic_wire::test_initial(version, &hello[5..]);
            let expected = if version == crate::reality_quic_wire::V1 { Candidate::QuicH3("example.org".into()) } else { Candidate::Other };
            assert_eq!(Observer::default().outgoing(&packet), expected);
        }
        let plain = super::super::tls::fixture("example.org");
        let packet = crate::reality_quic_wire::test_initial(crate::reality_quic_wire::V1, &plain[5..]);
        assert_eq!(Observer::default().outgoing(&packet), Candidate::Other);
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
        assert!(observer.request.is_none());
    }
}
