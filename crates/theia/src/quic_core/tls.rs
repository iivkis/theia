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

}
