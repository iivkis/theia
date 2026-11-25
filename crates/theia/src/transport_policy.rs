//! Single versioned production resource and TLS contract for native H2/H3.
//! This is a Theia security policy, not a browser fingerprint or parity claim.
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::sync::Arc;

pub const VERSION: u32 = 1;
pub const MAX_HEADER_LIST_BYTES: u32 = 8192;
pub const MAX_BIDI_STREAMS: u32 = 32;
pub const MAX_QUIC_UNI_STREAMS: u32 = 8;
pub const QUIC_STREAM_RECEIVE_BYTES: u32 = 256 * 1024;
pub const QUIC_CONNECTION_RECEIVE_BYTES: u32 = 4 * 1024 * 1024;
pub const QUIC_SEND_WINDOW_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    H2,
    H3,
}

impl Carrier {
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::H2 => b"h2",
            Self::H3 => b"h3",
        }
    }

    pub(crate) fn accepts_alpn(self, negotiated: Option<&[u8]>) -> bool {
        negotiated == Some(self.alpn())
    }

    pub(crate) fn accepts_tls(
        self,
        version: Option<rustls::ProtocolVersion>,
        negotiated: Option<&[u8]>,
    ) -> bool {
        version == Some(rustls::ProtocolVersion::TLSv1_3) && self.accepts_alpn(negotiated)
    }

    pub(crate) fn configure_client(self, config: &mut ClientConfig) {
        config.alpn_protocols = vec![self.alpn().to_vec()];
        config.enable_early_data = false;
    }

    pub(crate) fn configure_server(self, config: &mut ServerConfig) {
        config.alpn_protocols = vec![self.alpn().to_vec()];
        config.max_early_data_size = 0;
    }

    /// PKI is always supplied explicitly. Identity-specific admission and
    /// resumption restrictions are applied separately by the identity layer.
    pub(crate) fn client_tls(self, roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
        if roots.is_empty() {
            return Err(rustls::Error::General("empty explicit trust store".into()));
        }
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        self.configure_client(&mut config);
        Ok(config)
    }

    pub(crate) fn server_tls(
        self,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, rustls::Error> {
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
        self.configure_server(&mut config);
        Ok(config)
    }

    pub(crate) fn h2_client(self) -> h2::client::Builder {
        assert_eq!(self, Self::H2);
        let mut builder = h2::client::Builder::new();
        builder.enable_push(false);
        builder.max_header_list_size(MAX_HEADER_LIST_BYTES);
        builder
    }

    pub(crate) fn h2_server(self) -> h2::server::Builder {
        assert_eq!(self, Self::H2);
        let mut builder = h2::server::Builder::new();
        builder.max_concurrent_streams(MAX_BIDI_STREAMS);
        builder.max_header_list_size(MAX_HEADER_LIST_BYTES);
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_carriers_have_exact_tls_and_resource_contract() {
        assert_eq!(VERSION, 1);
        assert_eq!(MAX_HEADER_LIST_BYTES, 8192);
        assert_eq!(MAX_BIDI_STREAMS, 32);
        assert_eq!(MAX_QUIC_UNI_STREAMS, 8);
        assert_eq!(QUIC_STREAM_RECEIVE_BYTES, 262144);
        assert_eq!(QUIC_CONNECTION_RECEIVE_BYTES, 4194304);
        assert_eq!(QUIC_SEND_WINDOW_BYTES, 4194304);
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        for (carrier, wrong) in [(Carrier::H2, Carrier::H3), (Carrier::H3, Carrier::H2)] {
            let client = carrier.client_tls(roots.clone()).unwrap();
            assert_eq!(client.alpn_protocols, vec![carrier.alpn().to_vec()]);
            assert!(!client.enable_early_data);
            let server = carrier.server_tls(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into(),
            ).unwrap();
            assert_eq!(server.alpn_protocols, vec![carrier.alpn().to_vec()]);
            assert_eq!(server.max_early_data_size, 0);
            assert!(carrier.client_tls(RootCertStore::empty()).is_err());
            let version = Some(rustls::ProtocolVersion::TLSv1_3);
            assert!(carrier.accepts_tls(version, Some(carrier.alpn())));
            assert!(!carrier.accepts_tls(version, Some(wrong.alpn())));
            assert!(!carrier.accepts_tls(version, None));
            assert!(!carrier.accepts_tls(Some(rustls::ProtocolVersion::TLSv1_2), Some(carrier.alpn())));
            assert!(!carrier.accepts_tls(None, Some(carrier.alpn())));
        }
    }
}
