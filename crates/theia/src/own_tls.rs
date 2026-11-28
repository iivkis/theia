//! Explicit Own-TLS chain anchor from a trusted access key.
//! The fingerprint selects exactly one presented certificate; ordinary
//! WebPKI still checks the chain, hostname, certificate time and usage.
//! TLS CertificateVerify and Finished remain rustls responsibilities.
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

const PREFIX: &str = "anchor-sha256:";
const MAX_CHAIN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anchor([u8; 32]);

impl Anchor {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn reference(self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from(PREFIX);
        for byte in self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    pub(crate) fn from_server(cert_ref: &str, name: &str) -> Result<Self, Error> {
        let pem = crate::server::pem_data(cert_ref, false).map_err(|_| invalid())?;
        let chain = rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if chain.is_empty() || chain.len() > MAX_CHAIN {
            return Err(invalid());
        }
        let leaf = chain.first().ok_or_else(invalid)?;
        let anchor = Self::from_der(chain.last().ok_or_else(invalid)?.as_ref());
        let name = ServerName::try_from(name.to_owned()).map_err(|_| invalid())?;
        anchor.verify_server_cert(leaf, &chain[1..], &name, &[], UnixTime::now())?;
        Ok(anchor)
    }

    pub(crate) fn matches_reference(self, reference: &str) -> bool {
        if let Some(other) = Self::parse(reference) {
            return self == other;
        }
        let Some(path) = reference.strip_prefix("file:") else {
            return false;
        };
        let Ok(pem) =
            crate::bounded_input::read(std::path::Path::new(path), 1024 * 1024, true, false)
        else {
            return false;
        };
        let Ok(certs) = rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        // A wider CA bundle is not equivalent to a single pinned anchor.
        certs.len() == 1 && self.matches(certs[0].as_ref())
    }

    pub(crate) fn bytes(self) -> [u8; 32] {
        self.0
    }

    fn from_der(cert: &[u8]) -> Self {
        Self(Sha256::digest(cert).into())
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        let hex = value.strip_prefix(PREFIX)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes
            .iter_mut()
            .zip(hex.as_bytes().as_chunks::<2>().0.iter())
        {
            *byte =
                (pair[0] as char).to_digit(16)? as u8 * 16 + (pair[1] as char).to_digit(16)? as u8;
        }
        Some(Self(bytes))
    }

    fn matches(self, der: &[u8]) -> bool {
        bool::from(self.0.ct_eq(&Self::from_der(der).0))
    }
}

fn invalid() -> Error {
    Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
}

impl ServerCertVerifier for Anchor {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if intermediates.len() >= MAX_CHAIN {
            return Err(invalid());
        }
        let (anchor, chain) = if self.matches(end_entity.as_ref()) {
            (end_entity, &intermediates[..0])
        } else {
            let index = intermediates
                .iter()
                .position(|cert| self.matches(cert.as_ref()))
                .ok_or_else(invalid)?;
            (&intermediates[index], &intermediates[..index])
        };
        let mut roots = RootCertStore::empty();
        roots.add(anchor.clone()).map_err(|_| invalid())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| invalid())?;
        verifier.verify_server_cert(end_entity, chain, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
pub(crate) enum Trust {
    Roots(RootCertStore),
    Pinned(Anchor),
}

impl Trust {
    pub(crate) fn usable(&self) -> bool {
        match self {
            Self::Roots(roots) => !roots.is_empty(),
            Self::Pinned(_) => true,
        }
    }

    pub(crate) fn tls(
        &self,
        carrier: crate::transport_policy::Carrier,
    ) -> Result<ClientConfig, Error> {
        match self {
            Self::Roots(roots) => carrier.client_tls(roots.clone()),
            Self::Pinned(anchor) => {
                let mut config = crate::net::tls::client_tls13_builder()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(*anchor))
                    .with_no_client_auth();
                carrier.configure_client(&mut config);
                // Revalidate the anchor on every new physical TLS connection.
                crate::net::tls::require_full_handshake(&mut config);
                Ok(config)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_certificate_still_requires_webpki_name_and_validity() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let leaf = cert.cert.der();
        let pin = Anchor::from_der(leaf.as_ref());
        let name = ServerName::try_from("localhost").unwrap();
        let wrong_name = ServerName::try_from("wrong.invalid").unwrap();
        let raw = pin
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(Anchor::parse(&format!("{PREFIX}{raw}")), Some(pin));
        assert!(Anchor::parse(&format!("{PREFIX}{}", raw.to_uppercase())).is_none());
        assert!(pin
            .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
            .is_ok());
        assert!(pin
            .verify_server_cert(other.cert.der(), &[], &name, &[], UnixTime::now())
            .is_err());
        assert!(pin
            .verify_server_cert(leaf, &[], &wrong_name, &[], UnixTime::now())
            .is_err());
        assert!(pin
            .verify_server_cert(
                leaf,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO)
            )
            .is_err());
        for carrier in [
            crate::transport_policy::Carrier::H2,
            crate::transport_policy::Carrier::H3,
        ] {
            let tls = Trust::Pinned(pin).tls(carrier).unwrap();
            assert_eq!(tls.alpn_protocols, vec![carrier.alpn().to_vec()]);
            assert!(!tls.enable_early_data);
        }
    }
}
