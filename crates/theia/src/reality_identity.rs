//! Independent Ed25519 server identity on a fully verified TLS channel.
//! This is an explicit authenticated adapter, not TLS camouflage or a claim
//! of resistance to active probing. Never sign arbitrary caller-provided data.
use crate::client::ClientError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header, HeaderValue, Method, Request, Response, StatusCode, Uri};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use std::path::Path;

pub(crate) const PATH: &str = "/v1/identity";
const SIGNATURE: &str = "theia-server-identity";
const PREFIX: &str = "smart-reality-v1:";
const DOMAIN: &[u8] = b"SmartTheia/REALITY/server-identity/v1\0";
const MAX_KEY_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity([u8; 32]);

impl PublicIdentity {
    pub fn parse_profile(profile: &str) -> Option<Self> {
        let raw = profile.strip_prefix(PREFIX)?;
        if raw.len() != 43 {
            return None;
        }
        let decoded = URL_SAFE_NO_PAD.decode(raw).ok()?;
        let key: [u8; 32] = decoded.try_into().ok()?;
        if key == [0; 32] || URL_SAFE_NO_PAD.encode(key) != raw {
            return None;
        }
        Some(Self(key))
    }

    pub fn profile(self) -> String {
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }

    pub fn encoded(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub(crate) fn verify<T>(
        self,
        key: &crate::channel_binding::Key,
        response: &Response<T>,
    ) -> Result<(), ClientError> {
        if response.status() != StatusCode::OK
            || response.headers().get_all(SIGNATURE).iter().count() != 1
        {
            return Err(ClientError::Tls);
        }
        let value = response.headers().get(SIGNATURE).ok_or(ClientError::Tls)?;
        let raw = value.to_str().map_err(|_| ClientError::Tls)?;
        if raw.len() != 86 {
            return Err(ClientError::Tls);
        }
        let sig = URL_SAFE_NO_PAD.decode(raw).map_err(|_| ClientError::Tls)?;
        if sig.len() != 64 || URL_SAFE_NO_PAD.encode(&sig) != raw {
            return Err(ClientError::Tls);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, self.0)
            .verify(&transcript(key), &sig)
            .map_err(|_| ClientError::Tls)
    }
}

pub(crate) struct Signer(Ed25519KeyPair);

impl Signer {
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, crate::server::ServerError> {
        // Accept standard PKCS#8 v1 or v2; ring checks the embedded public
        // key if present. No custom private-key parser or raw seed format.
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map(Self)
            .map_err(|_| crate::server::ServerError::Config)
    }

    pub(crate) fn public(&self) -> PublicIdentity {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.0.public_key().as_ref());
        PublicIdentity(key)
    }

    pub(crate) fn response(&self, key: &crate::channel_binding::Key) -> Option<Response<()>> {
        let signature = self.0.sign(&transcript(key));
        let mut value = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(signature.as_ref()))
            .ok()?;
        value.set_sensitive(true);
        let mut response = Response::new(());
        response.headers_mut().insert(SIGNATURE, value);
        Some(response)
    }
}

fn transcript(key: &crate::channel_binding::Key) -> zeroize::Zeroizing<Vec<u8>> {
    // The exporter is unique to the verified connection; H2 and H3 use
    // separate exporter contexts. Do not accept a caller-supplied challenge.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(DOMAIN.len() + 32));
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&key[..]);
    bytes
}

pub(crate) fn read_key(
    reference: Option<&str>,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, crate::server::ServerError> {
    reference
        .map(|reference| {
            let path = reference.strip_prefix("file:").ok_or(crate::server::ServerError::Config)?;
            crate::bounded_input::read(Path::new(path), MAX_KEY_BYTES, true, true)
                .map_err(|_| crate::server::ServerError::Config)
        })
        .transpose()
}

pub(crate) fn request(uri: &Uri) -> Result<Request<()>, ClientError> {
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(http::uri::PathAndQuery::from_static(PATH));
    Request::get(Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?)
        .body(())
        .map_err(|_| ClientError::Configuration)
}

pub(crate) fn is_request<T>(request: &Request<T>) -> bool {
    request.method() == Method::GET
        && request.uri().path() == PATH
        && request.uri().query().is_none()
        && !request.headers().contains_key(header::AUTHORIZATION)
        && !request.headers().contains_key(header::CONTENT_LENGTH)
        && !request.headers().contains_key(SIGNATURE)
        && !request.headers().contains_key("theia-channel-proof")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use zeroize::Zeroizing;

    #[test]
    fn independent_identity_signature_rejects_wrong_key_channel_and_duplicate() {
        let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Signer::from_der(der.as_ref()).unwrap();
        let other = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let other = Signer::from_der(other.as_ref()).unwrap();
        let key = Zeroizing::new([1u8; 32]);
        let different = Zeroizing::new([2u8; 32]);
        let identity = signer.public();
        assert_eq!(PublicIdentity::parse_profile(&identity.profile()), Some(identity));
        assert!(PublicIdentity::parse_profile(&format!("{}=", identity.profile())).is_none());
        assert!(Signer::from_der(b"not pkcs8").is_err());
        let mut response = signer.response(&key).unwrap();
        assert!(identity.verify(&key, &response).is_ok());
        assert!(identity.verify(&different, &response).is_err());
        assert!(other.public().verify(&key, &response).is_err());
        let duplicate = response.headers()[SIGNATURE].clone();
        response.headers_mut().append(SIGNATURE, duplicate);
        assert!(identity.verify(&key, &response).is_err());
        assert!(identity.verify(&key, &Response::new(())).is_err());
    }
}
