//! TLS 1.3 exporter-bound HTTP admission for the explicit pinned profiles.
//! No new cryptographic primitive. This does not hide the TLS handshake or
//! replace PKI, the leaf pin, grants, bearer verification or independent identity.
use crate::client::ClientError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header, HeaderValue, Request};
use ring::hmac;
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const LABEL: &[u8] = b"EXPORTER-SmartTheia-XHTTP-Admission-v1";
pub(crate) const H2: &[u8] = b"h2";
pub(crate) const H3: &[u8] = b"h3";
const HEADER: &str = "theia-channel-proof";

pub(crate) type Key = Zeroizing<[u8; 32]>;

fn proof<T>(key: &Key, request: &Request<T>) -> Option<HeaderValue> {
    if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        return None;
    }
    let authorization = request.headers().get(header::AUTHORIZATION)?;
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key[..]);
    let mut context = hmac::Context::with_key(&signing_key);
    context.update(b"SmartTheia/XHTTP/admission/v1\0");
    for value in [
        request.method().as_str().as_bytes(),
        request.uri().path().as_bytes(),
        authorization.as_bytes(),
    ] {
        let length = u32::try_from(value.len()).ok()?;
        context.update(&length.to_be_bytes());
        context.update(value);
    }
    let tag = context.sign();
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(tag.as_ref()));
    let mut value = HeaderValue::from_str(&encoded).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// The proof is attached only after full TLS/QUIC verification and pin check.
pub(crate) fn attach<T>(
    key: Option<&Key>,
    mut request: Request<T>,
) -> Result<Request<T>, ClientError> {
    if let Some(key) = key {
        let value = proof(key, &request).ok_or(ClientError::Configuration)?;
        request.headers_mut().insert(HEADER, value);
    }
    Ok(request)
}

pub(crate) struct Admission {
    key: Key,
    used: AtomicBool,
    identity_required: bool,
    identity_issued: AtomicBool,
}

impl Admission {
    pub(crate) fn new(key: Key) -> Self {
        Self {
            key,
            used: AtomicBool::new(false),
            identity_required: false,
            identity_issued: AtomicBool::new(false),
        }
    }

    pub(crate) fn requiring_identity(mut self, required: bool) -> Self {
        self.identity_required = required;
        self
    }

    pub(crate) fn identity_response(&self, signer: &crate::reality_identity::Signer) -> Option<http::Response<()>> {
        if !self.identity_required || self.identity_issued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return None;
        }
        signer.response(&self.key)
    }

    fn verifies<T>(&self, request: &Request<T>) -> bool {
        if request.headers().get_all(HEADER).iter().count() != 1 {
            return false;
        }
        let Some(received) = request.headers().get(HEADER) else {
            return false;
        };
        let Some(expected) = proof(&self.key, request) else {
            return false;
        };
        bool::from(received.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// At most one logical admission per verified pinned connection.
    /// Pairing remains same-connection and each leg has its own proof.
    pub(crate) fn admit<T>(&self, requests: &[&Request<T>]) -> bool {
        if (self.identity_required && !self.identity_issued.load(Ordering::Acquire))
            || !(1..=2).contains(&requests.len())
            || !requests.iter().all(|request| self.verifies(request))
        {
            return false;
        }
        self.used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Plain profiles do not negotiate this adapter. Refuse unexpected proofs
/// instead of treating an explicit request as a weaker profile.
pub(crate) fn admit<T>(binding: Option<&Admission>, requests: &[&Request<T>]) -> bool {
    match binding {
        Some(binding) => binding.admit(requests),
        None => requests
            .iter()
            .all(|request| !request.headers().contains_key(HEADER)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, path: &str, bearer: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, bearer)
            .body(())
            .unwrap()
    }

    #[test]
    fn channel_binding_rejects_missing_duplicate_wrong_route_bearer_and_connection() {
        let key = Zeroizing::new([1; 32]);
        let other_key = Zeroizing::new([2; 32]);
        let server = Admission::new(key.clone());
        let signed = attach(Some(&key), request("POST", "/a", "Bearer fixture")).unwrap();
        assert!(signed.headers()[HEADER].is_sensitive());
        assert!(!admit(None, &[&signed]));
        assert!(!server.admit(&[&request("POST", "/a", "Bearer fixture")]));
        assert!(!Admission::new(other_key).admit(&[&signed]));
        for (method, path, bearer) in [
            ("GET", "/a", "Bearer fixture"),
            ("POST", "/b", "Bearer fixture"),
            ("POST", "/a", "Bearer other"),
        ] {
            let mut changed = request(method, path, bearer);
            changed
                .headers_mut()
                .insert(HEADER, signed.headers()[HEADER].clone());
            assert!(!server.admit(&[&changed]));
        }
        let mut duplicate = attach(Some(&key), request("POST", "/a", "Bearer fixture")).unwrap();
        duplicate
            .headers_mut()
            .append(HEADER, signed.headers()[HEADER].clone());
        assert!(!server.admit(&[&duplicate]));
        assert!(server.admit(&[&signed]));
        assert!(!server.admit(&[&signed]));
    }

    #[test]
    fn pair_proofs_are_independent_and_one_admission_wins_concurrent_race() {
        let key = Zeroizing::new([3; 32]);
        let upload = attach(Some(&key), request("POST", "/upload", "Bearer fixture")).unwrap();
        let download = attach(Some(&key), request("GET", "/download", "Bearer fixture")).unwrap();
        let binding = Admission::new(key);
        assert_ne!(upload.headers()[HEADER], download.headers()[HEADER]);
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| binding.admit(&[&upload, &download]));
            let second = scope.spawn(|| binding.admit(&[&upload, &download]));
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_ne!(first, second);
    }
}
