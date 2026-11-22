//! M3.4f: inspect real HTTP/2 SETTINGS and HPACK pseudo-header names from
//! the production H2Client, including its optional BoringSSL TLS backend.
//! Capture occurs *after* a verified TLS1.3 handshake on test-only loopback.
//! No TLS secrets, authorization values, HPACK block or raw frames are logged.
#[path = "support/h2_wire.rs"]
mod h2_wire;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use h2_wire::{inspect, Observation, MAX_CAPTURE_BYTES};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use theia::{
    client::{ClientError, H2Client},
    protocol::Address,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const DEADLINE: Duration = Duration::from_secs(25);

/// Store only the first bounded decrypted H2 client flight. An HTTP bearer
/// value may appear in raw HPACK; clear it immediately after parsing.
#[derive(Default)]
struct Capture {
    raw: Vec<u8>,
    frozen: bool,
}

impl Drop for Capture {
    fn drop(&mut self) {
        // Also scrub on early TLS/H2 test failure, not only successful parse.
        self.raw.fill(0);
    }
}

struct Tap<T> {
    inner: T,
    capture: Arc<Mutex<Capture>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Tap<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let chunk = &buf.filled()[before..];
            if !chunk.is_empty() {
                let mut state = this.capture.lock().expect("test recorder lock");
                if !state.frozen {
                    if state.raw.len() + chunk.len() > MAX_CAPTURE_BYTES {
                        return Poll::Ready(Err(h2_wire::capture_error()));
                    }
                    state.raw.extend_from_slice(chunk);
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tap<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Private ephemeral root and signed leaf with distinct certificate subjects.
/// This tests real PKI, not InsecureSkipVerify or a fake TLS fixture.
fn tls_fixture() -> (TlsAcceptor, String, RootCertStore) {
    let mut ca_params = CertificateParams::new(vec!["fixture-root.invalid".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4f-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4f-server");
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone(), ca.der().clone()],
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    (TlsAcceptor::from(Arc::new(tls)), ca.pem(), roots)
}

#[derive(Clone, Copy)]
enum Backend {
    Rustls,
    #[cfg(feature = "experimental-btls-h2")]
    BoringSsl,
}

async fn measure(backend: Backend) -> Observation {
    timeout(DEADLINE, async {
        let (acceptor, ca_pem, roots) = tls_fixture();
        #[cfg(not(feature = "experimental-btls-h2"))]
        let _ = &ca_pem;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.expect("strict TLS 1.3");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let capture = Arc::new(Mutex::new(Capture::default()));
            let tapped = Tap {
                inner: tls,
                capture: capture.clone(),
            };
            let mut connection = h2::server::handshake(tapped)
                .await
                .expect("server HTTP/2 preface");
            let (request, mut response) = connection
                .accept()
                .await
                .expect("live H2 request")
                .expect("first request stream");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");

            let observation = {
                let mut state = capture.lock().unwrap();
                state.frozen = true;
                let mut transcript = std::mem::take(&mut state.raw);
                let summary = inspect(&transcript);
                transcript.fill(0);
                summary.expect("first H2 settings, HEADERS and bounded HPACK")
            };

            // Reject before request body EOF. The caller cannot obtain a
            // SmartTheia tunnel from HTTP denial, even with valid TLS.
            response
                .send_response(
                    http::Response::builder()
                        .status(http::StatusCode::FORBIDDEN)
                        .body(())
                        .unwrap(),
                    true,
                )
                .expect("send early HTTP 403");
            while let Some(next) = connection.accept().await {
                if next.is_err() {
                    break;
                }
            }
            observation
        });
        let token = URL_SAFE_NO_PAD.encode([0x42; 32]);
        let client = match backend {
            Backend::Rustls => H2Client::new(&endpoint.to_string(), "localhost", &token, roots)
                .expect("default rustls client"),
            #[cfg(feature = "experimental-btls-h2")]
            Backend::BoringSsl => H2Client::new_experimental_btls(
                &endpoint.to_string(),
                "localhost",
                &token,
                ca_pem.as_bytes(),
            )
            .expect("explicitly trusted BoringSSL client"),
        };
        let result = client.open(Address::Dns("localhost".into()), 443).await;
        assert!(
            matches!(result, Err(ClientError::Unauthorized)),
            "HTTP 403 before OPEN_OK must never create a tunnel"
        );
        let observation = server.await.expect("capture server complete");
        // No raw wire bytes, header values, SNI or secrets are printed.
        eprintln!(
            "M3.4f H2 first-flight backend={} SETTINGS={:?} preceding_frame_types={:?} optional_settings_ack={} pseudo_names={:?} ordinary_fields={} END_STREAM={}",
            match backend {
                Backend::Rustls => "rustls",
                #[cfg(feature = "experimental-btls-h2")]
                Backend::BoringSsl => "experimental-btls",
            },
            observation.settings,
            observation.frames_before_headers,
            observation.settings_ack_before_headers,
            observation.pseudo_headers,
            observation.ordinary_fields,
            observation.request_end_stream
        );
        assert_eq!(observation.pseudo_headers.len(), 4);
        assert!(!observation.request_end_stream, "SmartTheia request body remains open");
        observation
    })
    .await
    .expect("bounded H2 wire fingerprint loopback")
}

/// Compare exactly the same shipping HTTP/2 engine as the default browser
/// negative-control path. Go uTLS's manual H2 probe has *empty* SETTINGS and
/// pseudo-header order method/scheme/path/authority, not Chrome H2 settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_default_h2_settings_and_pseudo_headers_are_measured() {
    let observed = measure(Backend::Rustls).await;
    // New fail-closed baseline: reject unsolicited H2 server PUSH_PROMISE
    // without relaxing Theia's 8 KiB response-header decoding budget.
    // This is NOT a Chrome-like H2/TLS browser profile.
    // Exact client-wire baseline from native Linux CI, not a Chrome profile.
    // Guard against silent change of H2 settings, pseudo order or extra frames.
    assert_eq!(observed.settings, [(2, 0), (6, 8192)]);
    assert_eq!(
        observed.pseudo_headers,
        [":method", ":scheme", ":authority", ":path"]
    );
    assert!(observed.frames_before_headers.is_empty());
    assert_eq!(observed.ordinary_fields, 2); // content type and bearer names
}

#[cfg(feature = "experimental-btls-h2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_experimental_btls_and_rustls_share_h2_engine_not_chrome_profile() {
    let rustls = measure(Backend::Rustls).await;
    let btls = measure(Backend::BoringSsl).await;
    // Both production H2Client backends use the same h2::client::Builder.
    assert_eq!(btls.settings, rustls.settings);
    assert_eq!(btls.settings, [(2, 0), (6, 8192)]);
    assert_eq!(btls.pseudo_headers, rustls.pseudo_headers);
    assert_eq!(btls.frames_before_headers, rustls.frames_before_headers);
    assert_eq!(btls.ordinary_fields, rustls.ordinary_fields);
    // The Go uTLS repository's minimal H2 probe is a standards-compliant
    // NEGATIVE CONTROL, not a Chrome133 HTTP/2 reference capture.
    let go_probe_settings: &[(u16, u32)] = &[];
    let go_probe_pseudo = [":method", ":scheme", ":path", ":authority"];
    assert_ne!(btls.settings, go_probe_settings);
    assert_ne!(btls.pseudo_headers, go_probe_pseudo);
    eprintln!(
        "M3.4f control: minimal Go H2 SETTINGS={go_probe_settings:?}, pseudo_names={go_probe_pseudo:?}; Go uTLS HelloChrome_133 only defines TCP/TLS, not Chrome H2 SETTINGS. F-13 blocked."
    );
    assert_eq!(btls.ordinary_fields, 2);
}
