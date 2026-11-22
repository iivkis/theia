//! M3.4g CI-only actual Chromium H2 reference, not a TLS/X.509 verification
//! test. This is a research comparison with Theia's measured H2 baseline.
//! The browser context alone accepts a generated loopback-only test cert;
//! production Theia (default rustls/optional BoringSSL) still verifies PKI.
#[path = "support/h2_wire.rs"]
mod h2_wire;

use bytes::Bytes;
use h2_wire::{inspect, Observation, MAX_CAPTURE_BYTES};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{
    io,
    pin::Pin,
    process::Command,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

#[derive(Default)]
struct Capture {
    raw: Vec<u8>,
    frozen: bool,
}

impl Drop for Capture {
    fn drop(&mut self) {
        // Scrub raw HPACK even if the browser or parser fails.
        self.raw.fill(0);
    }
}

struct Tap<T> {
    inner: T,
    state: Arc<Mutex<Capture>>,
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
                let mut state = this.state.lock().expect("capture lock");
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
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Install Playwright and its pinned Chromium on the CI runner before calling
/// this ignored test. It never contacts a public origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "required native browser-e2e CI matrix provisions pinned Playwright/Chromium"]
async fn actual_chromium_h2_settings_and_pseudo_order_reference() {
    timeout(Duration::from_secs(80), async {
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            // Chromium may open a speculative TLS connection before the
            // navigation context's one-off test certificate exception applies.
            // A rejected speculative connection must not kill the reference
            // listener. Retry only loopback, with strictly bounded attempts.
            let mut verified = None;
            for _ in 0..8 {
                let (socket, _) = listener.accept().await.expect("loopback browser TCP");
                if let Ok(Ok(tls)) = timeout(
                    Duration::from_secs(5),
                    tls_acceptor.accept(socket),
                )
                .await
                {
                    verified = Some(tls);
                    break;
                }
            }
            let tls = verified.expect("a real Chromium h2 TLS connection must succeed");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let capture = Arc::new(Mutex::new(Capture::default()));
            let tapped = Tap {
                inner: tls,
                state: capture.clone(),
            };
            let mut h2 = h2::server::handshake(tapped)
                .await
                .expect("real Chromium HTTP/2 preface");
            let (request, mut respond) = h2
                .accept()
                .await
                .expect("HTTP/2 connection")
                .expect("first browser request");
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().path(), "/ci-chromium-h2-reference");

            let observation = {
                let mut state = capture.lock().unwrap();
                state.frozen = true;
                let mut raw = std::mem::take(&mut state.raw);
                let result = inspect(&raw);
                raw.fill(0);
                result.expect("bounded real Chromium SETTINGS and HPACK names")
            };

            let response = http::Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(
                Bytes::from_static(
                    b"<html><body><main id='h2-reference'>chromium-h2</main></body></html>",
                ),
                true,
            )
            .unwrap();

            // Continue driving the real H2 server until the browser closes.
            while let Some(result) = h2.accept().await {
                if result.is_err() {
                    break;
                }
            }
            observation
        });
        let reference_script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/e2e/chromium_h2_reference.py");
        let launched = tokio::task::spawn_blocking(move || {
            Command::new("python")
                .arg(reference_script)
                .arg(&endpoint)
                .output()
                .expect("Playwright Chromium runner available in CI")
        });
        let process = launched.await.expect("Chromium launcher task");
        assert!(
            process.status.success(),
            "isolated Chromium navigation failed: {}",
            String::from_utf8_lossy(&process.stderr)
        );
        let observation: Observation = server.await.expect("Chromium TLS H2 server task");
        assert!(
            !observation.settings.is_empty() && observation.settings.len() <= 16,
            "real browser SETTINGS must be observed, not synthesized"
        );
        assert_eq!(observation.pseudo_headers.len(), 4);
        assert!(observation.ordinary_fields > 0);
        assert!(observation.request_end_stream, "browser GET is bodyless");
        // Observations from M3.4f: the production h2 0.4.19 client advertises
        // only SETTINGS_MAX_HEADER_LIST_SIZE=8192. This assertion detects the
        // currently measurable gap, not a claim of Chromium compatibility.
        let theia_settings = [(6, 8192)];
        assert_ne!(
            observation.settings, theia_settings,
            "Chromium SETTINGS unexpectedly equal Theia; re-evaluate F-13"
        );
        eprintln!(
            "M3.4g real Chromium H2 SETTINGS={:?} pre_HEAD_sequence={:?} optional_SETTINGS_ACK={} pseudo_names={:?} ordinary_name_count={} END_STREAM={}; Theia baseline SETTINGS={theia_settings:?} pseudo_names=[:method,:scheme,:authority,:path]; comparison is research only, F-13 blocked",
            observation.settings,
            observation.frames_before_headers,
            observation.settings_ack_before_headers,
            observation.pseudo_headers,
            observation.ordinary_fields,
            observation.request_end_stream
        );
    })
    .await
    .expect("bounded real Chromium H2 reference deadline");
}
