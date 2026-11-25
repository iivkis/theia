//! M3.4j: real h2 0.4.19 encoder research on independent Tokio duplex.
//! Tests never send application secrets, use custom H2 frames, or alter the
//! shipping H2Client. Capture raw bytes only in-memory and zero them after
//! the bounded first-flight metadata parser returns.
#[path = "support/h2_wire.rs"]
mod h2_wire;

use bytes::Bytes;
use h2_wire::{inspect, Observation, CLIENT_PREFACE, MAX_CAPTURE_BYTES};
use http::{header, Request};
use tokio::{
    io::{AsyncReadExt, DuplexStream},
    time::{timeout, Duration},
};

const CHROME159_STREAM_WINDOW: u32 = 6_291_456;
// Separate connection-credit probe; actual Chromium159 connection target is
// 15 MiB (ADR-0013), not this deliberately smaller 6 MiB test-only target.
const RESEARCH_CONNECTION_WINDOW: u32 = 6_291_456;
const DEFAULT_H2_WINDOW: u32 = 65_535;
const RESEARCH_CONNECTION_INCREMENT: u32 = RESEARCH_CONNECTION_WINDOW - DEFAULT_H2_WINDOW;
const CHROME159_SETTINGS: [(u16, u32); 4] = [
    (1, 65_536),
    (2, 0),
    (4, CHROME159_STREAM_WINDOW),
    (6, 262_144),
];
const THEIA_SETTINGS: [(u16, u32); 2] = [(2, 0), (6, 8_192)];
const THEIA_PSEUDOS: [&str; 4] = [":method", ":scheme", ":authority", ":path"];
const CHROME159_PSEUDOS: [&str; 4] = [":method", ":authority", ":scheme", ":path"];

#[derive(Clone, Copy)]
enum H2Shape {
    ShippingBounds,
    ConnectionCreditOnly,
    Chrome159SettingsWithResearchCredit,
}

struct Captured {
    observation: Observation,
    connection_updates: Vec<u32>,
}

async fn read_next_frame(peer: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut head = [0u8; 9];
    peer.read_exact(&mut head)
        .await
        .expect("actual h2 encoder frame header");
    let length = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    assert!(length <= 16_384, "bounded first-flight frame");
    let stream = u32::from_be_bytes(head[5..9].try_into().unwrap());
    assert_eq!(stream & 0x8000_0000, 0);
    let mut body = vec![0u8; length];
    peer.read_exact(&mut body)
        .await
        .expect("actual h2 encoder frame payload");
    (head[3], head[4], stream, body)
}

/// All bytes come from a real `h2::client::Builder`. Only requests already
/// serialized by the library are inspected. No server handshake is needed to
/// observe this client's initial SETTINGS, WINDOW_UPDATE and HEADERS frame.
async fn capture_first_flight(shape: H2Shape, request: Request<()>) -> Captured {
    timeout(Duration::from_secs(12), async {
        let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
        let mut builder = h2::client::Builder::new();
        builder.enable_push(false);

        match shape {
            H2Shape::ShippingBounds => {
                builder.max_header_list_size(8_192);
            }
            H2Shape::ConnectionCreditOnly => {
                builder.max_header_list_size(8_192);
                // Not production: used only to isolate the connection-level
                // WINDOW_UPDATE. Large credit is not a memory-safe default.
                builder.initial_connection_window_size(RESEARCH_CONNECTION_WINDOW);
            }
            H2Shape::Chrome159SettingsWithResearchCredit => {
                // Test-only exact Chromium159 SETTINGS with separately chosen
                // 6 MiB connection credit. Real Chromium uses 15 MiB.
                // Deliberately leave Theia's production budgets untouched.
                builder.header_table_size(65_536);
                builder.initial_window_size(CHROME159_STREAM_WINDOW);
                builder.max_header_list_size(262_144);
                builder.initial_connection_window_size(RESEARCH_CONNECTION_WINDOW);
            }
        }

        let (mut sender, driver) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = driver.await;
        });
        let (_response, _body) = sender
            .send_request(request, false)
            .expect("real h2 client outgoing HEADERS");
        let mut raw = Vec::with_capacity(2048);
        let mut preface = [0u8; 24];
        peer.read_exact(&mut preface)
            .await
            .expect("real H2 preface");
        assert_eq!(&preface, CLIENT_PREFACE);
        raw.extend_from_slice(&preface);
        let mut updates = Vec::new();
        let mut reached_end_headers = false;
        for _ in 0..16 {
            let (kind, flags, stream, mut payload) = read_next_frame(&mut peer).await;
            let length = payload.len();
            assert!(
                raw.len() + 9 + length <= MAX_CAPTURE_BYTES,
                "{}",
                h2_wire::capture_error()
            );
            raw.extend_from_slice(&[
                ((length >> 16) & 0xff) as u8,
                ((length >> 8) & 0xff) as u8,
                (length & 0xff) as u8,
                kind,
                flags,
            ]);
            raw.extend_from_slice(&stream.to_be_bytes());
            raw.extend_from_slice(&payload);
            if kind == 8 && stream == 0 {
                assert_eq!(length, 4, "connection WINDOW_UPDATE length");
                let increment = u32::from_be_bytes(payload.as_slice().try_into().unwrap());
                assert!(increment > 0 && increment < (1 << 31));
                updates.push(increment);
            }
            payload.fill(0);
            if (kind == 1 || kind == 9) && flags & 4 != 0 {
                reached_end_headers = true;
                break;
            }
        }
        task.abort();
        assert!(reached_end_headers, "real HEADERS were not emitted");
        let parsed = inspect(&raw);
        raw.fill(0); // Never retain or print raw HPACK values.
        Captured {
            observation: parsed.expect("strict bounded HPACK pseudo-name parser"),
            connection_updates: updates,
        }
    })
    .await
    .expect("bounded H2 first-flight research")
}

fn post(content_type_first: bool) -> Request<()> {
    let builder = Request::post("https://localhost/v1/theia-example/session");
    let builder = if content_type_first {
        builder
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::AUTHORIZATION, "Bearer inert-fixture-not-a-token")
    } else {
        builder
            .header(header::AUTHORIZATION, "Bearer inert-fixture-not-a-token")
            .header(header::CONTENT_TYPE, "application/octet-stream")
    };
    builder.body(()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_encoder_pseudo_order_cannot_be_changed_by_application_header_order() {
    let first = capture_first_flight(H2Shape::ShippingBounds, post(true)).await;
    let reversed = capture_first_flight(H2Shape::ShippingBounds, post(false)).await;
    let get = capture_first_flight(
        H2Shape::ShippingBounds,
        Request::get("https://localhost/fixture")
            .header("x-fixture", "inert")
            .body(())
            .unwrap(),
    )
    .await;
    for observed in [&first, &reversed, &get] {
        assert_eq!(observed.observation.settings, THEIA_SETTINGS);
        assert_eq!(observed.observation.pseudo_headers, THEIA_PSEUDOS);
        assert!(observed.observation.frames_before_headers.is_empty());
        assert!(observed.connection_updates.is_empty());
        assert!(!observed.observation.request_end_stream);
        // This is an independently observed *encoder* ordering gap, not a
        // reason to reimplement HPACK or relax SmartTheia OPEN_OK semantics.
        assert_ne!(observed.observation.pseudo_headers, CHROME159_PSEUDOS);
    }
    assert_eq!(first.observation.ordinary_fields, 2);
    assert_eq!(reversed.observation.ordinary_fields, 2);
    eprintln!(
        "M3.4j h2 encoder: POST header insertion order and GET method do not alter pseudo-name order; Chrome159 still differs, no custom H2 encoder shipped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_window_update_is_a_separate_resource_risk_not_an_h2_settings_field() {
    let baseline = capture_first_flight(H2Shape::ShippingBounds, post(true)).await;
    assert_eq!(baseline.observation.settings, THEIA_SETTINGS);
    assert!(baseline.connection_updates.is_empty());

    let increased = capture_first_flight(H2Shape::ConnectionCreditOnly, post(true)).await;
    assert_eq!(increased.observation.settings, THEIA_SETTINGS);
    assert_eq!(increased.observation.frames_before_headers, [8]);
    assert_eq!(
        increased.connection_updates,
        [RESEARCH_CONNECTION_INCREMENT],
        "h2 must emit the actual connection-level credit increment"
    );
    // An unsolicited inbound peer may now put >6 MiB in-flight per
    // connection; never enable this in production without RSS/slow-reader
    // bounds and concurrency evidence.
    assert!(increased.connection_updates[0] > 90 * DEFAULT_H2_WINDOW);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium159_settings_with_separate_research_connection_credit() {
    let observed =
        capture_first_flight(H2Shape::Chrome159SettingsWithResearchCredit, post(true)).await;
    assert_eq!(observed.observation.settings, CHROME159_SETTINGS);
    assert_eq!(observed.observation.frames_before_headers, [8]);
    assert_eq!(observed.connection_updates, [RESEARCH_CONNECTION_INCREMENT]);
    // SETTINGS and flow credit can match; pseudo-header order cannot be
    // configured via documented h2::client::Builder APIs in h2 0.4.19.
    assert_eq!(observed.observation.pseudo_headers, THEIA_PSEUDOS);
    assert_ne!(observed.observation.pseudo_headers, CHROME159_PSEUDOS);
    eprintln!(
        "M3.4j Chromium159 SETTINGS + independent 6MiB connection credit encodable (NOT the 15MiB browser connection window), pseudo order differs; production Theia keeps 8KiB headers and default windows"
    );
}
