//! M3.4h: CI-only evidence for *which* Chromium159 SETTINGS h2 0.4.19
//! can encode, and why matching every value is not safe for shipping Theia.
//! This test drives the actual h2 client builder over a bounded in-memory
//! Tokio duplex, not handcrafted HTTP/2 frames or fake Chrome behavior.
//! No production client, certificate validation or SmartTheia flow is bypassed.
use tokio::{
    io::{AsyncReadExt, DuplexStream},
    time::{timeout, Duration},
};

const CHROMIUM_SETTINGS: [(u16, u32); 4] = [
    (1, 65_536),    // HPACK header table size, Chromium 159 control
    (2, 0),         // server push disabled
    (4, 6_291_456), // per-stream receive credit, NOT a safe default
    (6, 262_144),   // max header list, 32x Theia's 8 KiB security budget
];
const MAX_HEADER_LIST_THEIA: u32 = 8_192;
const DEFAULT_STREAM_WINDOW: u32 = 65_535;

async fn read_first_client_settings(peer: &mut DuplexStream) -> Vec<(u16, u32)> {
    let mut preface = [0u8; 24];
    peer.read_exact(&mut preface).await.expect("client preface");
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    let mut frame = [0u8; 9];
    peer.read_exact(&mut frame)
        .await
        .expect("SETTINGS frame header");
    let length =
        (usize::from(frame[0]) << 16) | (usize::from(frame[1]) << 8) | usize::from(frame[2]);
    assert_eq!(frame[3], 4, "first frame must be SETTINGS");
    assert_eq!(frame[4], 0, "client initial SETTINGS cannot be ACK");
    assert_eq!(&frame[5..], &[0, 0, 0, 0], "SETTINGS must use stream zero");
    assert!(length <= 6 * 16 && length % 6 == 0, "bounded SETTINGS");
    let mut bytes = vec![0u8; length];
    peer.read_exact(&mut bytes).await.expect("SETTINGS payload");
    bytes
        .as_chunks::<6>()
        .0
        .iter()
        .map(|field| {
            (
                u16::from_be_bytes([field[0], field[1]]),
                u32::from_be_bytes([field[2], field[3], field[4], field[5]]),
            )
        })
        .collect()
}

const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;
// Research-only candidate: 15 MiB initial connection credit, matching a
// commonly used Chromium window target. The exact browser increment is
// separately measured from real Chromium, never presumed from this number.
const RESEARCH_CONNECTION_WINDOW: u32 = 15_728_640;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_builder_emits_real_connection_window_update_without_shipping_large_credit() {
    timeout(Duration::from_secs(12), async {
        let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
        let mut builder = h2::client::Builder::new();
        builder.enable_push(false);
        builder.max_header_list_size(8_192);
        // Test-only: larger connection credit is not a safe Theia default.
        builder.initial_connection_window_size(RESEARCH_CONNECTION_WINDOW);
        let (_sender, driver) = builder.handshake::<_, bytes::Bytes>(client_io).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = driver.await;
        });
        let settings = read_first_client_settings(&mut peer).await;
        assert_eq!(settings, [(2, 0), (6, 8_192)]);
        let mut header = [0u8; 9];
        peer.read_exact(&mut header).await.expect("WINDOW_UPDATE frame");
        assert_eq!(header, [0, 0, 4, 8, 0, 0, 0, 0, 0]);
        let mut body = [0u8; 4];
        peer.read_exact(&mut body).await.expect("WINDOW_UPDATE credit");
        let increment = u32::from_be_bytes(body);
        assert_eq!(increment, RESEARCH_CONNECTION_WINDOW - DEFAULT_CONNECTION_WINDOW);
        assert_eq!(increment, 15_663_105);
        task.abort();
        eprintln!(
            "M3.4i h2-only test target=15728640 WINDOW_UPDATE=15663105; production credit unchanged at 65535"
        );
    })
    .await
    .expect("bounded connection-window feasibility");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn experimental_h2_builder_can_encode_real_chromium159_settings_but_not_safely_ship_them() {
    timeout(Duration::from_secs(12), async {
        let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
        let mut builder = h2::client::Builder::new();
        // Deliberately test-only. These large browser receive limits must NOT
        // become Theia defaults merely to cosmetically match the wire.
        builder.header_table_size(65_536);
        builder.enable_push(false);
        builder.initial_window_size(6_291_456);
        builder.max_header_list_size(262_144);

        let (_sender, driver) = builder.handshake::<_, bytes::Bytes>(client_io).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = driver.await;
        });
        let settings = read_first_client_settings(&mut peer).await;
        task.abort();

        assert_eq!(
            settings, CHROMIUM_SETTINGS,
            "h2 Builder must actually emit the observed Chromium SETTINGS in wire order"
        );
        // These are *resource budget blockers*, not allowable shipping goals:
        assert_eq!(CHROMIUM_SETTINGS[3].1, 32 * MAX_HEADER_LIST_THEIA);
        assert!(CHROMIUM_SETTINGS[2].1 > 90 * DEFAULT_STREAM_WINDOW);
        // This research test does not weaken the separate production
        // first-flight assertions or prove matching HPACK pseudo order.
        eprintln!(
            "M3.4h h2 builder research: exact Chromium159 SETTINGS encodable, but 256KiB headers/6MiB stream credit exceed Theia's guards; no production profile enabled"
        );
    })
    .await
    .expect("bounded h2 builder SETTINGS experiment");
}
