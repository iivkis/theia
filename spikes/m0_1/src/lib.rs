pub mod client_hello;
//! M0.1 API feasibility spike: NOT a proxy, TLS implementation, or benchmark.
//! The tests prove only explicitly named properties, never DPI resistance.
use std::sync::Arc;

/// Produces a Quinn QUIC transport config with the BBR controller factory.
/// This config must be attached to BOTH endpoints and verified at runtime.
pub fn bbr_transport() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    config
}

/// Production composition roots must use this for the client sender.
pub fn configure_client_bbr(config: &mut quinn::ClientConfig) {
    config.transport_config(Arc::new(bbr_transport()));
}

/// Production composition roots must use this for the server sender.
pub fn configure_server_bbr(config: &mut quinn::ServerConfig) {
    config.transport_config(Arc::new(bbr_transport()));
}

/// Compile-time proof that h3 0.0.8 exposes independent client send/receive
/// halves. This is NOT an HTTP/3 end-to-end test.
#[allow(dead_code)]
fn h3_client_has_split<S, B>(stream: h3::client::RequestStream<S, B>)
where
    S: h3::quic::BidiStream<B>,
    B: bytes::Buf,
{
    let (_send, _receive) = stream.split();
}

/// Compile-time proof for the server half.
#[allow(dead_code)]
fn h3_server_has_split<S, B>(stream: h3::server::RequestStream<S, B>)
where
    S: h3::quic::BidiStream<B>,
    B: bytes::Buf,
{
    let (_send, _receive) = stream.split();
}

/// h3_quinn binds the QUIC and HTTP/3 stacks; type must resolve.
pub fn h3_quinn_bridge_type() -> &'static str {
    std::any::type_name::<h3_quinn::Connection>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    #[test]
    fn bbr_factory_can_be_configured_for_both_roles() {
        let _ = bbr_transport();
        // No claim that packet pacing or selected controller is measured yet.
        let _: fn(&mut quinn::ClientConfig) = configure_client_bbr;
        let _: fn(&mut quinn::ServerConfig) = configure_server_bbr;
    }

    #[test]
    fn http3_quinn_bridge_links() {
        assert!(h3_quinn_bridge_type().contains("Connection"));
    }

    /// A genuine in-memory h2 client/server exchange:
    /// the server responds while the request body is still open;
    /// then the client sends more body bytes and server receives them.
    #[tokio::test]
    async fn http2_response_before_request_eof() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let mut done_tx = Some(done_tx);
                while let Some(accepted) = conn.accept().await {
                    let (request, mut respond) = accepted.unwrap();
                    let done = done_tx.take();
                    tokio::spawn(async move {
                        // Respond BEFORE consuming request body or seeing EOS.
                        respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                true,
                            )
                            .unwrap();

                        let mut incoming = request.into_body();
                        let part1 = incoming.data().await.unwrap().unwrap();
                        assert_eq!(part1, Bytes::from_static(b"phase-1"));
                        incoming
                            .flow_control()
                            .release_capacity(part1.len())
                            .unwrap();
                        let part2 = incoming.data().await.unwrap().unwrap();
                        assert_eq!(part2, Bytes::from_static(b"phase-2"));
                        incoming
                            .flow_control()
                            .release_capacity(part2.len())
                            .unwrap();
                        assert!(incoming.data().await.is_none());
                        if let Some(tx) = done {
                            tx.send(()).unwrap();
                        }
                    });
                }
            });

            let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(async move {
                connection.await.unwrap();
            });
            let request = http::Request::builder()
                .method("POST")
                .version(http::Version::HTTP_2)
                .uri("https://localhost/v1/session")
                .body(())
                .unwrap();
            let (response_future, mut request_body) = sender.send_request(request, false).unwrap();
            request_body
                .send_data(Bytes::from_static(b"phase-1"), false)
                .unwrap();

            // If the server waited for body EOF, awaiting this response would deadlock.
            let response = response_future.await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            request_body
                .send_data(Bytes::from_static(b"phase-2"), true)
                .unwrap();
            done_rx.await.unwrap();
            server.abort();
            client_driver.abort();
        })
        .await
        .expect("h2 full-duplex header/body test timed out");
    }
}
