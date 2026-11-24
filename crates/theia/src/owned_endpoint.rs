//! Explicit, bounded HTTP readiness check for an operator-owned local inbound.
//! The caller verifies the assigned address and bind scope before invoking
//! this helper. No DNS, credentials, redirects, arbitrary paths or fallback.
use crate::security_profile::CertificatePin;
use bytes::Bytes;
use http::{Request, StatusCode};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_HEADERS: u32 = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpWitness {
    pub h2: u16,
    pub h3: u16,
}

fn request(name: &str, port: u16) -> Result<Request<()>, &'static str> {
    Request::head(format!("https://{name}:{port}/"))
        .body(())
        .map_err(|_| "Invalid HTTP endpoint")
}

fn final_status(status: StatusCode) -> Result<u16, &'static str> {
    if (200..600).contains(&status.as_u16()) {
        Ok(status.as_u16())
    } else {
        Err("No final HTTP response")
    }
}

async fn h2(
    address: SocketAddr,
    name: &str,
    roots: RootCertStore,
    pin: CertificatePin,
) -> Result<u16, &'static str> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| "H2 TLS config")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.enable_early_data = false;
    let tls_name = ServerName::try_from(name.to_owned()).map_err(|_| "Invalid SNI")?;
    let tcp = TcpStream::connect(address).await.map_err(|_| "H2 TCP")?;
    if tcp.peer_addr().ok() != Some(address) {
        return Err("H2 peer mismatch");
    }
    let tls = TlsConnector::from(Arc::new(config))
        .connect(tls_name, tcp)
        .await
        .map_err(|_| "H2 TLS")?;
    let peer = tls.get_ref().1;
    if peer.alpn_protocol() != Some(b"h2".as_slice())
        || peer.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return Err("H2 ALPN/TLS");
    }
    let leaf = peer.peer_certificates().and_then(|chain| chain.first()).ok_or("H2 certificate")?;
    pin.verify(leaf.as_ref()).map_err(|_| "H2 certificate changed")?;
    let mut builder = h2::client::Builder::new();
    builder.max_header_list_size(MAX_HEADERS);
    let (sender, connection) = builder.handshake::<_, Bytes>(tls).await.map_err(|_| "H2 HTTP")?;
    let exchange = async {
        let mut sender = sender.ready().await.map_err(|_| "H2 HTTP")?;
        let (response, _) = sender.send_request(request(name, address.port())?, true)
            .map_err(|_| "H2 request")?;
        let response = response.await.map_err(|_| "H2 response")?;
        let status = final_status(response.status())?;
        let mut body = response.into_body();
        if body.data().await.is_some() || body.trailers().await.map_err(|_| "H2 trailers")?.is_some() {
            return Err("Unexpected HEAD payload");
        }
        Ok(status)
    };
    tokio::select! {
        biased;
        result = exchange => result,
        _ = connection => Err("H2 connection ended before complete response"),
    }
}

async fn h3(
    address: SocketAddr,
    name: &str,
    roots: RootCertStore,
    pin: CertificatePin,
) -> Result<u16, &'static str> {
    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let endpoint = crate::quic_transport::ObservedEndpoint::new(
        bind.parse().map_err(|_| "H3 bind")?, roots,
    ).map_err(|_| "H3 endpoint")?;
    let connection = endpoint.connect(address, name, DEADLINE).await.map_err(|_| "H3 QUIC/TLS")?;
    if connection.remote_address() != address {
        return Err("H3 peer mismatch");
    }
    let chain = connection.peer_identity().ok_or("H3 certificate")?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| "H3 certificate")?;
    let leaf = chain.first().ok_or("H3 certificate")?;
    pin.verify(leaf.as_ref()).map_err(|_| "H3 certificate changed")?;
    let mut builder = h3::client::builder();
    builder.max_field_section_size(u64::from(MAX_HEADERS));
    let (mut driver, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await.map_err(|_| "H3 HTTP")?;
    let exchange = async {
        let mut stream = sender.send_request(request(name, address.port())?).await.map_err(|_| "H3 request")?;
        stream.finish().await.map_err(|_| "H3 request end")?;
        let response = stream.recv_response().await.map_err(|_| "H3 response")?;
        let status = final_status(response.status())?;
        if stream.recv_data().await.map_err(|_| "H3 body")?.is_some()
            || stream.recv_trailers().await.map_err(|_| "H3 trailers")?.is_some() {
            return Err("Unexpected HEAD payload");
        }
        Ok(status)
    };
    tokio::select! {
        biased;
        result = exchange => result,
        _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => Err("H3 connection ended before complete response"),
    }
}

/// Both real HTTP responses on the same pinned endpoint, strict PKI and
/// exact locally reviewed leaf. A 404 still proves HTTP, not service health.
/// Any failure returns no positive dual witness.
pub(crate) async fn verify(
    address: SocketAddr,
    name: &str,
    roots: RootCertStore,
    pin: CertificatePin,
) -> Result<HttpWitness, &'static str> {
    if address.port() == 0 || address.ip().is_unspecified() || roots.is_empty()
        || !matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_))) {
        return Err("Invalid owned HTTP endpoint or trust");
    }
    timeout(DEADLINE, async {
        let (h2, h3) = tokio::try_join!(
            h2(address, name, roots.clone(), pin),
            h3(address, name, roots, pin),
        )?;
        Ok(HttpWitness { h2, h3 })
    }).await.map_err(|_| "Owned HTTP verification timed out")?
}
