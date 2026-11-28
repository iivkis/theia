//! Exact-endpoint HTTPS diagnostics. Reuse the production ClientHello
//! transformer and socket factory, but never publish production evidence.
use super::{strategy::Strategy, tcp, tls};
use crate::{
    net::{
        guarded_io::{revoked, GuardedIo},
        tls as verified_tls,
    },
    network_scope,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Timeout,
    Denied,
    Network,
    Tls,
    Protocol,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) connected: bool,
    pub(crate) verified_tls: bool,
    pub(crate) transformed: bool,
    pub(crate) result: Result<u16, Failure>,
}

/// Require complete final HTTP headers, including the empty terminating
/// line. No redirects, body downloads, cookies or authenticated sessions.
async fn head_status(input: &mut (impl AsyncRead + Unpin)) -> Result<u16, Failure> {
    for _ in 0..5 {
        let mut bytes = Vec::new();
        loop {
            let byte = input.read_u8().await.map_err(|_| Failure::Protocol)?;
            if bytes.len() == 8192 {
                return Err(Failure::Protocol);
            }
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Protocol)?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let status = lines.next().ok_or(Failure::Protocol)?;
        let mut parts = status.splitn(3, ' ');
        if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(Failure::Protocol);
        }
        let code = parts.next().ok_or(Failure::Protocol)?;
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::Protocol);
        }
        let code: u16 = code.parse().map_err(|_| Failure::Protocol)?;
        if !(100..=599).contains(&code) || code == 101 {
            return Err(Failure::Protocol);
        }
        for line in lines {
            let (key, value) = line.split_once(':').ok_or(Failure::Protocol)?;
            http::header::HeaderName::from_bytes(key.as_bytes()).map_err(|_| Failure::Protocol)?;
            http::header::HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| Failure::Protocol)?;
        }
        if code >= 200 {
            return Ok(code);
        }
    }
    Err(Failure::Protocol)
}

/// Transport closure/reset during TLS is not itself a certificate rejection.
fn handshake_failure(error: &std::io::Error) -> Failure {
    use std::io::ErrorKind;
    if error.get_ref().and_then(|cause| cause.downcast_ref::<rustls::Error>()).is_some() {
        return Failure::Tls;
    }
    match error.kind() {
        ErrorKind::PermissionDenied => Failure::Denied,
        ErrorKind::TimedOut => Failure::Timeout,
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe | ErrorKind::NotConnected => Failure::Network,
        _ => Failure::Tls,
    }
}

/// One independently connected, fully authenticated HTTP HEAD. A requested
/// transform must actually change the wire first flight; no plain fallback.
/// The caller binds the exact pinned endpoint and strategy to its lease.
pub(crate) async fn https(
    name: &str,
    peer: SocketAddr,
    scope: network_scope::Scope,
    strategy: Option<Strategy>,
    roots: &rustls::RootCertStore,
    live: &(dyn Fn() -> bool + Sync),
    deadline: Instant,
) -> Observation {
    let connected = AtomicBool::new(false);
    let verified = AtomicBool::new(false);
    let transformed = AtomicBool::new(false);
    let scoped = || live() && network_scope::observe(peer) == Some(scope);
    let operation = async {
        if !scoped() {
            return Err(Failure::Denied);
        }
        let mut config =
            verified_tls::application_probe(roots.clone()).map_err(|_| Failure::Tls)?;
        verified_tls::configure_client(&mut config, b"http/1.1");
        let server_name =
            rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| Failure::Tls)?;
        let (socket, _admission) = tcp::connect(peer).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                Failure::Denied
            } else {
                Failure::Network
            }
        })?;
        if !scoped()
            || !socket
                .local_addr()
                .is_ok_and(|local| scope.matches_local(local))
        {
            return Err(Failure::Denied);
        }
        connected.store(true, Ordering::Release);
        let mut socket = GuardedIo::new(socket, &scoped);
        // Same application TLS configuration and relay shape for Direct and
        // Modify. The latter uses the exact existing production transformer.
        let (local, mut relay) = tokio::io::duplex(64 * 1024);
        let app = async {
            let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(server_name, local)
                .await
                .map_err(|error| handshake_failure(&error))?;
            if stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_some_and(|p| p != b"http/1.1")
            {
                return Err(Failure::Tls);
            }
            if !scoped() {
                return Err(Failure::Denied);
            }
            verified.store(true, Ordering::Release);
            let request = format!("HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|_| Failure::Network)?;
            let code = head_status(&mut stream).await?;
            if !scoped() {
                return Err(Failure::Denied);
            }
            Ok(code)
        };
        let forwarding = async {
            if let Some(strategy) = strategy {
                let mut first = Vec::new();
                if !tcp::read_hello(&mut relay, &mut first)
                    .await
                    .map_err(|_| Failure::Protocol)?
                {
                    return Err(Failure::Unavailable);
                }
                let changed = tls::transform(&first, name, strategy)
                    .filter(|value| *value != first)
                    .ok_or(Failure::Unavailable)?;
                if !scoped() {
                    return Err(Failure::Denied);
                }
                socket
                    .write_all(&changed)
                    .await
                    .map_err(|_| Failure::Network)?;
                transformed.store(true, Ordering::Release);
            }
            tokio::io::copy_bidirectional(&mut relay, &mut socket)
                .await
                .map_err(|_| Failure::Network)?;
            Ok(())
        };
        tokio::pin!(app, forwarding);
        let code = tokio::select! {
            biased;
            result = &mut app => result?,
            result = &mut forwarding => { result?; app.await? }
        };
        if strategy.is_some() && !transformed.load(Ordering::Acquire) {
            return Err(Failure::Unavailable);
        }
        Ok(code)
    };
    let result = tokio::select! {
        biased;
        _ = revoked(&scoped) => Err(Failure::Denied),
        _ = tokio::time::sleep_until(deadline) => Err(Failure::Timeout),
        result = operation => if scoped() { result } else { Err(Failure::Denied) },
    };
    Observation {
        connected: connected.load(Ordering::Acquire),
        verified_tls: verified.load(Ordering::Acquire),
        transformed: transformed.load(Ordering::Acquire),
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn handshake_transport_closure_is_not_identity_rejection() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset, ErrorKind::BrokenPipe] {
            assert_eq!(handshake_failure(&Error::from(kind)), Failure::Network);
        }
        assert_eq!(handshake_failure(&Error::from(ErrorKind::PermissionDenied)), Failure::Denied);
        assert_eq!(handshake_failure(&Error::from(ErrorKind::InvalidData)), Failure::Tls);
        let tls = Error::new(ErrorKind::UnexpectedEof, rustls::Error::NoCertificatesPresented);
        assert_eq!(handshake_failure(&tls), Failure::Tls);
    }

    #[tokio::test]
    async fn final_headers_are_required_and_codes_remain_distinct() {
        for code in [200, 302, 403, 429, 451, 503] {
            let bytes = format!(
                "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 {code} Test\r\nX-Test: value\r\n\r\n"
            );
            assert_eq!(head_status(&mut bytes.as_bytes()).await, Ok(code));
        }
        for bytes in [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n".as_slice(),
            b"HTTP/1.1 999 Invalid\r\n\r\n".as_slice(),
        ] {
            let mut input = bytes;
            assert_eq!(head_status(&mut input).await, Err(Failure::Protocol));
        }
    }

    #[tokio::test]
    async fn direct_and_transformed_flights_reach_a_verified_fixture() {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let scope = network_scope::observe(peer).unwrap();
        for strategy in std::iter::once(None).chain(Strategy::ALL.into_iter().map(Some)) {
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    bytes.push(stream.read_u8().await.unwrap());
                    if bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(bytes.len() < 1024);
                }
                assert_eq!(
                    bytes,
                    b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                let _ = stream.shutdown().await;
            };
            let probe = https(
                "example.com",
                peer,
                scope,
                strategy,
                &roots,
                &|| true,
                Instant::now() + Duration::from_secs(3),
            );
            let (result, _) = tokio::join!(probe, server);
            assert_eq!(result.result, Ok(200), "{result:?}");
            assert!(result.connected && result.verified_tls);
            assert_eq!(result.transformed, strategy.is_some());
        }
    }
}
