//! Shared native client handshake boundary. Only an observed send without
//! any received UDP, or a definitive error on the exact destination send,
//! can be considered unavailable. PKI, protocol, receive and local errors
//! never authorize a transport downgrade.
use super::{
    endpoint::LabSession, handshake_udp, negotiation::VersionPolicy, scope::NetworkScope,
    wire::Version,
};
use rustls::{pki_types::ServerName, ClientConfig};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Configuration,
    Bind,
    Handshake,
    Timeout,
    Unreachable,
    EndpointNetworkRefused,
}

#[derive(Default)]
pub(crate) struct Observation {
    sent: AtomicBool,
    received: AtomicBool,
    refused: AtomicBool,
}

impl Observation {
    pub(crate) fn sent(&self) {
        self.sent.store(true, Ordering::SeqCst);
    }

    pub(crate) fn received(&self) {
        self.received.store(true, Ordering::SeqCst);
    }

    pub(crate) fn send_error(&self, kind: io::ErrorKind) {
        if matches!(
            kind,
            io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::ConnectionRefused
        ) {
            self.refused.store(true, Ordering::SeqCst);
        }
    }

    fn failure(&self, timeout: bool) -> Error {
        if !self.received.load(Ordering::SeqCst) {
            if self.refused.load(Ordering::SeqCst) {
                return Error::EndpointNetworkRefused;
            }
            if timeout && self.sent.load(Ordering::SeqCst) {
                return Error::Unreachable;
            }
        }
        if timeout {
            Error::Timeout
        } else {
            Error::Handshake
        }
    }
}

/// A source is selected by the OS without sending any datagram or resolving
/// DNS. An explicit source (e.g. a protected routing lease) is never replaced.
pub(crate) fn bind_source(
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> Result<SocketAddr, Error> {
    if peer.port() == 0 || peer.ip().is_unspecified() {
        return Err(Error::Configuration);
    }
    let bind = match local {
        Some(local) => local,
        None => crate::local_proxy::route_source(peer).ok_or(Error::Bind)?,
    };
    if bind.ip().is_unspecified() || bind.is_ipv4() != peer.is_ipv4() {
        return Err(Error::Configuration);
    }
    Ok(bind)
}

/// An exact address, DNS name, TLS config and explicit version. Full TLS,
/// transport parameters and HANDSHAKE_DONE must authenticate before return.
/// The outer deadline also covers local socket setup and confirmation.
pub(crate) async fn connect(
    peer: SocketAddr,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    local: Option<SocketAddr>,
    versions: VersionPolicy,
    deadline: Duration,
) -> Result<(Version, LabSession), Error> {
    if deadline.is_zero() || !matches!(&name, ServerName::DnsName(_)) {
        return Err(Error::Configuration);
    }
    let observation = Observation::default();
    let result = tokio::time::timeout(deadline, async {
        let local = bind_source(peer, local)?;
        let scope =
            NetworkScope::pinned([local.ip(); 2], [peer.ip(); 2]).ok_or(Error::Configuration)?;
        let (version, mut session) = handshake_udp::connect_versions_observed(
            local,
            peer,
            versions,
            tls,
            name,
            scope,
            &observation,
        )
        .await
        .map_err(|error| match error {
            handshake_udp::Error::Timeout => observation.failure(true),
            handshake_udp::Error::Io(_) => observation.failure(false),
            handshake_udp::Error::Scope => Error::Configuration,
            _ => Error::Handshake,
        })?;
        // Completion of TLS alone is insufficient for a verified probe.
        // No HTTP streams, bearer or user data have been created.
        confirm(&mut session).await?;
        Ok((version, session))
    })
    .await;
    result.unwrap_or_else(|_| Err(observation.failure(true)))
}

pub(crate) async fn confirm(session: &mut LabSession) -> Result<(), Error> {
    while !session.handshake_confirmed() {
        if session.shutdown_phase() != super::lifecycle::ShutdownPhase::Open {
            return Err(Error::Handshake);
        }
        session
            .flush(Instant::now())
            .await
            .map_err(|_| Error::Handshake)?;
        let wait = session.deadline().map_or(Duration::from_millis(100), |at| {
            at.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100))
        });
        session.recv(wait).await.map_err(|_| Error::Handshake)?;
    }
    Ok(())
}

pub(crate) async fn close_probe(mut session: LabSession) -> Result<(), Error> {
    session
        .close(0x100, Instant::now())
        .map_err(|_| Error::Handshake)?;
    session
        .flush(Instant::now())
        .await
        .map_err(|_| Error::Handshake)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_requires_observed_send_or_exact_send_error_and_no_response() {
        let observation = Observation::default();
        assert_eq!(observation.failure(true), Error::Timeout);
        use io::ErrorKind::*;
        for error in [
            PermissionDenied,
            AddrNotAvailable,
            WouldBlock,
            Interrupted,
            OutOfMemory,
            ConnectionReset,
            TimedOut,
            Other,
            InvalidInput,
        ] {
            observation.send_error(error);
            assert_eq!(observation.failure(false), Error::Handshake);
        }
        for error in [NetworkUnreachable, HostUnreachable, ConnectionRefused] {
            let refused = Observation::default();
            refused.send_error(error);
            assert_eq!(refused.failure(false), Error::EndpointNetworkRefused);
            refused.received();
            assert_eq!(refused.failure(true), Error::Timeout);
        }
        observation.sent();
        assert_eq!(observation.failure(true), Error::Unreachable);
        assert_eq!(observation.failure(false), Error::Handshake);
        observation.send_error(io::ErrorKind::HostUnreachable);
        assert_eq!(observation.failure(false), Error::EndpointNetworkRefused);
        observation.received();
        assert_eq!(observation.failure(true), Error::Timeout);
        assert_eq!(observation.failure(false), Error::Handshake);
    }

    #[tokio::test]
    async fn malformed_response_disables_silence_classification() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let tls = crate::transport_policy::Carrier::H3
            .client_tls(roots)
            .unwrap();
        let (result, ()) = tokio::join!(
            connect(
                address,
                ServerName::try_from("localhost").unwrap(),
                Arc::new(tls),
                None,
                VersionPolicy::exact(Version::V1),
                Duration::from_millis(300)
            ),
            async {
                let mut initial = [0; 1500];
                let (_, from) = peer.recv_from(&mut initial).await.unwrap();
                peer.send_to(b"invalid", from).await.unwrap();
            }
        );
        assert!(matches!(result, Err(Error::Timeout)));
    }
}
