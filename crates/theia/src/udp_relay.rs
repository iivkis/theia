//! SOCKS5 datagrams and bounded per-destination relay. All socket I/O is
//! ordinary Tokio UDP; no raw packet access. One pinned target per flow.
use crate::{
    client::ClientError,
    protocol::{self, Address, ErrorCode},
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{sleep_until, timeout, timeout_at, Instant},
};

pub(crate) const MAX_FLOWS: usize = 8;
pub(crate) const QUEUE: usize = 8;
const IDLE: Duration = Duration::from_secs(60);
pub(crate) struct Activity {
    last: Mutex<Instant>,
    idle: Duration,
}
impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            idle: IDLE,
        }
    }
    pub(crate) fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
    fn deadline(&self) -> Instant {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) + self.idle
    }
    pub(crate) async fn expire(&self) {
        loop {
            sleep_until(self.deadline()).await;
            if Instant::now() >= self.deadline() {
                return;
            }
        }
    }
}
pub(crate) enum Target {
    Tcp(tokio::net::TcpStream),
    Udp(UdpSocket),
}
pub(crate) async fn connect(address: SocketAddr) -> io::Result<UdpSocket> {
    let normalized = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    if address.port() == 0
        || normalized.is_unspecified()
        || normalized.is_multicast()
        || normalized == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    crate::routing::carrier_socket::connect_plain_udp(address).await
}
pub(crate) async fn send_datagram(socket: &UdpSocket, data: &[u8]) -> io::Result<()> {
    if data.len() > protocol::MAX_DATAGRAM || socket.send(data).await? != data.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(())
}
pub(crate) async fn direct(
    address: Address,
    port: u16,
    pinned: Option<Vec<IpAddr>>,
) -> Result<UdpSocket, ClientError> {
    if port == 0 {
        return Err(ClientError::Protocol);
    }
    timeout(Duration::from_secs(15), async {
        let candidates: Vec<SocketAddr> = if let Some(ips) = pinned {
            ips.into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        } else {
            match address {
                Address::V4(ip) => vec![SocketAddr::from((ip, port))],
                Address::V6(ip) => vec![SocketAddr::from((ip, port))],
                Address::Dns(name) => tokio::net::lookup_host((name.as_str(), port))
                    .await
                    .map_err(|_| ClientError::Open(ErrorCode::DialFailed))?
                    .take(65)
                    .collect(),
            }
        };
        if candidates.len() > 64 {
            return Err(ClientError::Open(ErrorCode::ResourceLimit));
        }
        for addr in candidates {
            if addr.ip().is_unspecified()
                || addr.ip().is_multicast()
                || addr.ip() == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            {
                continue;
            }
            if let Ok(socket) = connect(addr).await {
                return Ok(socket);
            }
        }
        Err(ClientError::Open(ErrorCode::DialFailed))
    })
    .await
    .map_err(|_| ClientError::Open(ErrorCode::DialTimeout))?
}
type Fallback =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Tunnel, ClientError>> + Send>>;
const FIRST_RESPONSE: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum LocalRelayError {
    Peer(ClientError),
    Application(ClientError),
}
impl LocalRelayError {
    fn into_client(self) -> ClientError {
        match self {
            Self::Peer(error) | Self::Application(error) => error,
        }
    }
}

pub(crate) enum Tunnel {
    Direct(UdpSocket),
    VerifiedLocal(Box<crate::routing::dpi::VerifiedUdp>, Fallback),
    H2(Box<crate::client::Tunnel>),
    H3(Box<crate::h3_client::H3Tunnel>),
}
impl Tunnel {
    pub(crate) fn local_delivery_guard(&self) -> Option<crate::routing::dpi::FallbackPolicy> {
        match self {
            Self::VerifiedLocal(verified, _) => Some(verified.fallback_policy()),
            _ => None,
        }
    }

    pub(crate) fn record_transport(&self, observed: &std::sync::atomic::AtomicU8) {
        let (transport, up) = match self {
            Self::H2(tunnel) => (2, tunnel.opened_stream_up()),
            Self::H3(tunnel) => (3, tunnel.opened_stream_up()),
            Self::Direct(_) => return,
            Self::VerifiedLocal(..) => return,
        };
        observed.store(
            (transport << 2) | if up { 2 } else { 1 },
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    #[cfg(test)]
    pub(crate) async fn relay(
        self,
        upload: mpsc::Receiver<Vec<u8>>,
        download: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        self.relay_guarded(upload, download, None).await
    }

    pub(crate) async fn relay_guarded(
        self,
        upload: mpsc::Receiver<Vec<u8>>,
        download: mpsc::Sender<Vec<u8>>,
        flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError> {
        match self {
            Self::VerifiedLocal(verified, fallback) => {
                use crate::routing::dpi::{
                    udp::{prepare_binding, BindingStrategy},
                    UdpStrategy,
                };
                let mut upload = upload;
                let Some(first) = upload.recv().await else {
                    return Ok(());
                };
                // Fixtures without a flow exercise the old prewrite
                // fallback. Real product flows must have live authorization.
                if let Some(flow) = flow {
                    flow.check_pending()?;
                    verified.check_live()?;
                }
                let admissible = verified.admissible()?;
                let batch = match verified.strategy {
                    UdpStrategy::Quic(_) => verified.quic_batch(&first),
                    _ => None,
                };
                let stun = matches!(
                    verified.strategy,
                    UdpStrategy::StunBinding(BindingStrategy::Fingerprint)
                ) && prepare_binding(&first, BindingStrategy::Fingerprint)
                    .is_some_and(|bytes| bytes.as_ref() != first.as_slice());
                if !admissible || (!stun && batch.is_none()) {
                    // Exactly one original first datagram, never its changed
                    // form. Drop the local socket before opening the VPS.
                    let authorization = verified.fallback_policy();
                    drop(verified);
                    authorization.check()?;
                    if let Some(flow) = flow {
                        flow.check_pending()?;
                    }
                    let tunnel = fallback.await?;
                    authorization.check()?;
                    if let Some(flow) = flow {
                        flow.check_pending()?;
                    }
                    if !matches!(tunnel, Self::H2(_) | Self::H3(_)) {
                        return Err(ClientError::Protocol);
                    }
                    return tunnel
                        .relay_selected(Some(first), upload, download, flow)
                        .await;
                }
                // Destroy fallback before any attempted user send.
                drop(fallback);
                relay_verified_selected(verified, first, upload, download, flow, batch, stun).await
            }
            other => other.relay_selected(None, upload, download, flow).await,
        }
    }

    async fn relay_selected(
        self,
        first: Option<Vec<u8>>,
        upload: mpsc::Receiver<Vec<u8>>,
        download: mpsc::Sender<Vec<u8>>,
        flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError> {
        match self {
            Self::H2(t) => t.relay_udp(first, upload, download, flow).await,
            Self::H3(t) => t.relay_udp(first, upload, download, flow).await,
            Self::Direct(socket) => relay_local(&socket, None, first, upload, download, flow)
                .await
                .map_err(LocalRelayError::into_client),
            Self::VerifiedLocal(..) => Err(ClientError::Protocol),
        }
    }
}

pub(crate) async fn next_datagram(
    first: &mut Option<Vec<u8>>,
    upload: &mut mpsc::Receiver<Vec<u8>>,
) -> Option<Vec<u8>> {
    if let Some(data) = first.take() {
        Some(data)
    } else {
        upload.recv().await
    }
}

async fn relay_local(
    socket: &UdpSocket,
    verification_deadline: Option<Duration>,
    first: Option<Vec<u8>>,
    upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: Option<&crate::routing::flow::FlowLease>,
) -> Result<(), LocalRelayError> {
    relay_local_batch(
        socket,
        verification_deadline,
        first,
        None,
        upload,
        download,
        flow,
        None,
    )
    .await
}

/// The unified native lab commits a real transformation only. All other
/// strategies are rejected; there is no fallback after this boundary.
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
))]
pub(crate) async fn relay_native_modify_lab(
    verified: &crate::routing::dpi::VerifiedUdp,
    first: Vec<u8>,
    upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: &crate::routing::flow::FlowLease,
) -> Result<(), ClientError> {
    use crate::routing::dpi::{
        udp::{prepare_binding, BindingStrategy},
        UdpStrategy,
    };
    if !verified.admissible()? {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    match verified.strategy {
        UdpStrategy::Quic(_) => relay_quic_lab(verified, first, upload, download, flow).await,
        UdpStrategy::StunBinding(BindingStrategy::Fingerprint) => {
            if !prepare_binding(&first, BindingStrategy::Fingerprint)
                .is_some_and(|bytes| bytes.as_ref() != first.as_slice())
            {
                return Err(ClientError::Open(ErrorCode::PolicyDenied));
            }
            let result = relay_stun(
                &verified.socket,
                BindingStrategy::Fingerprint,
                first,
                upload,
                download,
                Some(flow),
                Some(verified),
            )
            .await;
            if matches!(&result, Err(LocalRelayError::Peer(_))) {
                verified.failed();
                crate::traffic::udp_peer_failure();
            }
            result.map_err(LocalRelayError::into_client)
        }
        _ => Err(ClientError::Open(ErrorCode::PolicyDenied)),
    }
}

/// Native lab entrypoint. The shared relay also requires the actual
/// first datagram to split; reachability alone is never Modify.
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
))]
pub(crate) async fn relay_quic_lab(
    verified: &crate::routing::dpi::VerifiedUdp,
    first: Vec<u8>,
    upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: &crate::routing::flow::FlowLease,
) -> Result<(), ClientError> {
    if !verified.admissible()? {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let parts = verified
        .quic_batch(&first)
        .ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
    let result = relay_local_batch(
        &verified.socket,
        Some(FIRST_RESPONSE),
        Some(first),
        Some(parts),
        upload,
        download,
        Some(flow),
        Some(verified),
    )
    .await;
    if matches!(&result, Err(LocalRelayError::Peer(_))) {
        verified.failed();
        crate::traffic::udp_peer_failure();
    }
    result.map_err(LocalRelayError::into_client)
}

/// Standalone path has no carrier or fallback object at all.
#[cfg(windows)]
pub(crate) async fn relay_standalone_verified(
    verified: Box<crate::routing::dpi::VerifiedUdp>,
    first: Vec<u8>,
    upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: &crate::routing::flow::FlowLease,
) -> Result<(), ClientError> {
    use crate::routing::dpi::{
        udp::{prepare_binding, BindingStrategy},
        UdpStrategy,
    };
    flow.check_pending()?;
    verified.check_live()?;
    if !verified.admissible()? {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let batch = verified.quic_batch(&first);
    let stun = matches!(
        verified.strategy,
        UdpStrategy::StunBinding(BindingStrategy::Fingerprint)
    ) && prepare_binding(&first, BindingStrategy::Fingerprint)
        .is_some_and(|bytes| bytes.as_ref() != first.as_slice());
    if !stun && batch.is_none() {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    relay_verified_selected(verified, first, upload, download, Some(flow), batch, stun).await
}

async fn relay_verified_selected(
    verified: Box<crate::routing::dpi::VerifiedUdp>,
    first: Vec<u8>,
    upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: Option<&crate::routing::flow::FlowLease>,
    batch: Option<Vec<Vec<u8>>>,
    stun: bool,
) -> Result<(), ClientError> {
    use crate::routing::dpi::udp::BindingStrategy;
    verified.check_live()?;
    let relay = async {
        if stun {
            relay_stun(
                &verified.socket,
                BindingStrategy::Fingerprint,
                first,
                upload,
                download,
                flow,
                Some(&verified),
            )
            .await
        } else {
            relay_local_batch(
                &verified.socket,
                Some(FIRST_RESPONSE),
                Some(first),
                batch,
                upload,
                download,
                flow,
                Some(&verified),
            )
            .await
        }
    };
    let result = tokio::select! {
        biased;
        result = verified.wait_revoked() => result.map_err(LocalRelayError::Application),
        result = relay => result,
    };
    if matches!(&result, Err(LocalRelayError::Peer(_))) && verified.check_live().is_ok() {
        verified.failed();
        crate::traffic::udp_peer_failure();
    }
    result.map_err(LocalRelayError::into_client)
}

#[allow(clippy::too_many_arguments)]
async fn relay_local_batch(
    socket: &UdpSocket,
    verification_deadline: Option<Duration>,
    mut first: Option<Vec<u8>>,
    first_batch: Option<Vec<Vec<u8>>>,
    mut upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: Option<&crate::routing::flow::FlowLease>,
    verified: Option<&crate::routing::dpi::VerifiedUdp>,
) -> Result<(), LocalRelayError> {
    let live = || {
        verified
            .map_or(Ok(()), |v| v.check_live())
            .map_err(LocalRelayError::Application)
    };
    use crate::routing::{flow::FirstSend, PacketAction};
    let mut first_send = FirstSend::new(
        flow,
        if verification_deadline.is_some() {
            PacketAction::Modify
        } else {
            PacketAction::Pass
        },
    );
    let traffic = crate::traffic::enter_udp(crate::Role::Client, false, true);
    let activity = Activity::new();
    // For verified QUIC, start the receive deadline only after a successful
    // first application write. No server response is assumed authenticated.
    if let Some(deadline) = verification_deadline {
        let data = first
            .take()
            .ok_or(LocalRelayError::Application(ClientError::Protocol))?;
        let parts = match first_batch {
            Some(parts) => {
                let valid = if let Some(verified) = verified {
                    // Re-derive the exact shared transform; a single
                    // reprotected public Initial is allowed only if it is
                    // the validated CRYPTO-frame alternative, never Plain.
                    verified.quic_batch(&data).as_ref() == Some(&parts)
                } else {
                    parts.len() >= 2 && parts.concat() == data
                };
                if !valid
                    || parts.is_empty()
                    || parts.len() > 3
                    || parts
                        .iter()
                        .any(|p| p.is_empty() || p.len() > protocol::MAX_DATAGRAM)
                {
                    return Err(LocalRelayError::Application(ClientError::Protocol));
                }
                parts
            }
            None if verified.is_none() => vec![data.clone()],
            None => return Err(LocalRelayError::Application(ClientError::Protocol)),
        };
        // One deadline for the entire actual emission. Failure/cancellation
        // after any attempt is terminal; no replay of the original flight.
        timeout(deadline, async {
            for part in &parts {
                live()?;
                first_send.attempt().map_err(LocalRelayError::Application)?;
                send_datagram(socket, part)
                    .await
                    .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            }
            Ok::<(), LocalRelayError>(())
        })
        .await
        .map_err(|_| LocalRelayError::Peer(ClientError::Timeout))??;
        traffic.upload(data.len());
        crate::traffic::udp_verified_local();
        activity.touch();
    }
    let send = async {
        while let Some(data) = next_datagram(&mut first, &mut upload).await {
            live()?;
            first_send.attempt().map_err(LocalRelayError::Application)?;
            send_datagram(socket, &data)
                .await
                .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            traffic.upload(data.len());
            activity.touch();
        }
        Ok::<(), LocalRelayError>(())
    };
    let receive = async {
        let mut buf = vec![0; protocol::MAX_DATAGRAM + 1];
        let mut waiting = verification_deadline.map(|duration| Instant::now() + duration);
        loop {
            let n = if let Some(deadline) = waiting {
                timeout_at(deadline, socket.recv(&mut buf))
                    .await
                    .map_err(|_| LocalRelayError::Peer(ClientError::Timeout))?
            } else {
                socket.recv(&mut buf).await
            }
            .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            if n > protocol::MAX_DATAGRAM {
                continue;
            }
            if waiting.take().is_some() {
                crate::traffic::udp_peer_reply();
            }
            live()?;
            if let Some(flow) = flow {
                flow.commit(if verification_deadline.is_some() {
                    PacketAction::Modify
                } else {
                    PacketAction::Pass
                })
                .map_err(LocalRelayError::Application)?;
            }
            if deliver(&download, || buf[..n].to_vec()).map_err(LocalRelayError::Application)? {
                traffic.download(n);
                activity.touch();
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), LocalRelayError>(())
    };
    tokio::select! { result=send=>result, result=receive=>result, ()=activity.expire()=>Ok(()) }
}

/// The locally admitted STUN subset stays Binding-only for the entire flow.
/// No credentials or unrelated UDP may leak by reusing the same target tuple.
async fn relay_stun(
    socket: &UdpSocket,
    strategy: crate::routing::dpi::udp::BindingStrategy,
    first: Vec<u8>,
    mut upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: Option<&crate::routing::flow::FlowLease>,
    verified: Option<&crate::routing::dpi::VerifiedUdp>,
) -> Result<(), LocalRelayError> {
    let live = || {
        verified
            .map_or(Ok(()), |v| v.check_live())
            .map_err(LocalRelayError::Application)
    };
    use crate::routing::dpi::udp::{prepare_binding, BindingTransactions};
    let traffic = crate::traffic::enter_udp(crate::Role::Client, false, true);
    let activity = Activity::new();
    let requests = Mutex::new(BindingTransactions::default());
    if !requests
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .admit(&first)
    {
        return Err(LocalRelayError::Application(ClientError::Protocol));
    }
    let packet = prepare_binding(&first, strategy)
        .ok_or(LocalRelayError::Application(ClientError::Protocol))?;
    live()?;
    if let Some(flow) = flow {
        flow.commit(crate::routing::PacketAction::Modify)
            .map_err(LocalRelayError::Application)?;
    }
    timeout(FIRST_RESPONSE, send_datagram(socket, &packet))
        .await
        .map_err(|_| LocalRelayError::Peer(ClientError::Timeout))?
        .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
    if packet.len() != first.len() {
        crate::traffic::udp_stun_fingerprint();
    }
    traffic.upload(first.len());
    activity.touch();
    crate::traffic::udp_stun_local();
    let send = async {
        while let Some(data) = upload.recv().await {
            if !requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .admit(&data)
            {
                // No switch or replay once the local flow was used.
                return Err(LocalRelayError::Application(ClientError::Protocol));
            }
            let packet = prepare_binding(&data, strategy)
                .ok_or(LocalRelayError::Application(ClientError::Protocol))?;
            live()?;
            if let Some(flow) = flow {
                flow.commit(crate::routing::PacketAction::Modify)
                    .map_err(LocalRelayError::Application)?;
            }
            send_datagram(socket, &packet)
                .await
                .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            if packet.len() != data.len() {
                crate::traffic::udp_stun_fingerprint();
            }
            traffic.upload(data.len());
            activity.touch();
        }
        Ok::<(), LocalRelayError>(())
    };
    let receive = async {
        let mut buf = [0u8; 513];
        let mut waiting = Some(Instant::now() + FIRST_RESPONSE);
        loop {
            let n = match waiting {
                Some(deadline) => timeout_at(deadline, socket.recv(&mut buf))
                    .await
                    .map_err(|_| LocalRelayError::Peer(ClientError::Timeout))?,
                None => socket.recv(&mut buf).await,
            }
            .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            if !requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .accept(&buf[..n])
            {
                continue;
            }
            if waiting.take().is_some() {
                crate::traffic::udp_peer_reply();
            }
            live()?;
            if let Some(flow) = flow {
                flow.commit(crate::routing::PacketAction::Modify)
                    .map_err(LocalRelayError::Application)?;
            }
            if deliver(&download, || buf[..n].to_vec()).map_err(LocalRelayError::Application)? {
                traffic.download(n);
                activity.touch();
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), LocalRelayError>(())
    };
    tokio::select! { result=send=>result, result=receive=>result, ()=activity.expire()=>Ok(()) }
}

/// UDP overload drops rather than blocking the entire incoming stream.
/// Do not allocate/copy a datagram unless the bounded queue accepts it.
pub(crate) fn deliver(
    download: &mpsc::Sender<Vec<u8>>,
    data: impl FnOnce() -> Vec<u8>,
) -> Result<bool, ClientError> {
    match download.try_reserve() {
        Ok(permit) => {
            permit.send(data());
            Ok(true)
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            crate::traffic::udp_queue_drop();
            Ok(false)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(ClientError::Io),
    }
}

pub(crate) fn valid_associate(address: &Address, peer: IpAddr) -> bool {
    let ip: IpAddr = match address {
        Address::V4(ip) => (*ip).into(),
        Address::V6(ip) => (*ip).into(),
        Address::Dns(_) => return false,
    };
    ip.is_unspecified() || ip == peer
}
fn encode_address(out: &mut Vec<u8>, address: &Address, port: u16) {
    match address {
        Address::V4(ip) => {
            out.push(1);
            out.extend(ip)
        }
        Address::V6(ip) => {
            out.push(4);
            out.extend(ip)
        }
        Address::Dns(name) => {
            out.push(3);
            out.push(name.len() as u8);
            out.extend(name.as_bytes())
        }
    }
    out.extend(port.to_be_bytes());
}
pub(crate) fn associate_reply(bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![5, 0, 0];
    let addr = match bound.ip() {
        IpAddr::V4(ip) => Address::V4(ip.octets()),
        IpAddr::V6(ip) => Address::V6(ip.octets()),
    };
    encode_address(&mut out, &addr, bound.port());
    out
}
pub(crate) fn parse_socks(bytes: &[u8]) -> Option<(Address, u16, &[u8])> {
    if bytes.get(..3)? != [0, 0, 0] {
        return None;
    } // RFC 1928 FRAG unsupported
    let (address, end) = match *bytes.get(3)? {
        1 => (Address::V4(bytes.get(4..8)?.try_into().ok()?), 8),
        4 => (Address::V6(bytes.get(4..20)?.try_into().ok()?), 20),
        3 => {
            let n = usize::from(*bytes.get(4)?);
            let name = std::str::from_utf8(bytes.get(5..5 + n)?).ok()?;
            (Address::Dns(name.to_ascii_lowercase()), 5 + n)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(bytes.get(end..end + 2)?.try_into().ok()?);
    let data = bytes.get(end + 2..)?;
    if data.len() > protocol::MAX_DATAGRAM
        || port == 0
        || matches!(&address, Address::Dns(name) if !protocol::valid_dns(name))
    {
        return None;
    }
    Some((address, port, data))
}
pub(crate) fn encode_socks_into(
    out: &mut Vec<u8>,
    address: &Address,
    port: u16,
    data: &[u8],
) -> bool {
    out.clear();
    if port == 0 || matches!(address, Address::Dns(name) if !protocol::valid_dns(name)) {
        return false;
    }
    out.extend([0, 0, 0]);
    encode_address(out, address, port);
    if data.len() > protocol::MAX_DATAGRAM.saturating_sub(out.len()) {
        out.clear();
        return false;
    }
    out.extend(data);
    true
}

#[cfg(test)]
pub(crate) fn encode_socks(address: &Address, port: u16, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    encode_socks_into(&mut out, address, port, data).then_some(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socks_datagrams_exact_and_fragment_rejected() {
        for address in [
            Address::V4([127, 0, 0, 1]),
            Address::V6([0; 16]),
            Address::Dns("example.org".into()),
        ] {
            let mut encoded = encode_socks(&address, 443, b"data").unwrap();
            assert_eq!(
                parse_socks(&encoded),
                Some((address, 443, b"data".as_slice()))
            );
            encoded[2] = 1;
            assert!(parse_socks(&encoded).is_none());
        }
        assert!(encode_socks(&Address::Dns("bad/name".into()), 443, b"").is_none());
        assert!(valid_associate(
            &Address::V4([0; 4]),
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!valid_associate(
            &Address::V4([8, 8, 8, 8]),
            "127.0.0.1".parse().unwrap()
        ));
    }
    #[test]
    fn reusable_socks_buffer_never_keeps_previous_datagram() {
        let address = Address::V4([127, 0, 0, 1]);
        let mut packet = Vec::new();
        assert!(encode_socks_into(&mut packet, &address, 443, b"previous"));
        let capacity = packet.capacity();
        assert!(encode_socks_into(&mut packet, &address, 443, b""));
        assert_eq!(
            parse_socks(&packet),
            Some((address.clone(), 443, b"".as_slice()))
        );
        assert_eq!(packet.capacity(), capacity);
        assert!(!encode_socks_into(&mut packet, &address, 0, b"bad"));
        assert!(packet.is_empty());
        assert!(!encode_socks_into(
            &mut packet,
            &address,
            443,
            &vec![0; protocol::MAX_DATAGRAM]
        ));
        assert!(packet.is_empty());
    }

    #[tokio::test]
    async fn active_flow_renews_idle_and_queue_overload_drops_without_replay() {
        let activity = Activity {
            last: Mutex::new(Instant::now()),
            idle: IDLE,
        };
        let initial = activity.deadline();
        tokio::time::sleep(Duration::from_millis(2)).await;
        activity.touch();
        assert!(activity.deadline() > initial);
        let (tx, mut rx) = mpsc::channel(1);
        assert!(deliver(&tx, || b"one".to_vec()).unwrap());
        assert!(!deliver(&tx, || panic!("full queue must not allocate")).unwrap());
        assert_eq!(rx.recv().await.unwrap(), b"one");
        assert!(deliver(&tx, Vec::new).unwrap());
        assert!(rx.recv().await.unwrap().is_empty());
        drop(rx);
        assert!(deliver(&tx, || b"closed".to_vec()).is_err());
    }

    /// Independent peers use real loopback UDP and application traffic.
    /// The test supplies local fixture evidence only; it cannot change the
    /// production acceptance gate or authorize a public target.
    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    async fn run_independent_udp_peer(
        mut command: std::process::Command,
        strategy: crate::routing::dpi::UdpStrategy,
    ) {
        use std::{
            io::{Read, Write},
            process::{Child, Stdio},
            sync::Arc,
        };
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut peer = ChildGuard(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut stdout = peer.0.stdout.take().unwrap();
        let ports = timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || {
                let mut ports = [0; 4];
                stdout.read_exact(&mut ports).unwrap();
                ports
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let target: SocketAddr = ([127, 0, 0, 1], u16::from_be_bytes([ports[0], ports[1]])).into();
        let app: SocketAddr = ([127, 0, 0, 1], u16::from_be_bytes([ports[2], ports[3]])).into();
        let ingress = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        ingress.connect(app).await.unwrap();
        let (verified, flow) = crate::routing::dpi::VerifiedUdp::active_fixture(
            connect(target).await.unwrap(),
            strategy,
            "localhost",
        );
        let flow = Arc::new(flow);
        let relay_flow = flow.clone();
        let (up, upload) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (download, mut down) = mpsc::channel::<Vec<u8>>(QUEUE);
        let fallback: Fallback =
            Box::pin(async { panic!("a committed active strategy must never invoke fallback") });
        let tunnel = Tunnel::VerifiedLocal(Box::new(verified), fallback);
        let relay = tokio::spawn(async move {
            tunnel
                .relay_guarded(upload, download, Some(&relay_flow))
                .await
        });
        let reader = ingress.clone();
        let up_task = tokio::spawn(async move {
            let mut buf = vec![0; protocol::MAX_DATAGRAM + 1];
            while let Ok(n) = reader.recv(&mut buf).await {
                assert!(n <= protocol::MAX_DATAGRAM);
                if up.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        let writer = ingress.clone();
        let down_task = tokio::spawn(async move {
            while let Some(data) = down.recv().await {
                send_datagram(&writer, &data).await.unwrap();
            }
        });
        {
            let mut stdin = peer.0.stdin.take().unwrap();
            stdin
                .write_all(&ingress.local_addr().unwrap().port().to_be_bytes())
                .unwrap();
        }
        let status = timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = peer.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            status.success(),
            "independent UDP peer rejected the real relay"
        );
        assert_eq!(
            flow.actual_action().unwrap(),
            Some(crate::routing::PacketAction::Modify)
        );
        up_task.abort();
        let _ = up_task.await;
        timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), down_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    fn independent_python(script: &str) -> std::process::Command {
        let python = std::env::var_os("THEIA_DPI_PYTHON").unwrap_or_else(|| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        });
        let mut command = std::process::Command::new(python);
        command.arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/e2e")
                .join(script),
        );
        command
    }

    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    #[tokio::test]
    async fn independent_stun_product_relay_binding_exchange() {
        use crate::routing::dpi::{udp::BindingStrategy, UdpStrategy};
        run_independent_udp_peer(
            independent_python("independent_stun_live_modify.py"),
            UdpStrategy::StunBinding(BindingStrategy::Fingerprint),
        )
        .await;
    }

    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    #[tokio::test]
    #[ignore = "requires pinned aioquic from browser-e2e CI"]
    async fn independent_quic_product_relay_v1_v2() {
        use crate::{quic_core::wire::Version, routing::dpi::UdpStrategy};
        use ring::rand::{SecureRandom, SystemRandom};
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let unique: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let directory = Scratch(std::env::temp_dir().join(format!("theia-quic-relay-{unique}")));
        std::fs::create_dir(&directory.0).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(directory.0.join("cert.pem"), cert.cert.pem()).unwrap();
        std::fs::write(directory.0.join("key.pem"), cert.key_pair.serialize_pem()).unwrap();
        for version in [Version::V1, Version::V2] {
            let mut command = independent_python("independent_quic_live_modify.py");
            command
                .arg(&directory.0)
                .arg(version.wire().to_string())
                .arg("--relay");
            run_independent_udp_peer(command, UdpStrategy::Quic(version)).await;
        }
    }

    #[tokio::test]
    async fn verified_local_relay_preserves_first_datagram_and_peer_response() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(target.local_addr().unwrap()).await.unwrap();
        let (up, rx) = mpsc::channel(QUEUE);
        let (down, mut responses) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            relay_local(
                &socket,
                Some(FIRST_RESPONSE),
                Some(b"first".to_vec()),
                rx,
                down,
                None,
            )
            .await
        });
        let mut buf = [0; 32];
        let (n, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"first");
        target.send_to(b"response", peer).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), responses.recv())
                .await
                .unwrap()
                .unwrap(),
            b"response"
        );
        up.send(Vec::new()).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        drop(up);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn multipacket_first_emission_preserves_order_and_datagram_boundaries() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(peer.local_addr().unwrap()).await.unwrap();
        let (up_tx, up_rx) = mpsc::channel(QUEUE);
        let (down_tx, _down_rx) = mpsc::channel(QUEUE);
        let relay = tokio::spawn(async move {
            relay_local_batch(
                &socket,
                Some(Duration::from_secs(2)),
                Some(b"abcdef".to_vec()),
                Some(vec![b"abc".to_vec(), b"def".to_vec()]),
                up_rx,
                down_tx,
                None,
                None,
            )
            .await
        });
        let mut bytes = [0; 16];
        for expected in [b"abc", b"def"] {
            let (n, _) = timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..n], expected);
        }
        drop(up_tx);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn verified_first_response_timeout_does_not_repeat_datagram() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(target.local_addr().unwrap()).await.unwrap();
        let (_up, rx) = mpsc::channel(QUEUE);
        let (down, _responses) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            relay_local(
                &socket,
                Some(Duration::from_millis(50)),
                Some(b"first".to_vec()),
                rx,
                down,
                None,
            )
            .await
        });
        let mut buf = [0; 32];
        let (n, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"first");
        assert!(matches!(
            task.await.unwrap(),
            Err(LocalRelayError::Peer(ClientError::Timeout))
        ));
        assert!(
            timeout(Duration::from_millis(30), target.recv_from(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stun_relay_uses_selected_strategy_and_rejects_other_payload() {
        use crate::routing::dpi::udp::{prepare_binding, BindingStrategy};
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(target.local_addr().unwrap()).await.unwrap();
        let (up, rx) = mpsc::channel(QUEUE);
        let (down, mut responses) = mpsc::channel(QUEUE);
        let mut first = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        first.extend([7; 12]);
        let expected = prepare_binding(&first, BindingStrategy::Fingerprint)
            .unwrap()
            .into_owned();
        let task = tokio::spawn(async move {
            relay_stun(
                &socket,
                BindingStrategy::Fingerprint,
                first,
                rx,
                down,
                None,
                None,
            )
            .await
        });
        let mut buf = [0; 512];
        let (n, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], expected.as_slice());
        let mut response = expected[..20].to_vec();
        response[0] = 1;
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response.extend([0, 0x20, 0, 8, 0, 1, 0x21, 0x13, 1, 2, 3, 4]);
        let mut wrong = response.clone();
        wrong[19] ^= 1;
        target.send_to(&wrong, peer).await.unwrap();
        target.send_to(&response, peer).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), responses.recv())
                .await
                .unwrap()
                .unwrap(),
            response
        );
        up.send(b"not Binding".to_vec()).await.unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(LocalRelayError::Application(ClientError::Protocol))
        ));
        assert!(
            timeout(Duration::from_millis(50), target.recv_from(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_nonunicast_before_open() {
        for address in [
            "0.0.0.0:53",
            "255.255.255.255:53",
            "224.0.0.1:53",
            "[::]:53",
            "[ff02::1]:53",
            "[::ffff:255.255.255.255]:53",
            "127.0.0.1:0",
        ] {
            assert!(connect(address.parse().unwrap()).await.is_err());
        }
    }
    #[tokio::test]
    async fn connected_udp_preserves_boundaries_and_empty_datagrams() {
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = connect(origin.local_addr().unwrap()).await.unwrap();
        for data in [b"first".as_slice(), b"".as_slice(), b"second".as_slice()] {
            send_datagram(&client, data).await.unwrap();
            let mut buf = [0; 32];
            let (n, peer) = timeout(Duration::from_secs(1), origin.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], data);
            assert_eq!(origin.send_to(data, peer).await.unwrap(), n);
            let n = timeout(Duration::from_secs(1), client.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], data);
        }
    }
}
