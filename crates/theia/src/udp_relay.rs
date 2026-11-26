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
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    if socket.peer_addr()? != address {
        return Err(io::Error::other("UDP peer mismatch"));
    }
    Ok(socket)
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
type Fallback = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Tunnel, ClientError>> + Send>>;
const FIRST_RESPONSE: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum LocalRelayError {
    Peer(ClientError),
    Application(ClientError),
}
impl LocalRelayError {
    fn into_client(self) -> ClientError {
        match self { Self::Peer(error) | Self::Application(error) => error }
    }
}

pub(crate) enum Tunnel {
    Direct(UdpSocket),
    VerifiedQuic(Box<crate::routing::dpi::VerifiedUdp>, Fallback),
    H2(Box<crate::client::Tunnel>),
    H3(Box<crate::h3_client::H3Tunnel>),
}
impl Tunnel {
    pub(crate) fn record_transport(&self, observed: &std::sync::atomic::AtomicU8) {
        let (transport, up) = match self {
            Self::H2(tunnel) => (2, tunnel.opened_stream_up()),
            Self::H3(tunnel) => (3, tunnel.opened_stream_up()),
            Self::Direct(_) | Self::VerifiedQuic(..) => return,
        };
        observed.store((transport << 2) | if up { 2 } else { 1 }, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) async fn relay(
        self,
        mut upload: mpsc::Receiver<Vec<u8>>,
        download: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        match self {
            Self::VerifiedQuic(verified, fallback) => {
                let Some(first) = upload.recv().await else { return Ok(()); };
                if !verified.admissible()? {
                    drop(verified);
                    let tunnel = fallback.await?;
                    if !matches!(tunnel, Self::H2(_) | Self::H3(_)) {
                        return Err(ClientError::Protocol);
                    }
                    return tunnel.relay_selected(Some(first), upload, download).await;
                }
                // Once a send is attempted no fallback or replay is legal.
                drop(fallback);
                let result = relay_local(&verified.socket, Some(FIRST_RESPONSE), Some(first), upload, download).await;
                if matches!(&result, Err(LocalRelayError::Peer(_))) {
                    verified.failed();
                    crate::traffic::udp_peer_failure();
                }
                result.map_err(LocalRelayError::into_client)
            }
            other => other.relay_selected(None, upload, download).await,
        }
    }

    async fn relay_selected(
        self,
        first: Option<Vec<u8>>,
        upload: mpsc::Receiver<Vec<u8>>,
        download: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        match self {
            Self::H2(t) => t.relay_udp(first, upload, download).await,
            Self::H3(t) => t.relay_udp(first, upload, download).await,
            Self::Direct(socket) => relay_local(&socket, None, first, upload, download).await.map_err(LocalRelayError::into_client),
            Self::VerifiedQuic(..) => Err(ClientError::Protocol),
        }
    }
}

pub(crate) async fn next_datagram(first: &mut Option<Vec<u8>>, upload: &mut mpsc::Receiver<Vec<u8>>) -> Option<Vec<u8>> {
    if let Some(data) = first.take() { Some(data) } else { upload.recv().await }
}

async fn relay_local(
    socket: &UdpSocket,
    verification_deadline: Option<Duration>,
    mut first: Option<Vec<u8>>,
    mut upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
) -> Result<(), LocalRelayError> {
    let traffic = crate::traffic::enter_udp(crate::Role::Client, false, true);
    let activity = Activity::new();
    // For verified QUIC, start the receive deadline only after a successful
    // first application write. No server response is assumed authenticated.
    if let Some(deadline) = verification_deadline {
        let data = first.take().ok_or(LocalRelayError::Application(ClientError::Protocol))?;
        timeout(deadline, send_datagram(socket, &data)).await
            .map_err(|_| LocalRelayError::Peer(ClientError::Timeout))?
            .map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
        traffic.upload(data.len());
        crate::traffic::udp_verified_local();
        activity.touch();
    }
    let send = async {
        while let Some(data) = next_datagram(&mut first, &mut upload).await {
            send_datagram(socket, &data).await.map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
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
                timeout_at(deadline, socket.recv(&mut buf)).await.map_err(|_| LocalRelayError::Peer(ClientError::Timeout))?
            } else {
                socket.recv(&mut buf).await
            }.map_err(|_| LocalRelayError::Peer(ClientError::Io))?;
            if n > protocol::MAX_DATAGRAM { continue; }
            if waiting.take().is_some() {
                crate::traffic::udp_peer_reply();
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
pub(crate) fn deliver(download: &mpsc::Sender<Vec<u8>>, data: impl FnOnce() -> Vec<u8>) -> Result<bool, ClientError> {
    match download.try_reserve() {
        Ok(permit) => { permit.send(data()); Ok(true) }
        Err(mpsc::error::TrySendError::Full(_)) => { crate::traffic::udp_queue_drop(); Ok(false) }
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
    if data.len() > protocol::MAX_DATAGRAM || port == 0
        || matches!(&address, Address::Dns(name) if !protocol::valid_dns(name))
    {
        return None;
    }
    Some((address, port, data))
}
pub(crate) fn encode_socks(address: &Address, port: u16, data: &[u8]) -> Option<Vec<u8>> {
    if port == 0 || matches!(address, Address::Dns(name) if !protocol::valid_dns(name)) { return None; }
    let mut out = vec![0, 0, 0];
    encode_address(&mut out, address, port);
    if out.len() + data.len() > protocol::MAX_DATAGRAM {
        return None;
    }
    out.extend(data);
    Some(out)
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
    #[tokio::test]
    async fn active_flow_renews_idle_and_queue_overload_drops_without_replay() {
        let activity = Activity { last: Mutex::new(Instant::now()), idle: IDLE };
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

    #[tokio::test]
    async fn verified_local_relay_preserves_first_datagram_and_peer_response() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(target.local_addr().unwrap()).await.unwrap();
        let (up, rx) = mpsc::channel(QUEUE);
        let (down, mut responses) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            relay_local(&socket, Some(FIRST_RESPONSE), Some(b"first".to_vec()), rx, down).await
        });
        let mut buf = [0; 32];
        let (n, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"first");
        target.send_to(b"response", peer).await.unwrap();
        assert_eq!(timeout(Duration::from_secs(2), responses.recv()).await.unwrap().unwrap(), b"response");
        up.send(Vec::new()).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(n, 0);
        drop(up);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn verified_first_response_timeout_does_not_repeat_datagram() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connect(target.local_addr().unwrap()).await.unwrap();
        let (_up, rx) = mpsc::channel(QUEUE);
        let (down, _responses) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            relay_local(&socket, Some(Duration::from_millis(50)), Some(b"first".to_vec()), rx, down).await
        });
        let mut buf = [0; 32];
        let (n, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"first");
        assert!(matches!(task.await.unwrap(), Err(LocalRelayError::Peer(ClientError::Timeout))));
        assert!(timeout(Duration::from_millis(30), target.recv_from(&mut buf)).await.is_err());
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
