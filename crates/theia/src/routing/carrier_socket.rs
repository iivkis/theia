//! Shared TCP/UDP socket factory and task-scoped native admission.
//! No process-wide or target-wide exclusion. Ordinary System Proxy has
//! no registrar or OS changes. Native callers retain the exact admission lease.
use std::{future::Future, io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

#[derive(Default)]
pub(crate) struct Lease {
    _resource: Option<Box<dyn Send + Sync>>,
}
impl Lease {
    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    pub(crate) fn retain<T: Send + Sync + 'static>(resource: T) -> Self {
        Self {
            _resource: Some(Box::new(resource)),
        }
    }
}

pub(crate) trait Registrar: Send + Sync {
    fn tcp(&self, socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease>;
    fn udp(&self, socket: &UdpSocket, peer: SocketAddr) -> io::Result<Lease>;
    #[cfg(target_os = "linux")]
    fn udp_reply(&self, socket: &UdpSocket, peer: SocketAddr) -> io::Result<Lease> {
        self.udp(socket, peer)
    }
    /// Permanently refuse new admission and revoke existing capabilities.
    /// This does not restore capture rules or authorize direct traffic.
    fn retire(&self) -> io::Result<()>;
}

tokio::task_local! { static CURRENT: Option<Arc<dyn Registrar>>; }

pub(crate) async fn scope<T>(
    registrar: Option<Arc<dyn Registrar>>,
    future: impl Future<Output = T>,
) -> T {
    // An inner None is not permission to inherit a different native
    // owner's registrar. Refuse rather than mask or escape an active
    // native scope. Ordinary unscoped proxy calls are unchanged.
    match registrar {
        Some(registrar) => CURRENT.scope(Some(registrar), future).await,
        None if active() => CURRENT.scope(None, future).await,
        None => future.await,
    }
}
pub(crate) fn active() -> bool {
    CURRENT.try_with(|_| ()).is_ok()
}
/// Native Windows carriers must reserve an exclusive local endpoint
/// before bind. A later tuple registration cannot repair shared binding.
pub(crate) fn prepare_tcp(socket: &TcpSocket) -> io::Result<()> {
    #[cfg(all(any(feature = "native-ingress-lab", test), target_os = "windows", target_arch = "x86_64"))]
    if active() {
        return super::windivert::prepare_carrier_tcp(socket);
    }
    #[cfg(not(any(feature = "native-ingress-lab", test)))]
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let _ = socket;
    Ok(())
}
pub(crate) async fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    #[cfg(all(any(feature = "native-ingress-lab", test), target_os = "windows", target_arch = "x86_64"))]
    if active() {
        return super::windivert::bind_carrier_udp(address);
    }
    #[cfg(not(any(feature = "native-ingress-lab", test)))]
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    UdpSocket::bind(address).await
}
pub(crate) fn tcp(socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease> {
    CURRENT
        .try_with(|r| match r {
            Some(r) => r.tcp(socket, peer),
            None => Err(io::ErrorKind::PermissionDenied.into()),
        })
        .unwrap_or_else(|_| Ok(Lease::default()))
}
pub(crate) fn udp(socket: &UdpSocket, peer: SocketAddr) -> io::Result<Lease> {
    CURRENT
        .try_with(|r| match r {
            Some(r) => r.udp(socket, peer),
            None => Err(io::ErrorKind::PermissionDenied.into()),
        })
        .unwrap_or_else(|_| Ok(Lease::default()))
}

/// A listener or ordinary UDP bind is never a native carrier exclusion.
pub(crate) async fn bind_plain_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    UdpSocket::bind(address).await
}

/// Synchronous reservation for a listener transferred to a Tokio owner.
pub(crate) fn bind_std_udp_listener(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let socket = std::net::UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Bind a prepared listener without inheriting outbound carrier privileges.
pub(crate) fn listen_tcp(
    socket: TcpSocket,
    local: SocketAddr,
    backlog: u32,
) -> io::Result<TcpListener> {
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    socket.bind(local)?;
    socket.listen(backlog)
}

/// Create an unconnected TCP socket in the destination family.
pub(crate) fn new_tcp(peer: SocketAddr) -> io::Result<TcpSocket> {
    if peer.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
}

/// Admission must precede the SYN. The caller retains the returned lease
/// for the full lifetime of the connected socket.
pub(crate) fn admit_tcp_dial(socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease> {
    if active() {
        prepare_tcp(socket).map_err(|_| io::ErrorKind::PermissionDenied)?;
        let mut source = selected_source(peer).map_err(|_| io::ErrorKind::PermissionDenied)?;
        if source.ip().is_unspecified() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        source.set_port(0);
        socket.bind(source)?;
    }
    tcp(socket, peer).map_err(|_| io::ErrorKind::PermissionDenied.into())
}

pub(crate) async fn connect_tcp(peer: SocketAddr, nodelay: bool) -> io::Result<(TcpStream, Lease)> {
    let socket = new_tcp(peer)?;
    let lease = admit_tcp_dial(&socket, peer)?;
    let stream = socket.connect(peer).await?;
    if nodelay {
        stream.set_nodelay(true)?;
    }
    if stream.peer_addr()? != peer || (nodelay && !stream.nodelay()?) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((stream, lease))
}

/// Ordinary egress without a retained native lease must never run inside
/// a native registrar. Native paths have a distinct lease-owning API.
pub(crate) async fn connect_plain_tcp(peer: SocketAddr) -> io::Result<TcpStream> {
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    connect_tcp(peer, false).await.map(|(socket, _)| socket)
}

#[derive(Debug)]
pub(crate) enum UdpDialError {
    Bind(io::Error),
    Denied,
    Connect(io::Error),
}
impl UdpDialError {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Bind(error) | Self::Connect(error) => error,
            Self::Denied => io::ErrorKind::PermissionDenied.into(),
        }
    }
}

/// Bind -> validate exact source -> register -> optionally connect.
/// QUIC can retain unconnected I/O for validated path changes outside native capture.
pub(crate) async fn dial_udp(
    local: SocketAddr,
    peer: SocketAddr,
    connected: bool,
    check_local: impl FnOnce(SocketAddr) -> bool,
) -> Result<(UdpSocket, Lease), UdpDialError> {
    let socket = bind_udp(local).await.map_err(UdpDialError::Bind)?;
    if !check_local(socket.local_addr().map_err(UdpDialError::Bind)?) {
        return Err(UdpDialError::Denied);
    }
    let lease = udp(&socket, peer).map_err(|_| UdpDialError::Denied)?;
    if connected {
        socket.connect(peer).await.map_err(UdpDialError::Connect)?;
        if socket.peer_addr().ok() != Some(peer) {
            return Err(UdpDialError::Denied);
        }
    }
    Ok((socket, lease))
}

pub(crate) async fn connect_plain_udp(peer: SocketAddr) -> io::Result<UdpSocket> {
    if active() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let bind = wildcard(peer);
    dial_udp(bind, peer, true, |_| true)
        .await
        .map(|(socket, _)| socket)
        .map_err(UdpDialError::into_io)
}

fn wildcard(peer: SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

/// Route observation selects a source without sending a datagram. On
/// Windows under native capture use the existing read-only OS query.
pub(crate) fn selected_source(peer: SocketAddr) -> io::Result<SocketAddr> {
    #[cfg(target_os = "windows")]
    if active() {
        return windows_route_binding(peer)
            .map(|(source, _)| source)
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into());
    }
    let socket = std::net::UdpSocket::bind(wildcard(peer))?;
    socket.connect(peer)?;
    socket.local_addr()
}

/// Return the same route source and its actual selected interface from
/// one read-only route observation. The capture backend independently
/// pins GUID/LUID and revalidates the network epoch.
#[cfg(target_os = "windows")]
pub(crate) fn windows_route_binding(remote: SocketAddr) -> Option<(SocketAddr, u32)> {
    use std::{
        mem,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        ptr,
    };
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{GetBestInterfaceEx, GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET},
    };
    if remote.ip().is_unspecified() || remote.ip().is_multicast() {
        return None;
    }
    let mut dst: SOCKADDR_INET = unsafe { mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };
    if mem::size_of::<SOCKADDR_INET>() != 28 {
        return None;
    }
    let raw = unsafe {
        std::slice::from_raw_parts_mut((&mut dst as *mut SOCKADDR_INET).cast::<u8>(), 28)
    };
    match remote {
        SocketAddr::V4(v4) => {
            raw[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            raw[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            if v6.scope_id() != 0 || v6.ip().to_ipv4_mapped().is_some() {
                return None;
            }
            raw[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            raw[8..24].copy_from_slice(&v6.ip().octets());
        }
    }
    let mut interface = 0u32;
    if unsafe { GetBestInterfaceEx((&mut dst as *mut SOCKADDR_INET).cast(), &mut interface) } != 0
        || interface == 0
    {
        return None;
    }
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    if unsafe {
        GetBestRoute2(
            ptr::null(),
            interface,
            ptr::null(),
            &dst,
            0,
            &mut route,
            &mut source,
        )
    } != 0
    {
        return None;
    }
    let raw =
        unsafe { std::slice::from_raw_parts((&source as *const SOCKADDR_INET).cast::<u8>(), 28) };
    let family = u16::from_ne_bytes(raw[..2].try_into().ok()?);
    let ip = match (remote, family) {
        (SocketAddr::V4(_), AF_INET) => {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[4..8]).ok()?))
        }
        (SocketAddr::V6(_), AF_INET6) if raw[24..28] == [0; 4] => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?))
        }
        _ => return None,
    };
    (!ip.is_unspecified() && !ip.is_multicast() && route.InterfaceIndex == interface)
        .then_some((SocketAddr::new(ip, 0), interface))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Refuse;
    impl Registrar for Refuse {
        fn tcp(&self, _: &TcpSocket, _: SocketAddr) -> io::Result<Lease> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn udp(&self, _: &UdpSocket, _: SocketAddr) -> io::Result<Lease> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn retire(&self) -> io::Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn factory_rejects_plain_and_registered_egress_in_denied_scope() {
        let tcp_peer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = tcp_peer.local_addr().unwrap();
        let udp_target = udp_peer.local_addr().unwrap();
        scope(Some(Arc::new(Refuse)), async {
            assert!(connect_plain_tcp(tcp_target).await.is_err());
            assert!(connect_plain_udp(udp_target).await.is_err());
            assert!(bind_plain_udp("127.0.0.1:0".parse().unwrap())
                .await
                .is_err());
            assert!(bind_std_udp_listener("127.0.0.1:0".parse().unwrap()).is_err());
            assert!(listen_tcp(
                new_tcp(tcp_target).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
                8
            )
            .is_err());
            assert!(connect_tcp(tcp_target, true).await.is_err());
            assert!(
                dial_udp("127.0.0.1:0".parse().unwrap(), udp_target, true, |_| true)
                    .await
                    .is_err()
            );
        })
        .await;
        assert!(connect_plain_tcp(tcp_target).await.is_ok());
        assert!(connect_plain_udp(udp_target).await.is_ok());
        assert_eq!(selected_source(udp_target).unwrap().ip(), udp_target.ip());
        let reserved = bind_std_udp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(std::net::UdpSocket::bind(reserved.local_addr().unwrap()).is_err());
        assert!(matches!(
            dial_udp("127.0.0.1:0".parse().unwrap(), udp_target, true, |_| false).await,
            Err(UdpDialError::Denied)
        ));
    }
    #[tokio::test]
    async fn scoped_denial_never_leaks_to_other_tasks() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer = "127.0.0.1:443".parse().unwrap();
        assert!(tcp(&socket, peer).is_ok());
        scope(Some(Arc::new(Refuse)), async {
            assert!(active());
            assert!(tcp(&socket, peer).is_err());
            scope(None, async {
                assert!(active());
                assert!(tcp(&socket, peer).is_err());
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                assert!(udp(&udp_socket, peer).is_err());
                scope(None, async {
                    assert!(tcp(&socket, peer).is_err());
                })
                .await;
            })
            .await;
            assert!(tcp(&socket, peer).is_err());
            assert!(!tokio::spawn(async { active() }).await.unwrap());
        })
        .await;
        assert!(!active());
        assert!(tcp(&socket, peer).is_ok());
    }
}
