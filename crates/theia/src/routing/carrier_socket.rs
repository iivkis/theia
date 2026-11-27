//! Shared client egress socket factory and task-scoped native admission.
//! No process-wide or target-wide exclusion. Ordinary System Proxy has
//! no registrar or OS changes. Native callers retain the exact admission lease.
use std::{future::Future, io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Default)]
pub(crate) struct Lease {
    _resource: Option<Box<dyn Send + Sync>>,
}
impl Lease {
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn retain<T: Send + Sync + 'static>(resource: T) -> Self {
        Self {
            _resource: Some(Box::new(resource)),
        }
    }
}

pub(crate) trait Registrar: Send + Sync {
    fn tcp(&self, socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease>;
    fn udp(&self, socket: &UdpSocket, peer: SocketAddr) -> io::Result<Lease>;
    #[cfg(target_os="linux")]
    fn udp_reply(&self,socket:&UdpSocket,peer:SocketAddr)->io::Result<Lease> {
        self.udp(socket,peer)
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
pub(crate) fn prepare_tcp(socket:&TcpSocket)->io::Result<()> {
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    if active() {
        return super::windivert::prepare_carrier_tcp(socket);
    }
    let _=socket;
    Ok(())
}
pub(crate) async fn bind_udp(address:SocketAddr)->io::Result<UdpSocket> {
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    if active() {
        return super::windivert::bind_carrier_udp(address);
    }
    UdpSocket::bind(address).await
}
pub(crate) fn tcp(socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease> {
    CURRENT.try_with(|r| match r {
        Some(r) => r.tcp(socket, peer),
        None => Err(io::ErrorKind::PermissionDenied.into()),
    }).unwrap_or_else(|_| Ok(Lease::default()))
}
pub(crate) fn udp(socket: &UdpSocket, peer: SocketAddr) -> io::Result<Lease> {
    CURRENT.try_with(|r| match r {
        Some(r) => r.udp(socket, peer),
        None => Err(io::ErrorKind::PermissionDenied.into()),
    }).unwrap_or_else(|_| Ok(Lease::default()))
}

/// Create an unconnected TCP socket in the destination family.
pub(crate) fn new_tcp(peer: SocketAddr) -> io::Result<TcpSocket> {
    if peer.is_ipv4() { TcpSocket::new_v4() } else { TcpSocket::new_v6() }
}

/// Admission must precede the SYN. The caller retains the returned lease
/// for the full lifetime of the connected socket.
pub(crate) fn admit_tcp_dial(socket: &TcpSocket, peer: SocketAddr) -> io::Result<Lease> {
    if active() {
        prepare_tcp(socket).map_err(|_| io::ErrorKind::PermissionDenied)?;
        let source = crate::local_proxy::route_source(peer).ok_or(io::ErrorKind::PermissionDenied)?;
        socket.bind(source)?;
    }
    tcp(socket, peer).map_err(|_| io::ErrorKind::PermissionDenied.into())
}

pub(crate) async fn connect_tcp(peer: SocketAddr, nodelay: bool) -> io::Result<(TcpStream, Lease)> {
    let socket = new_tcp(peer)?;
    let lease = admit_tcp_dial(&socket, peer)?;
    let stream = socket.connect(peer).await?;
    if nodelay { stream.set_nodelay(true)?; }
    if stream.peer_addr()? != peer || (nodelay && !stream.nodelay()?) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((stream, lease))
}

/// Ordinary egress without a retained native lease must never run inside
/// a native registrar. Native paths have a distinct lease-owning API.
pub(crate) async fn connect_plain_tcp(peer: SocketAddr) -> io::Result<TcpStream> {
    if active() { return Err(io::ErrorKind::PermissionDenied.into()); }
    connect_tcp(peer, false).await.map(|(socket, _)| socket)
}

#[derive(Debug)]
pub(crate) enum UdpDialError { Bind(io::Error), Denied, Connect(io::Error) }
impl UdpDialError {
    pub(crate) fn into_io(self) -> io::Error {
        match self { Self::Bind(error) | Self::Connect(error) => error, Self::Denied => io::ErrorKind::PermissionDenied.into() }
    }
}

/// Bind -> validate exact source -> register -> optionally connect.
/// QUIC can retain unconnected I/O for validated path changes outside native capture.
pub(crate) async fn dial_udp(
    local: SocketAddr, peer: SocketAddr, connected: bool, check_local: impl FnOnce(SocketAddr) -> bool,
) -> Result<(UdpSocket, Lease), UdpDialError> {
    let socket = bind_udp(local).await.map_err(UdpDialError::Bind)?;
    if !check_local(socket.local_addr().map_err(UdpDialError::Bind)?) { return Err(UdpDialError::Denied); }
    let lease = udp(&socket, peer).map_err(|_| UdpDialError::Denied)?;
    if connected {
        socket.connect(peer).await.map_err(UdpDialError::Connect)?;
        if socket.peer_addr().ok() != Some(peer) { return Err(UdpDialError::Denied); }
    }
    Ok((socket, lease))
}

pub(crate) async fn connect_plain_udp(peer: SocketAddr) -> io::Result<UdpSocket> {
    if active() { return Err(io::ErrorKind::PermissionDenied.into()); }
    let bind = if peer.is_ipv4() { SocketAddr::from(([0,0,0,0],0)) } else { SocketAddr::from(([0u16;8],0)) };
    dial_udp(bind, peer, true, |_| true).await.map(|(socket, _)| socket).map_err(UdpDialError::into_io)
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
        fn retire(&self) -> io::Result<()> { Ok(()) }
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
            assert!(connect_tcp(tcp_target, true).await.is_err());
            assert!(dial_udp("127.0.0.1:0".parse().unwrap(), udp_target, true, |_| true).await.is_err());
        }).await;
        assert!(connect_plain_tcp(tcp_target).await.is_ok());
        assert!(connect_plain_udp(udp_target).await.is_ok());
        assert!(matches!(dial_udp("127.0.0.1:0".parse().unwrap(), udp_target, true, |_| false).await, Err(UdpDialError::Denied)));
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
                scope(None, async { assert!(tcp(&socket, peer).is_err()); }).await;
            }).await;
            assert!(tcp(&socket, peer).is_err());
            assert!(!tokio::spawn(async { active() }).await.unwrap());
        })
        .await;
        assert!(!active());
        assert!(tcp(&socket, peer).is_ok());
    }
}
