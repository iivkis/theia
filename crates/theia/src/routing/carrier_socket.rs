//! Task-scoped native admission hook used only at actual H2/H3 carrier
//! socket construction. No process-wide or target-wide exclusion.
//! In ordinary proxy operation there is no registrar and no OS change.
use std::{future::Future, io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpSocket, UdpSocket};

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
