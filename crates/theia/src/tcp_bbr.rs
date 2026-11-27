//! Fixed carrier policy: prefer BBR, use CUBIC when BBR is unavailable.
//! No runtime global TCP changes. Windows delegates to its native TCP
//! provider (normally CUBIC on supported deployments), never falsely reports
//! that a socket's controller was verified. Local/target TCP is not affected.
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Network,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Unavailable,
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Network
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Controller {
    #[cfg(target_os = "linux")]
    Bbr,
    #[cfg(target_os = "linux")]
    Cubic,
    #[cfg(not(target_os = "linux"))]
    OsManaged,
}

impl Controller {
    pub(crate) fn label(self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::Bbr => "bbr",
            #[cfg(target_os = "linux")]
            Self::Cubic => "cubic",
            #[cfg(not(target_os = "linux"))]
            Self::OsManaged => "os_managed_unverified",
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Controller, Error};
    use std::os::fd::AsRawFd;

    fn set(socket: &impl AsRawFd, name: &[u8]) -> Result<(), Error> {
        // SAFETY: caller holds a live fd; name is a valid buffer.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                name.as_ptr().cast(),
                name.len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn select(socket: &impl AsRawFd) -> Result<Controller, Error> {
        if set(socket, b"bbr\0").is_ok() && verify(socket) == Ok(Controller::Bbr) {
            return Ok(Controller::Bbr);
        }
        set(socket, b"cubic\0")?;
        if verify(socket) == Ok(Controller::Cubic) {
            Ok(Controller::Cubic)
        } else {
            Err(Error::Unavailable)
        }
    }

    pub(crate) fn verify(socket: &impl AsRawFd) -> Result<Controller, Error> {
        let mut name = [0u8; 16]; // Linux TCP_CA_NAME_MAX
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: writable buffer and length are valid; fd remains live.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let len = len as usize;
        if result != 0 || len > name.len() {
            return Err(Error::Unavailable);
        }
        let observed = &name[..len];
        let end = observed.iter().position(|&byte| byte == 0).unwrap_or(len);
        match &observed[..end] {
            b"bbr" => Ok(Controller::Bbr),
            b"cubic" => Ok(Controller::Cubic),
            _ => Err(Error::Unavailable),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{Controller, Error};

    // Winsock has no confirmed supported per-socket BBR/CUBIC selector.
    // Keep native TCP operational; CUBIC is the deployment preference,
    // but a custom OS TCP template may choose differently. No global edits.
    pub(crate) fn select<T>(_socket: &T) -> Result<Controller, Error> {
        Ok(Controller::OsManaged)
    }

    pub(crate) fn verify<T>(_socket: &T) -> Result<Controller, Error> {
        Ok(Controller::OsManaged)
    }
}

pub(crate) use platform::{select, verify};

fn new_socket(address: SocketAddr) -> Result<TcpSocket, Error> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    select(&socket)?;
    Ok(socket)
}

/// Select before connect and observe after connect; return the actual
/// controller when the platform exposes readback.
#[cfg(test)]
pub(crate) async fn connect(endpoint: &str) -> Result<(TcpStream, Controller), Error> {
    for address in tokio::net::lookup_host(endpoint).await? {
        let socket = new_socket(address)?;
        if let Ok(stream) = socket.connect(address).await {
            let controller = verify(&stream)?;
            return Ok((stream, controller));
        }
    }
    Err(Error::Network)
}

/// Product H2 socket factory. The optional scope admits exactly the
/// concrete socket and target before the first SYN. Its lease is retained
/// by the H2 driver task until that connection is destroyed.
pub(crate) async fn connect_carrier(endpoint: &str) -> Result<(TcpStream, Controller, crate::routing::carrier_socket::Lease), Error> {
    use crate::routing::carrier_socket;
    if carrier_socket::active() && endpoint.parse::<SocketAddr>().is_err() {
        // The native capture scope cannot silently send local DNS.
        return Err(Error::Unavailable);
    }
    for address in tokio::net::lookup_host(endpoint).await? {
        let socket = new_socket(address)?;
        if carrier_socket::active() {
            let source = crate::local_proxy::route_source(address).ok_or(Error::Unavailable)?;
            socket.bind(source)?;
        }
        let lease = carrier_socket::tcp(&socket, address).map_err(|_| Error::Unavailable)?;
        if let Ok(stream) = socket.connect(address).await {
            let controller = verify(&stream)?;
            return Ok((stream, controller, lease));
        }
    }
    Err(Error::Network)
}

pub(crate) fn bind(address: SocketAddr) -> Result<TcpListener, Error> {
    let socket = new_socket(address)?;
    #[cfg(target_os = "linux")]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    let listener = socket.listen(1024)?;
    verify(&listener)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn preferred_controller_on_listener_and_both_tcp_peers() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let selected = verify(&listener).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let (client, accepted) = tokio::join!(connect(&endpoint), listener.accept());
        let (mut client, actual) = client.unwrap();
        let (mut server, _) = accepted.unwrap();
        assert_eq!(actual, verify(&client).unwrap());
        assert_eq!(selected, verify(&server).unwrap());
        client.write_all(b"tcp").await.unwrap();
        let mut received = [0; 3];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"tcp");

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let name = b"cubic\0";
            // SAFETY: live fd and static option buffer.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        client.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        libc::TCP_CONGESTION,
                        name.as_ptr().cast(),
                        name.len() as libc::socklen_t,
                    )
                },
                0
            );
            assert_eq!(verify(&client), Ok(Controller::Cubic));
            // If BBR is selectable, the preference must win over CUBIC.
            assert_eq!(select(&client).unwrap(), selected);
            let name = b"reno\0";
            // SAFETY: live fd and static option buffer.
            if unsafe {
                libc::setsockopt(
                    client.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    name.as_ptr().cast(),
                    name.len() as libc::socklen_t,
                )
            } == 0
            {
                assert_eq!(verify(&client), Err(Error::Unavailable));
            }
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(actual, Controller::OsManaged);
    }
}
