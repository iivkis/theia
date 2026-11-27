//! OS-assisted socket ownership observations for future native attribution.
//! A pidfd plus exact socket cookie rejects PID/FD reuse. It does NOT prove
//! which process sent an individual packet: inherited/shared sockets and
//! exec races require kernel-origin connect/send events. Never promote this
//! observation to routing Evidence::Known on its own.
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    mem,
    net::{TcpStream, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
};

const MAX_EXECUTABLE: u64 = 128 * 1024 * 1024;
const SO_COOKIE: libc::c_int = 57;

fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

/// Read the kernel socket cookie from a live socket, not a PID, mark or
/// process name. A caller-supplied cookie must still originate from a
/// trusted flow event before it can establish ownership.
pub fn socket_cookie(socket: &impl AsRawFd) -> io::Result<u64> {
    let mut cookie = 0u64;
    let mut size = mem::size_of_val(&cookie) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cookie == 0 || size as usize != mem::size_of_val(&cookie) {
        return Err(denied());
    }
    Ok(cookie)
}

fn owned_syscall(raw: libc::c_long) -> io::Result<OwnedFd> {
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = i32::try_from(raw).map_err(|_| denied())?;
    // SAFETY: successful pidfd_open/getfd returns a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn duplicate(pidfd: &OwnedFd, fd: i32) -> io::Result<OwnedFd> {
    owned_syscall(unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) })
}
fn live(pidfd: &OwnedFd) -> io::Result<()> {
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if rc != 0 || p.revents != 0 {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn identity(file: &File) -> io::Result<FileIdentity> {
    let m = file.metadata()?;
    if !m.is_file() || m.len() == 0 || m.len() > MAX_EXECUTABLE {
        return Err(denied());
    }
    Ok(FileIdentity {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOwnerObservation {
    pub socket_cookie: u64,
    pub executable_sha256: [u8; 32],
}

/// Blocking, bounded diagnostic. Requires pidfd_getfd permissions and a
/// kernel-provided event containing pid, descriptor and cookie. Restricted
/// kernels/processes return errors; no fallback to process-name matching.
pub fn observe_socket_owner(
    pid: u32,
    fd: i32,
    expected_cookie: u64,
) -> io::Result<SocketOwnerObservation> {
    observe_inner(pid, fd, expected_cookie, None).map(|(owner, _)| owner)
}

pub(super) fn observe_event(
    event: &super::linux_events::KernelFlowEvent,
    fd: i32,
) -> io::Result<super::linux_events::CorroboratedFlow> {
    event.fresh()?;
    let (owner, key) = observe_inner(event.pid, fd, event.cookie, Some(event))?;
    event.fresh()?;
    Ok(super::linux_events::CorroboratedFlow {
        key: key.ok_or_else(denied)?,
        cookie: owner.socket_cookie,
        process_start: event.process_start,
        application: super::ApplicationId::from_sha256(owner.executable_sha256),
    })
}

fn proc_start_ticks(pid: u32) -> io::Result<u64> {
    let file = File::open(format!("/proc/{pid}/stat"))?;
    let mut text = String::new();
    file.take(8192).read_to_string(&mut text)?;
    // comm may contain spaces and closing parentheses; fields after its
    // final ')' are ASCII state and numbers. starttime is field 22.
    text.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|word| word.parse().ok())
        .ok_or_else(denied)
}
fn matches_start(pid: u32, ns: u64) -> io::Result<bool> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return Err(denied());
    }
    let ticks = (u128::from(ns) * hz as u128) / 1_000_000_000;
    let ticks = u64::try_from(ticks).map_err(|_| denied())?;
    Ok(proc_start_ticks(pid)?.abs_diff(ticks) <= 1)
}
fn linux_device(dev: u64) -> (u32, u32) {
    (
        ((dev & 0x0000_0000_000f_ff00) >> 8 | (dev & 0xffff_f000_0000_0000) >> 32) as u32,
        ((dev & 0xff) | (dev & 0x0000_0fff_fff0_0000) >> 12) as u32,
    )
}
fn connected_key(
    socket: &OwnedFd,
    event: &super::linux_events::KernelFlowEvent,
) -> io::Result<super::packet::FlowKey> {
    use super::packet::{FlowKey, Transport};
    let mut protocol: libc::c_int = 0;
    let mut len = mem::size_of_val(&protocol) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PROTOCOL,
            (&mut protocol as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of_val(&protocol) || protocol != i32::from(event.protocol) {
        return Err(denied());
    }
    let fd = socket.try_clone()?;
    let (source, destination, transport) = match protocol {
        libc::IPPROTO_TCP => {
            let s = TcpStream::from(fd);
            (s.local_addr()?, s.peer_addr()?, Transport::Tcp)
        }
        libc::IPPROTO_UDP => {
            let s = UdpSocket::from(fd);
            (s.local_addr()?, s.peer_addr()?, Transport::Udp)
        }
        _ => return Err(denied()),
    };
    if destination != event.destination
        || source.ip().is_unspecified()
        || source.port() == 0
        || source.is_ipv4() != destination.is_ipv4()
    {
        return Err(denied());
    }
    Ok(FlowKey {
        source,
        destination,
        transport,
        interface: 0,
    })
}
fn observe_inner(
    pid: u32,
    fd: i32,
    expected_cookie: u64,
    event: Option<&super::linux_events::KernelFlowEvent>,
) -> io::Result<(SocketOwnerObservation, Option<super::packet::FlowKey>)> {
    if pid == 0 || pid > i32::MAX as u32 || fd < 0 || expected_cookie == 0 {
        return Err(denied());
    }
    let pidfd = owned_syscall(unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) })?;
    live(&pidfd)?;
    let socket = duplicate(&pidfd, fd)?;
    if socket_cookie(&socket)? != expected_cookie {
        return Err(denied());
    }
    let key = event.map(|e| connected_key(&socket, e)).transpose()?;
    if let Some(e) = event {
        if !matches_start(pid, e.process_start)? {
            return Err(denied());
        }
    }

    // /proc/PID/exe resolves the kernel's current executable file. Keep the
    // file descriptor open during hashing, and reject changed inode/metadata.
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let mut executable = File::open(&path)?;
    let before = identity(&executable)?;
    if let Some(e) = event {
        if before.ino != e.inode || linux_device(before.dev) != (e.dev_major, e.dev_minor) {
            return Err(denied());
        }
    }
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 32 * 1024];
    let mut remaining = before.size;
    while remaining != 0 {
        let size = usize::try_from(remaining.min(bytes.len() as u64)).map_err(|_| denied())?;
        let n = executable.read(&mut bytes[..size])?;
        if n == 0 {
            return Err(denied());
        }
        hash.update(&bytes[..n]);
        remaining -= n as u64;
    }
    if executable.read(&mut [0u8; 1])? != 0
        || identity(&executable)? != before
        || identity(&File::open(&path)?)? != before
    {
        return Err(denied());
    }
    live(&pidfd)?;
    let current_socket = duplicate(&pidfd, fd)?;
    if socket_cookie(&current_socket)? != expected_cookie {
        return Err(denied());
    }
    if let Some(e) = event {
        if !matches_start(pid, e.process_start)? || Some(connected_key(&current_socket, e)?) != key
        {
            return Err(denied());
        }
    }
    Ok((
        SocketOwnerObservation {
            socket_cookie: expected_cookie,
            executable_sha256: hash.finalize().into(),
        },
        key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow_event(
        peer: std::net::SocketAddr,
        protocol: u32,
    ) -> super::super::linux_events::KernelFlowEvent {
        let mut bytes = [0u8; 88];
        for offset in [0, 8, 16, 24] {
            bytes[offset..offset + 8].copy_from_slice(&1u64.to_ne_bytes());
        }
        bytes[32..40].copy_from_slice(&0x1_0000_0001u64.to_ne_bytes());
        bytes[52..56].copy_from_slice(&protocol.to_ne_bytes());
        bytes[56..60].copy_from_slice(&1u32.to_ne_bytes());
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                bytes[48..52].copy_from_slice(&4u32.to_ne_bytes());
                bytes[64..68].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                bytes[48..52].copy_from_slice(&6u32.to_ne_bytes());
                bytes[64..80].copy_from_slice(&ip.octets());
            }
        }
        bytes[80..82].copy_from_slice(&peer.port().to_ne_bytes());
        super::super::linux_events::KernelFlowEvent::parse(&bytes).unwrap()
    }

    #[test]
    fn exact_connected_tuple_requires_matching_protocol_and_peer() {
        use super::super::packet::Transport;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let tcp = TcpStream::connect(target).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let fd: OwnedFd = tcp.try_clone().unwrap().into();
        let key = connected_key(&fd, &flow_event(target, 6)).unwrap();
        assert_eq!(key.source, tcp.local_addr().unwrap());
        assert_eq!(key.destination, target);
        assert_eq!(key.transport, Transport::Tcp);
        assert!(connected_key(&fd, &flow_event(target, 17)).is_err());

        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = b.local_addr().unwrap();
        let fd: OwnedFd = a.try_clone().unwrap().into();
        assert!(connected_key(&fd, &flow_event(dest, 17)).is_err());
        a.connect(dest).unwrap();
        let key = connected_key(&fd, &flow_event(dest, 17)).unwrap();
        assert_eq!(key.source, a.local_addr().unwrap());
        assert_eq!(key.destination, dest);
        assert_eq!(key.transport, Transport::Udp);
        assert!(connected_key(&fd, &flow_event(c.local_addr().unwrap(), 17)).is_err());
        assert!(connected_key(&fd, &flow_event(dest, 6)).is_err());
        let ordinary_file: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(connected_key(&ordinary_file, &flow_event(dest, 17)).is_err());
        assert!(socket_cookie(&ordinary_file).is_err());
    }

    #[test]
    fn live_process_and_executable_metadata_are_not_interchangeable() {
        let pid = std::process::id();
        let pidfd =
            owned_syscall(unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) }).unwrap();
        assert!(live(&pidfd).is_ok());
        let ticks = proc_start_ticks(pid).unwrap();
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u128;
        let ns = u64::try_from((u128::from(ticks) * 1_000_000_000).div_ceil(hz)).unwrap();
        assert!(matches_start(pid, ns).unwrap());
        assert!(!matches_start(pid, ns + 5_000_000_000).unwrap());
        assert!(proc_start_ticks(u32::MAX).is_err());
        assert!(owned_syscall(unsafe { libc::syscall(libc::SYS_pidfd_open, -1i32, 0) }).is_err());
        assert_eq!(linux_device(0x1234), (0x12, 0x34));
        assert!(identity(&File::open("/dev/null").unwrap()).is_err());
        let path = std::env::temp_dir().join(format!(
            "theia-executable-identity-{}-{}",
            pid,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"fixture").unwrap();
        let file = File::open(&path).unwrap();
        let before = identity(&file).unwrap();
        assert_eq!(before.size, 7);
        assert!(identity(&file).unwrap() == before);
        std::fs::write(&path, b"replacement").unwrap();
        assert!(identity(&file).unwrap() != before);
        std::fs::remove_file(path).unwrap();

        // The real pidfd_getfd may be restricted by runner policy. A wrong
        // cookie must never succeed regardless of that permission.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(
            observe_socket_owner(pid, socket.as_raw_fd(), socket_cookie(&other).unwrap()).is_err()
        );
    }

    #[test]
    fn actual_kernel_cookies_distinguish_sockets_and_survive_duplication() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let cookie = socket_cookie(&a).unwrap();
        assert_ne!(cookie, socket_cookie(&b).unwrap());
        assert_eq!(cookie, socket_cookie(&a.try_clone().unwrap()).unwrap());
        assert!(observe_socket_owner(0, a.as_raw_fd(), cookie).is_err());
        assert!(observe_socket_owner(std::process::id(), -1, cookie).is_err());
    }
}
