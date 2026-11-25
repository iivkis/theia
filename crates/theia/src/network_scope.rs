//! Local network generation, separate from TLS identity and authorization.
//! Observes OS routing/address/link notifications only. No remote probes,
//! DNS, packet payload, network names or identifiers in diagnostics.
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    source: SocketAddr,
    epoch: u64,
}

impl Scope {
    #[cfg(test)]
    pub(crate) fn fixture(source: SocketAddr, epoch: u64) -> Self {
        Self { source, epoch }
    }
}

#[cfg(test)]
impl std::str::FromStr for Scope {
    type Err = std::net::AddrParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Ok(Self::fixture(raw.parse()?, 0))
    }
}

/// Bracket source selection with two observations. A transition or an
/// unavailable observer prevents reuse and negative-cache publication.
pub(crate) fn observe(remote: SocketAddr) -> Option<Scope> {
    let before = platform::epoch()?;
    let source = crate::local_proxy::route_source(remote)?;
    let after = platform::epoch()?;
    (before == after).then_some(Scope {
        source,
        epoch: after,
    })
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        io, mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::{Mutex, OnceLock},
    };

    #[derive(Default)]
    struct Observer {
        socket: Option<OwnedFd>,
        epoch: u64,
    }

    fn subscribe() -> io::Result<OwnedFd> {
        // SAFETY: a Linux route notification socket; no writes or requests.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new uniquely owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zero is valid for the integer fields and padding of sockaddr_nl.
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_groups = (libc::RTMGRP_LINK
            | libc::RTMGRP_IPV4_IFADDR
            | libc::RTMGRP_IPV6_IFADDR
            | libc::RTMGRP_IPV4_ROUTE
            | libc::RTMGRP_IPV6_ROUTE
            | libc::RTMGRP_IPV4_RULE) as u32
            | (1 << 18); // RTNLGRP_IPV6_RULE (group 19).
                         // SAFETY: a fully initialized address, borrowed only during bind.
        let status = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    impl Observer {
        fn changed(&mut self) -> Option<()> {
            self.epoch = self.epoch.checked_add(1)?;
            Some(())
        }

        fn poll(&mut self) -> Option<u64> {
            if self.socket.is_none() {
                self.socket = Some(subscribe().ok()?);
                self.changed()?;
            }
            // Every message on the subscribed groups is evidence of change.
            // Discard it, including identifiers, rather than parsing payload.
            // MSG_TRUNC consumes the datagram even if the buffer is smaller.
            let fd = self.socket.as_ref()?.as_raw_fd();
            let mut byte = 0u8;
            for _ in 0..256 {
                // SAFETY: fd is owned by self; writable one-byte buffer.
                let n = unsafe {
                    libc::recv(
                        fd,
                        (&mut byte as *mut u8).cast(),
                        1,
                        libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    )
                };
                if n > 0 {
                    self.changed()?;
                    continue;
                }
                if n < 0 {
                    let error = io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(libc::EAGAIN) => return Some(self.epoch),
                        Some(libc::EINTR) => continue,
                        Some(libc::ENOBUFS) => {
                            // Notification loss invalidates all prior evidence.
                            self.changed()?;
                            continue;
                        }
                        _ => {}
                    }
                }
                // On an unexpected socket failure, reopen on next observation
                // under a new epoch. Never resurrect an earlier cache entry.
                self.socket = None;
                self.changed()?;
                return None;
            }
            // A notification storm is not a stable network.
            None
        }
    }

    pub(super) fn epoch() -> Option<u64> {
        static OBSERVER: OnceLock<Mutex<Observer>> = OnceLock::new();
        OBSERVER
            .get_or_init(|| Mutex::new(Observer::default()))
            .lock()
            .ok()?
            .poll()
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::{
        ffi::c_void,
        ptr,
        sync::{
            atomic::{AtomicU64, Ordering},
            OnceLock,
        },
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        NetworkManagement::IpHelper::{
            CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2,
            NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
            MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
        },
        Networking::WinSock::AF_UNSPEC,
    };

    static EPOCH: AtomicU64 = AtomicU64::new(1);

    fn changed() {
        // Saturation disables caching instead of reusing an old generation.
        let _ = EPOCH.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            Some(n.saturating_add(1))
        });
    }

    unsafe extern "system" fn route(
        _: *const c_void,
        _: *const MIB_IPFORWARD_ROW2,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        changed();
    }

    unsafe extern "system" fn interface(
        _: *const c_void,
        _: *const MIB_IPINTERFACE_ROW,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        changed();
    }

    unsafe extern "system" fn address(
        _: *const c_void,
        _: *const MIB_UNICASTIPADDRESS_ROW,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        changed();
    }

    fn subscribe() -> bool {
        let mut handles: [HANDLE; 3] = [ptr::null_mut(); 3];
        // SAFETY: callbacks use process-lifetime static atomics only, never
        // dereference OS pointers or caller context. Registrations are
        // bounded to one set for this process, released by the OS at exit.
        unsafe {
            let results = [
                NotifyRouteChange2(AF_UNSPEC, Some(route), ptr::null(), false, &mut handles[0]),
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface),
                    ptr::null(),
                    false,
                    &mut handles[1],
                ),
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(address),
                    ptr::null(),
                    false,
                    &mut handles[2],
                ),
            ];
            if results.iter().all(|status| *status == 0) {
                return true;
            }
            for (status, handle) in results.into_iter().zip(handles) {
                if status == 0 && !handle.is_null() {
                    let _ = CancelMibChangeNotify2(handle);
                }
            }
        }
        false
    }

    pub(super) fn epoch() -> Option<u64> {
        static SUBSCRIBED: OnceLock<bool> = OnceLock::new();
        if !*SUBSCRIBED.get_or_init(subscribe) {
            return None;
        }
        let value = EPOCH.load(Ordering::Acquire);
        (value != u64::MAX).then_some(value)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    pub(super) fn epoch() -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_ip_in_a_different_generation_is_not_the_same_scope() {
        let source = "192.0.2.1:0".parse().unwrap();
        assert!(Scope::fixture(source, 1) == Scope::fixture(source, 1));
        assert!(Scope::fixture(source, 1) != Scope::fixture(source, 2));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn loopback_observation_does_not_send_datagrams() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let remote = peer.local_addr().unwrap();
        // An actual concurrent network change can make a single observation
        // unavailable. Retry within a bounded number of local observations.
        assert!((0..16).any(|_| observe(remote).is_some()));
        assert_eq!(
            peer.recv_from(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
