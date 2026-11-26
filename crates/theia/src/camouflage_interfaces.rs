//! M3.5b2b1: read assigned network-interface addresses and CIDR masks
//! from the local Linux kernel. No remote network traffic, DNS, STUN, RDAP,
//! active probing or implied permission to inspect neighbouring hosts.
//!
//! Windows builds retain the same typed API and fail with Unsupported until
//! a separately validated Windows-native collector is implemented.

use crate::camouflage_discovery::{InterfaceAddress, ServerSnapshot};
use std::{io, net::IpAddr};

#[cfg(target_os = "linux")]
const MAX_INTERFACE_ADDRESSES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceSource {
    LinuxGetifaddrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedInterface {
    pub interface_name: String,
    pub address: IpAddr,
    pub prefix_len: u8,
    pub is_up: bool,
    /// An address observation is never evidence of IP/CIDR ownership.
    pub source: InterfaceSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NativeInterfaces {
    pub interfaces: Vec<ObservedInterface>,
}

impl NativeInterfaces {
    /// The resulting data has neither public NAT egress nor inferred provider
    /// ownership. The higher-level planner still needs explicit approvals.
    pub fn server_snapshot(&self) -> ServerSnapshot {
        ServerSnapshot {
            interfaces: self
                .interfaces
                .iter()
                .filter(|observed| {
                    observed.is_up
                        && match observed.address {
                            IpAddr::V4(_) => (1..=32).contains(&observed.prefix_len),
                            IpAddr::V6(_) => (1..=128).contains(&observed.prefix_len),
                        }
                })
                .map(|observed| InterfaceAddress {
                    address: observed.address,
                    prefix_len: observed.prefix_len,
                })
                .collect(),
            egress: None,
            inferred_provider_prefixes: Vec::new(),
        }
    }
}

/// Reject unspecified (/0) or non-contiguous masks. In particular, there is
/// no safe way to promote a missing/invalid prefix to a guessed /24 or /64.
pub fn contiguous_netmask_prefix(mask: IpAddr) -> Option<u8> {
    match mask {
        IpAddr::V4(mask) => {
            let bits = u32::from_be_bytes(mask.octets());
            let prefix = bits.leading_ones() as u8;
            if prefix == 0 || bits != u32::MAX << (32 - prefix) {
                None
            } else {
                Some(prefix)
            }
        }
        IpAddr::V6(mask) => {
            let bits = u128::from_be_bytes(mask.octets());
            let prefix = bits.leading_ones() as u8;
            if prefix == 0 || bits != u128::MAX << (128 - prefix) {
                None
            } else {
                Some(prefix)
            }
        }
    }
}

/// Read real on-host assigned IP+netmask entries only. This does not discover
/// public egress behind NAT and never sends packets or queries a remote
/// service. Only Linux servers currently have a collector implementation.
#[cfg(target_os = "linux")]
pub fn collect_assigned_interfaces() -> io::Result<NativeInterfaces> {
    use std::{
        ffi::CStr,
        net::{Ipv4Addr, Ipv6Addr},
        ptr,
    };

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            // SAFETY: getifaddrs created this list and it is freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: a valid writable pointer is supplied. libc initializes it on
    // success; no thread-unsafe shared state is exposed by this API.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if head.is_null() {
        return Err(io::Error::other("getifaddrs returned an empty list"));
    }
    let _guard = IfAddrsGuard(head);
    let mut result = NativeInterfaces::default();
    let mut entry = head;
    let mut visited = 0usize;

    while !entry.is_null() {
        visited += 1;
        if visited > MAX_INTERFACE_ADDRESSES {
            return Err(io::Error::other("network interface result limit exceeded"));
        }
        // SAFETY: entry points into the list owned by _guard. All dereferences
        // and copies happen before freeifaddrs. Null address/netmask/name
        // pointers are checked. libc only returns OS-owned local metadata.
        unsafe {
            let item = &*entry;
            entry = item.ifa_next;
            if item.ifa_addr.is_null() || item.ifa_netmask.is_null() || item.ifa_name.is_null() {
                continue;
            }
            let is_up = item.ifa_flags & (libc::IFF_UP as u32) != 0;
            if !is_up {
                continue;
            }
            let (address, mask) = match (*item.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let ip = &*(item.ifa_addr as *const libc::sockaddr_in);
                    let mask = &*(item.ifa_netmask as *const libc::sockaddr_in);
                    if mask.sin_family as i32 != libc::AF_INET {
                        continue;
                    }
                    (
                        IpAddr::V4(Ipv4Addr::from(ip.sin_addr.s_addr.to_ne_bytes())),
                        IpAddr::V4(Ipv4Addr::from(mask.sin_addr.s_addr.to_ne_bytes())),
                    )
                }
                libc::AF_INET6 => {
                    let ip = &*(item.ifa_addr as *const libc::sockaddr_in6);
                    let mask = &*(item.ifa_netmask as *const libc::sockaddr_in6);
                    if mask.sin6_family as i32 != libc::AF_INET6 {
                        continue;
                    }
                    (
                        IpAddr::V6(Ipv6Addr::from(ip.sin6_addr.s6_addr)),
                        IpAddr::V6(Ipv6Addr::from(mask.sin6_addr.s6_addr)),
                    )
                }
                _ => continue,
            };
            let Some(prefix_len) = contiguous_netmask_prefix(mask) else {
                continue;
            };
            let interface_name = CStr::from_ptr(item.ifa_name).to_string_lossy().into_owned();
            if interface_name.is_empty() {
                continue;
            }
            if !result.interfaces.iter().any(|old| {
                old.interface_name == interface_name
                    && old.address == address
                    && old.prefix_len == prefix_len
            }) {
                result.interfaces.push(ObservedInterface {
                    interface_name,
                    address,
                    prefix_len,
                    is_up,
                    source: InterfaceSource::LinuxGetifaddrs,
                });
            }
        }
    }
    Ok(result)
}

/// Windows collector is an explicit future subtask; do not return invented
/// prefixes from guessed route/egress data or conceal lack of support.
#[cfg(not(target_os = "linux"))]
pub fn collect_assigned_interfaces() -> io::Result<NativeInterfaces> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native interface prefix collector currently supports Linux only",
    ))
}

// DNS-only reverse lookup of a previously authorized exact IPv4 address.
// PTR is neither certificate evidence nor permission to dial.
#[cfg(target_os = "linux")]
pub(crate) async fn reverse_reference_name(address: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    let IpAddr::V4(ip) = address else { return None };
    if !crate::camouflage_discovery::plausible_public_address(address) {
        return None;
    }
    let task = tokio::task::spawn_blocking(move || {
        let socket = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        };
        let mut host = [0 as libc::c_char; 1025];
        // SAFETY: initialized IPv4 address and writable bounded host buffer;
        // NI_NAMEREQD rejects numeric fallback. No service output.
        let status = unsafe {
            libc::getnameinfo(
                (&socket as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&socket) as libc::socklen_t,
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if status != 0 {
            return None;
        }
        // SAFETY: successful lookup writes a NUL-terminated name.
        let name = unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_str()
            .ok()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        crate::camouflage_domain_dns::validate_manual_dns_request(
            &name,
            crate::camouflage_domain_dns::DnsConsent::Approved,
        )
        .ok()?;
        Some(name)
    });
    tokio::time::timeout(crate::camouflage_domain_dns::DNS_DEADLINE, task)
        .await
        .ok()?
        .ok()?
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn reverse_reference_name(_address: IpAddr) -> Option<String> {
    None
}
