//! Parser and OS corroboration for the optional Linux CO-RE cgroup event
//! collector. A trusted loader must supply the actual private ring-buffer
//! records. Arbitrary bytes cannot prove that a kernel event occurred;
//! these observations must NOT authorize native egress until that loader
//! and the capture-side socket identity binding are independently accepted.
use super::{packet::FlowKey, ApplicationId};
use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

const SIZE: usize = 88;
const MAX_AGE_NS: u64 = 2_000_000_000;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFlowEvent {
    pub(super) cookie: u64,
    pub(super) process_start: u64,
    pub(super) inode: u64,
    pub(super) pid: u32,
    pub(super) dev_major: u32,
    pub(super) dev_minor: u32,
    pub(super) protocol: u8,
    pub(super) destination: SocketAddr,
    timestamp: u64,
}
impl KernelFlowEvent {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != SIZE || bytes[60..64] != [0; 4] || bytes[82..88] != [0; 6] {
            return Err(invalid());
        }
        let u64_at = |i| u64::from_ne_bytes(bytes[i..i + 8].try_into().expect("fixed wire"));
        let u32_at = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().expect("fixed wire"));
        let cookie = u64_at(0);
        let timestamp = u64_at(8);
        let process_start = u64_at(16);
        let inode = u64_at(24);
        let pid_tgid = u64_at(32);
        let pid = (pid_tgid >> 32) as u32;
        let tid = pid_tgid as u32;
        let protocol = u8::try_from(u32_at(52)).map_err(|_| invalid())?;
        let kind = u32_at(56);
        if cookie == 0
            || timestamp == 0
            || process_start == 0
            || inode == 0
            || pid == 0
            || tid == 0
            || !matches!((kind, protocol), (1, 6 | 17) | (2, 17))
        {
            return Err(invalid());
        }
        let ip = match u32_at(48) {
            4 if bytes[68..80] == [0; 12] => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&bytes[64..68]).map_err(|_| invalid())?,
            )),
            6 => {
                let v6 =
                    Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[64..80]).map_err(|_| invalid())?);
                if v6.to_ipv4_mapped().is_some() || v6.is_unicast_link_local() {
                    return Err(invalid());
                }
                IpAddr::V6(v6)
            }
            _ => return Err(invalid()),
        };
        let port = u16::from_ne_bytes(bytes[80..82].try_into().map_err(|_| invalid())?);
        if port == 0 || ip.is_unspecified() || ip.is_multicast() {
            return Err(invalid());
        }
        Ok(Self {
            cookie,
            process_start,
            inode,
            pid,
            dev_major: u32_at(40),
            dev_minor: u32_at(44),
            protocol,
            destination: SocketAddr::new(ip, port),
            timestamp,
        })
    }
    pub(super) fn fresh(&self) -> io::Result<()> {
        let mut now: libc::timespec = unsafe { mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let now_ns = u64::try_from(now.tv_sec)
            .map_err(|_| invalid())?
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(u64::try_from(now.tv_nsec).ok()?))
            .ok_or_else(invalid)?;
        if now_ns
            .checked_sub(self.timestamp)
            .is_none_or(|age| age > MAX_AGE_NS)
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Blocking diagnostic: event cookie, PID start, executable inode/dev,
    /// executable hash and the live connected socket must all agree.
    /// A shared/inherited socket and unconnected UDP still need additional
    /// attribution. This result is not a trusted routing credential.
    pub fn corroborate(&self, fd: i32) -> io::Result<CorroboratedFlow> {
        super::linux_attribution::observe_event(self, fd)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorroboratedFlow {
    pub(super) key: FlowKey,
    pub(super) cookie: u64,
    pub(super) process_start: u64,
    pub(super) application: ApplicationId,
}
impl CorroboratedFlow {
    pub fn key(self) -> FlowKey {
        self.key
    }
    pub fn application(self) -> ApplicationId {
        self.application
    }
    pub fn cookie(self) -> u64 {
        self.cookie
    }
    pub fn process_start(self) -> u64 {
        self.process_start
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_kernel_event_wire_rejects_malformed_and_wrong_protocol() {
        let mut wire = [0u8; SIZE];
        for i in [0, 8, 16, 24] {
            wire[i..i + 8].copy_from_slice(&1u64.to_ne_bytes());
        }
        wire[32..40].copy_from_slice(&((42u64 << 32) | 43).to_ne_bytes());
        wire[48..52].copy_from_slice(&4u32.to_ne_bytes());
        wire[52..56].copy_from_slice(&6u32.to_ne_bytes());
        wire[56..60].copy_from_slice(&1u32.to_ne_bytes());
        wire[64..68].copy_from_slice(&[192, 0, 2, 1]);
        wire[80..82].copy_from_slice(&443u16.to_ne_bytes());
        let event = KernelFlowEvent::parse(&wire).unwrap();
        assert_eq!(event.pid, 42);
        assert_eq!(event.destination, "192.0.2.1:443".parse().unwrap());
        for i in 0..SIZE {
            assert!(KernelFlowEvent::parse(&wire[..i]).is_err());
        }
        wire[56..60].copy_from_slice(&2u32.to_ne_bytes());
        assert!(KernelFlowEvent::parse(&wire).is_err());
    }
}
