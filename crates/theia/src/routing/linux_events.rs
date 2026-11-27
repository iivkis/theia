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
        fresh_timestamp(self.timestamp)
    }
    /// Blocking diagnostic: event cookie, PID start, executable inode/dev,
    /// executable hash and the live connected socket must all agree.
    /// A shared/inherited socket and unconnected UDP still need additional
    /// attribution. This result is not a trusted routing credential.
    pub fn corroborate(&self, fd: i32) -> io::Result<CorroboratedFlow> {
        super::linux_attribution::observe_event(self, fd)
    }
}

fn fresh_timestamp(timestamp:u64)->io::Result<()> {
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
            .checked_sub(timestamp)
            .is_none_or(|age| age > MAX_AGE_NS)
        {
            return Err(denied());
        }
        Ok(())
}

pub(super) const PACKET_EVENT_SIZE:usize=72;
/// Metadata emitted from the actual cgroup egress skb. A parsed record
/// alone is untrusted; only the private ring collector establishes origin.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct KernelPacketEvent {
    cookie:u64,
    timestamp:u64,
    key:FlowKey,
    length:u32,
}
impl KernelPacketEvent {
    pub fn parse(bytes:&[u8])->io::Result<Self> {
        use super::packet::Transport;
        if bytes.len()!=PACKET_EVENT_SIZE || bytes[68..72]!=[0;4] { return Err(invalid()); }
        let u64_at=|i|u64::from_ne_bytes(bytes[i..i+8].try_into().expect("fixed wire"));
        let u32_at=|i|u32::from_ne_bytes(bytes[i..i+4].try_into().expect("fixed wire"));
        let cookie=u64_at(0);
        let timestamp=u64_at(8);
        let family=u32_at(16);
        let transport=match u32_at(20) {
            6=>Transport::Tcp,
            17=>Transport::Udp,
            _=>return Err(invalid()),
        };
        let interface=u32_at(24);
        let length=u32_at(28);
        let ip=|raw:&[u8]|->io::Result<IpAddr>{
            let result=match family {
                4 if raw[4..]==[0;12]=>IpAddr::V4(Ipv4Addr::from(<[u8;4]>::try_from(&raw[..4]).map_err(|_|invalid())?)),
                6=>{
                    let v6=Ipv6Addr::from(<[u8;16]>::try_from(raw).map_err(|_|invalid())?);
                    if v6.to_ipv4_mapped().is_some() || v6.is_unicast_link_local() { return Err(invalid()); }
                    IpAddr::V6(v6)
                },
                _=>return Err(invalid()),
            };
            if result.is_unspecified() || result.is_multicast() { return Err(invalid()); }
            Ok(result)
        };
        let source=SocketAddr::new(ip(&bytes[32..48])?,u16::from_ne_bytes(bytes[64..66].try_into().map_err(|_|invalid())?));
        let destination=SocketAddr::new(ip(&bytes[48..64])?,u16::from_ne_bytes(bytes[66..68].try_into().map_err(|_|invalid())?));
        let minimum=(if family==4 {20} else {40}) + (if transport==Transport::Tcp {20} else {8});
        if cookie==0 || timestamp==0 || source.port()==0 || destination.port()==0 ||
            source==destination || length<minimum { return Err(invalid()); }
        Ok(Self{cookie,timestamp,key:FlowKey{source,destination,transport,interface},length})
    }
    pub fn cookie(&self)->u64 { self.cookie }
    pub fn key(&self)->FlowKey { self.key }
    pub fn length(&self)->u32 { self.length }
    pub(super) fn fresh(&self)->io::Result<()> { fresh_timestamp(self.timestamp) }
    /// No PID or executable identity is inferred from this event.
    pub(super) fn matches_flow(&self,flow:&KernelFlowEvent)->bool {
        self.cookie==flow.cookie && self.key.destination==flow.destination &&
            (match self.key.transport { super::packet::Transport::Tcp=>6,super::packet::Transport::Udp=>17 })==flow.protocol &&
            self.timestamp>=flow.timestamp
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
    fn packet_metadata_is_cookie_and_protocol_bound_and_rejects_bad_wire() {
        let mut raw=[0u8;PACKET_EVENT_SIZE];
        raw[0..8].copy_from_slice(&7u64.to_ne_bytes());
        raw[8..16].copy_from_slice(&100u64.to_ne_bytes());
        raw[16..20].copy_from_slice(&4u32.to_ne_bytes());
        raw[20..24].copy_from_slice(&17u32.to_ne_bytes());
        raw[24..28].copy_from_slice(&2u32.to_ne_bytes());
        raw[28..32].copy_from_slice(&28u32.to_ne_bytes());
        raw[32..36].copy_from_slice(&[192,0,2,1]);
        raw[48..52].copy_from_slice(&[198,51,100,1]);
        raw[64..66].copy_from_slice(&1234u16.to_ne_bytes());
        raw[66..68].copy_from_slice(&443u16.to_ne_bytes());
        let packet=KernelPacketEvent::parse(&raw).unwrap();
        assert_eq!(packet.cookie(),7);
        assert_eq!(packet.key().source,"192.0.2.1:1234".parse().unwrap());
        assert_eq!(packet.key().interface,2);
        assert_eq!(packet.length(),28);
        let flow=KernelFlowEvent{cookie:7,timestamp:99,process_start:1,inode:1,pid:1,
            dev_major:1,dev_minor:1,protocol:17,destination:packet.key().destination};
        assert!(packet.matches_flow(&flow));
        assert!(!packet.matches_flow(&KernelFlowEvent{cookie:8,..flow}));
        assert!(!packet.matches_flow(&KernelFlowEvent{timestamp:101,..flow}));
        assert!(!packet.matches_flow(&KernelFlowEvent{protocol:6,..flow}));
        for i in 0..raw.len() { assert!(KernelPacketEvent::parse(&raw[..i]).is_err()); }
        raw[68]=1;assert!(KernelPacketEvent::parse(&raw).is_err());raw[68]=0;
        raw[36]=1;assert!(KernelPacketEvent::parse(&raw).is_err());raw[36]=0;
        raw[28..32].copy_from_slice(&27u32.to_ne_bytes());
        assert!(KernelPacketEvent::parse(&raw).is_err());
    }
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
