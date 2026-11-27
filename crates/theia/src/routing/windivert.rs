//! WinDivert 2.2.2 is the target Windows transport. The ABI is defined
//! independently from the upstream C header, not linked to a custom SYS.
//! NETWORK metadata never authenticates an application or a socket.
//! The probe only opens match-none read-only handles; it cannot set ready.
use super::packet::{PacketMeta, ParseError};
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
use std::io;

pub const UPSTREAM_VERSION: &str = "2.2.2";
pub const MAX_PACKET: usize = 40 + 65535;

/// WinDivert 2.2 x64 address layout (80 bytes, 8-byte alignment).
/// Reserved storage is opaque; parse fields explicitly without C bitfields.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}
const _: [(); 80] = [(); std::mem::size_of::<Address>()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkObservation {
    pub timestamp: i64,
    pub outbound: bool,
    pub sniffed: bool,
    pub interface: u32,
    pub sub_interface: u32,
    pub meta: PacketMeta,
    /// Offloaded packets may have unset checksum flags. This is diagnostic,
    /// never evidence of a valid checksum for modified packet delivery.
    pub transport_checksum_reported_valid: bool,
}

impl Address {
    pub fn from_bytes(raw: &[u8; 80]) -> Self {
        Self {
            timestamp: i64::from_le_bytes(raw[..8].try_into().unwrap()),
            flags: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            reserved: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            data: raw[16..].try_into().unwrap(),
        }
    }

    /// Reject unsupported layers, injected/impostor packets and loopback.
    /// This parses a captured observation; it is not an admission ticket.
    pub fn network(&self, packet: &[u8]) -> Result<NetworkObservation, ParseError> {
        self.network_inner(packet, false)
    }

    fn network_inner(&self, packet: &[u8], loopback_lab: bool) -> Result<NetworkObservation, ParseError> {
        if self.timestamp <= 0 || self.flags & 0xffff != 0
            || self.flags & (1 << 19) != 0
            || (self.flags & (1 << 18) != 0) != loopback_lab
            || self.flags >> 24 != 0 || self.reserved != 0
            || packet.len() > MAX_PACKET
        {
            return Err(ParseError::Unsupported);
        }
        let interface = u32::from_le_bytes(self.data[..4].try_into().unwrap());
        let sub_interface = u32::from_le_bytes(self.data[4..8].try_into().unwrap());
        if interface == 0 && !loopback_lab { return Err(ParseError::Invalid); }
        let meta = PacketMeta::parse(packet, interface)?;
        if meta.flow.source.is_ipv6() != (self.flags & (1 << 20) != 0) {
            return Err(ParseError::Invalid);
        }
        let checksum_flag = match meta.flow.transport {
            super::packet::Transport::Tcp => 22,
            super::packet::Transport::Udp => 23,
        };
        Ok(NetworkObservation {
            timestamp: self.timestamp,
            outbound: self.flags & (1 << 17) != 0,
            sniffed: self.flags & (1 << 16) != 0,
            interface,
            sub_interface,
            meta,
            transport_checksum_reported_valid: self.flags & (1 << checksum_flag) != 0,
        })
    }

    /// Candidate metadata only. PID reuse, missing events and tuple sharing
    /// prohibit treating this as Evidence::Known or a carrier exemption.
    pub fn endpoint_candidate(&self) -> Option<EndpointCandidate> {
        let layer = self.flags & 255;
        let event = (self.flags >> 8) & 255;
        if self.timestamp <= 0 || self.reserved != 0 || self.flags >> 24 != 0
            || self.flags & (1 << 16) == 0
            || !matches!((layer,event),(2,1|2)|(3,3..=7))
        { return None; }
        let endpoint = u64::from_le_bytes(self.data[..8].try_into().ok()?);
        let pid = u32::from_le_bytes(self.data[16..20].try_into().ok()?);
        let protocol = self.data[56];
        if endpoint == 0 || pid == 0 || !matches!(protocol,6|17) { return None; }
        Some(EndpointCandidate { endpoint, pid, timestamp: self.timestamp, event: event as u8,
            layer: layer as u8, protocol, outbound: self.flags & (1<<17) != 0,
            local_port: u16::from_le_bytes(self.data[52..54].try_into().ok()?),
            remote_port: u16::from_le_bytes(self.data[54..56].try_into().ok()?),
            // Preserve upstream words until independently verified address
            // conversion and tuple/time correlation are implemented.
            local_words: self.data[20..36].try_into().ok()?,
            remote_words: self.data[36..52].try_into().ok()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointCandidate {
    pub endpoint: u64,
    pub pid: u32,
    pub timestamp: i64,
    pub layer: u8,
    pub event: u8,
    pub protocol: u8,
    pub outbound: bool,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_words: [u8; 16],
    pub remote_words: [u8; 16],
}

/// Correlation of NETWORK, FLOW and SOCKET observations. This deliberately
/// produces candidates, not authenticated application identity. NETWORK
/// does not carry the endpoint handle or compartment, and may race event
/// delivery. Losing an event stream invalidates the entire epoch.
#[derive(Debug,Clone,Copy,PartialEq,Eq,Hash)]
pub struct EndpointTuple {
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
    pub transport: super::packet::Transport,
}

impl EndpointCandidate {
    pub fn tuple(&self) -> Option<EndpointTuple> {
        use std::net::{IpAddr,Ipv6Addr,SocketAddr};
        let decode=|words:[u8;16]| {
            // WinDivert's host-order 128-bit address uses the low word
            // first; the pinned upstream helper reverses all 16 bytes.
            let v6=Ipv6Addr::from(u128::from_le_bytes(words));
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6),IpAddr::V4)
        };
        let local=decode(self.local_words);
        let remote=decode(self.remote_words);
        if self.local_port==0 || self.remote_port==0 || local.is_unspecified()
            || remote.is_unspecified() || local.is_ipv4()!=remote.is_ipv4()
            || local.is_multicast() || remote.is_multicast()
        { return None; }
        Some(EndpointTuple { local:SocketAddr::new(local,self.local_port),
            remote:SocketAddr::new(remote,self.remote_port),
            transport:match self.protocol { 6=>super::packet::Transport::Tcp,17=>super::packet::Transport::Udp,_=>return None } })
    }
}
#[derive(Default)]
struct EndpointHistory {
    connect: Option<EndpointCandidate>,
    flow: Option<EndpointCandidate>,
    terminal: bool,
    closed_tuple: Option<EndpointTuple>,
}
pub struct CandidateLedger {
    entries: std::collections::HashMap<u64,EndpointHistory>,
    capacity:usize,
    poisoned:bool,
    max_age:i64,
}
impl CandidateLedger {
    /// QPC ticks, not wall-clock milliseconds. Caller must obtain the
    /// actual QPC frequency and establish a fresh receive epoch.
    pub fn new(capacity:usize,max_age:i64)->Option<Self> {
        if !(1..=4096).contains(&capacity) || max_age<=0 { return None; }
        Some(Self { entries:std::collections::HashMap::new(),capacity,poisoned:false,max_age })
    }
    pub fn invalidate(&mut self) { self.poisoned=true; self.entries.clear(); }
    pub fn observe(&mut self,event:EndpointCandidate) {
        if self.poisoned { return; }
        if event.endpoint==0 || event.pid==0 || event.timestamp<=0 { self.invalidate(); return; }
        if !self.entries.contains_key(&event.endpoint) && self.entries.len()>=self.capacity {
            self.invalidate(); return;
        }
        let history=self.entries.entry(event.endpoint).or_default();
        if history.terminal { return; }
        if matches!((event.layer,event.event),(2,2)|(3,7)) {
            history.closed_tuple=event.tuple();
            if history.closed_tuple.is_none() && history.connect.is_none() && history.flow.is_none() {
                self.invalidate();
            } else {
                history.terminal=true;
            }
            return;
        }
        // Bind/listen may not yet have a remote. They cannot establish
        // or refresh an exact candidate. Incoming flows are not admitted.
        if !matches!((event.layer,event.event),(2,1)|(3,4)) { return; }
        if !event.outbound || event.tuple().is_none() {
            history.terminal=true;return;
        }
        let slot=if event.layer==2 { &mut history.flow } else { &mut history.connect };
        if let Some(previous)=slot {
            if *previous!=event { self.invalidate(); }
            return;
        }
        *slot=Some(event);
        if let (Some(a),Some(b))=(history.connect,history.flow) {
            if a.pid!=b.pid || a.tuple()!=b.tuple() || a.timestamp>b.timestamp {
                self.invalidate();
            }
        }
    }
    /// Unique event agreement for the exact packet tuple, bounded age.
    /// No match is returned when any conflicting live candidate exists.
    pub fn correlate(&self,packet:&NetworkObservation)->Option<EndpointCandidate> {
        if self.poisoned || !packet.outbound || packet.sniffed { return None; }
        let key=packet.meta.flow;
        let wanted=EndpointTuple { local:key.source,remote:key.destination,transport:key.transport };
        let mut matched=None;
        for history in self.entries.values() {
            // Keep terminal matching records as ambiguity tombstones for
            // the entire epoch. A tuple reused after close isn't trusted.
            let related=history.closed_tuple==Some(wanted) || [history.connect,history.flow].into_iter().flatten().any(|e|e.tuple()==Some(wanted));
            if !related { continue; }
            if history.terminal || matched.is_some() { return None; }
            let (a,b)=(history.connect?,history.flow?);
            if a.tuple()!=Some(wanted) || b.tuple()!=Some(wanted)
                || a.pid!=b.pid || a.endpoint!=b.endpoint || packet.timestamp<b.timestamp
                || packet.timestamp.saturating_sub(a.timestamp)>self.max_age
            { return None; }
            matched=Some(b);
        }
        matched
    }
}

/// Bound registry for the existing H2/H3 registrar hooks. A lease records
/// only the actual owned socket endpoint, exact concrete local/remote tuple
/// and process. It is not a process-wide or destination-wide filter permit.
/// Packet-level agreement remains a candidate; no production injector
/// consumes it until the independent guard and attribution gates pass.
#[derive(Clone,Default)]
pub struct CarrierRegistry {
    state:std::sync::Arc<std::sync::Mutex<CarrierState>>,
}
#[derive(Default)]
struct CarrierState {
    entries:std::collections::HashMap<u64,CarrierEntry>,
    retired:bool,
    next:u64,
}
#[derive(Clone,Copy)]
struct CarrierEntry {
    generation:u64,
    pid:u32,
    tuple:EndpointTuple,
    live:bool,
}
struct CarrierLease {
    registry:CarrierRegistry,
    endpoint:u64,
    generation:u64,
}
impl Drop for CarrierLease {
    fn drop(&mut self) {
        if let Ok(mut state)=self.registry.state.lock() {
            if let Some(entry)=state.entries.get_mut(&self.endpoint) {
                if entry.generation==self.generation { entry.live=false; }
            }
        }
    }
}
impl CarrierRegistry {
    fn register(&self,endpoint:u64,pid:u32,tuple:EndpointTuple)->Option<CarrierLease> {
        if endpoint==0 || pid==0 || tuple.local.port()==0 || tuple.remote.port()==0
            || tuple.local.ip().is_unspecified() || tuple.remote.ip().is_unspecified()
            || tuple.local.ip().is_multicast() || tuple.remote.ip().is_multicast()
            || tuple.local.is_ipv4()!=tuple.remote.is_ipv4() || tuple.local==tuple.remote
            || matches!(tuple.local,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
            || matches!(tuple.remote,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
        { return None; }
        let mut state=self.state.lock().ok()?;
        if state.retired { return None; }
        // Never reuse a retired kernel endpoint in the same epoch.
        if state.entries.len()>=4096 || state.entries.contains_key(&endpoint)
            || state.entries.values().any(|e|e.tuple==tuple)
        { state.retired=true;return None; }
        state.next=state.next.checked_add(1)?;
        let generation=state.next;
        state.entries.insert(endpoint,CarrierEntry {generation,pid,tuple,live:true});
        Some(CarrierLease {registry:self.clone(),endpoint,generation})
    }
    pub fn retire(&self) {
        if let Ok(mut state)=self.state.lock() { state.retired=true; }
    }
    pub fn matches_candidate(&self,event:&EndpointCandidate)->bool {
        self.state.lock().ok().is_some_and(|state|!state.retired &&
            state.entries.get(&event.endpoint).is_some_and(|entry|entry.live && entry.pid==event.pid &&
                event.outbound && event.tuple()==Some(entry.tuple) && matches!((event.layer,event.event),(2,1)|(3,4))))
    }
}

/// Offline reverse-datagram candidate for the native UDP relay.
/// No injection API accepts this as authorization. Before using it with
/// WinDivertSendEx, bind it to a live, exclusively owned flow generation,
/// committed redirect lease, current policy and proven inbound interface.
/// A sniffed packet was not diverted and must never create a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpReversePlan {
    flow: super::packet::FlowKey,
    interface: u32,
    sub_interface: u32,
}

impl UdpReversePlan {
    pub fn from_diverted_packet(address: &Address, packet: &[u8]) -> Option<Self> {
        Self::from_packet(address, packet, false)
    }

    fn from_packet(address: &Address, packet: &[u8], loopback_lab: bool) -> Option<Self> {
        use super::packet::Transport;
        use std::net::IpAddr;
        let n = address.network_inner(packet, loopback_lab).ok()?;
        let key = n.meta.flow;
        let valid = |ip: IpAddr| {
            !ip.is_unspecified() && ip.is_loopback() == loopback_lab && !ip.is_multicast()
                && match ip {
                    IpAddr::V4(v) => v.octets()[0] != 0 && v.octets()[0] < 224,
                    IpAddr::V6(v) => !v.is_unicast_link_local() && v.to_ipv4_mapped().is_none(),
                }
        };
        if !n.outbound || n.sniffed || key.transport != Transport::Udp
            || (if loopback_lab { key.source == key.destination } else { key.source.ip() == key.destination.ip() })
            || !valid(key.source.ip()) || !valid(key.destination.ip())
        { return None; }
        // Interface indices are observations only; a separate physical
        // acceptance must prove inbound delivery in the correct compartment.
        Some(Self { flow: key, interface: n.interface, sub_interface: n.sub_interface })
    }

    pub fn original_flow(&self) -> super::packet::FlowKey { self.flow }

    /// Build a complete IPv4 or IPv6 UDP response. No IP/port or interface
    /// override is accepted. IPv4 options and IPv6 extension headers are
    /// not reflected. Both families receive a full UDP checksum.
    pub fn build(&self, payload: &[u8]) -> Option<ReverseDatagram> {
        use super::packet::FlowKey;
        use std::net::IpAddr;
        if payload.len() > crate::protocol::MAX_DATAGRAM { return None; }
        let length = u16::try_from(8 + payload.len()).ok()?;
        let src = self.flow.destination;
        let dst = self.flow.source;
        let (mut packet, pseudo) = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut packet = vec![0u8; 20];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&u16::try_from(20 + usize::from(length)).ok()?.to_be_bytes());
                packet[6] = 0x40; // do not fragment
                packet[8] = 64;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&src.octets());
                packet[16..20].copy_from_slice(&dst.octets());
                let sum = checksum(word_sum(&packet));
                packet[10..12].copy_from_slice(&sum.to_be_bytes());
                let pseudo = word_sum(&src.octets()) + word_sum(&dst.octets()) + 17 + u32::from(length);
                (packet, pseudo)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut packet = vec![0u8; 40];
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&length.to_be_bytes());
                packet[6] = 17;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&src.octets());
                packet[24..40].copy_from_slice(&dst.octets());
                let pseudo = word_sum(&src.octets()) + word_sum(&dst.octets()) + 17 + u32::from(length);
                (packet, pseudo)
            }
            _ => return None,
        };
        let offset = packet.len();
        packet.extend_from_slice(&src.port().to_be_bytes());
        packet.extend_from_slice(&dst.port().to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        let sum = checksum(pseudo + word_sum(&packet[offset..]));
        packet[offset + 6..offset + 8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
        let meta = PacketMeta::parse(&packet, self.interface).ok()?;
        if meta.flow != (FlowKey { source: src, destination: dst, ..self.flow }) || meta.payload_len != payload.len() {
            return None;
        }
        Some(ReverseDatagram { packet, interface: self.interface, sub_interface: self.sub_interface })
    }
}

/// Exact TCP loopback mapping: original listener remains reserved, and
/// only the dedicated client/redirect listener pair can be translated.
/// The general native adapter must additionally prove socket ownership,
/// policy lease and route before constructing a non-loopback mapping.
#[derive(Debug, Clone, Copy)]
pub struct TcpLoopbackMap {
    client: std::net::SocketAddr,
    original: std::net::SocketAddr,
    relay: std::net::SocketAddr,
}
impl TcpLoopbackMap {
    pub fn new(client: std::net::SocketAddr, original: std::net::SocketAddr, relay: std::net::SocketAddr) -> Option<Self> {
        if !client.ip().is_loopback() || client.ip()!=original.ip() || client.ip()!=relay.ip()
            || [client.port(),original.port(),relay.port()].contains(&0)
            || client==original || client==relay || original==relay {
            return None;
        }
        Some(Self { client, original, relay })
    }

    /// Does not authorize a send. No other tuple can be rewritten.
    pub fn rewrite(&self,address:&Address, packet:&[u8]) -> Option<Vec<u8>> {
        use super::packet::Transport;
        let obs=address.network_inner(packet,true).ok()?;
        let key=obs.meta.flow;
        if obs.sniffed || !obs.outbound || key.transport!=Transport::Tcp { return None; }
        let (offset,port)=if key.source==self.client && key.destination==self.original {
            (2,self.relay.port())
        } else if key.source==self.relay && key.destination==self.client {
            (0,self.original.port())
        } else { return None; };
        // Do not transform extension/options/fragmented IP headers.
        let ip_len=if packet[0]==0x45 && packet[9]==6 { 20 }
            else if packet[0]>>4==6 && packet[6]==6 { 40 }
            else { return None; };
        let mut out=packet.to_vec();
        out[ip_len+offset..ip_len+offset+2].copy_from_slice(&port.to_be_bytes());
        let transport_len=(out.len()-ip_len) as u32;
        let pseudo=if ip_len==20 {
            out[10..12].fill(0);
            let sum=checksum(word_sum(&out[..20]));
            out[10..12].copy_from_slice(&sum.to_be_bytes());
            word_sum(&out[12..20])
        } else { word_sum(&out[8..40]) };
        out[ip_len+16..ip_len+18].fill(0);
        let sum=checksum(pseudo+6+transport_len+word_sum(&out[ip_len..]));
        out[ip_len+16..ip_len+18].copy_from_slice(&sum.to_be_bytes());
        let after=PacketMeta::parse(&out,obs.interface).ok()?;
        let (source,destination)=if offset==2 { (self.client,self.relay) } else { (self.original,self.client) };
        if after.flow.source!=source || after.flow.destination!=destination
            || after.payload_len!=obs.meta.payload_len || after.tcp_flags!=obs.meta.tcp_flags { return None; }
        Some(out)
    }
}

/// Candidate bytes only, not a live WinDivert injection token.
#[derive(Debug)]
pub struct ReverseDatagram {
    pub packet: Vec<u8>,
    pub interface: u32,
    pub sub_interface: u32,
}

fn word_sum(bytes: &[u8]) -> u32 {
    let chunks = bytes.chunks_exact(2);
    let tail = chunks.remainder().first().copied().unwrap_or(0);
    chunks.map(|w| u32::from(u16::from_be_bytes([w[0],w[1]]))).sum::<u32>() + (u32::from(tail) << 8)
}
fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn valid_pins(dll: [u8; 32], sys: [u8; 32]) -> io::Result<()> {
    if dll == [0; 32] || sys == [0; 32] || dll == sys {
        Err(io::ErrorKind::InvalidInput.into())
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod native {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::c_char,
        fs::{File, OpenOptions},
        io::Read,
        os::windows::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}},
        path::Path,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE, ERROR_IO_PENDING, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
            Threading::{CreateEventW, GetCurrentProcess, WaitForSingleObject},
        },
    };
    use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}, net::UdpSocket};
    type Recv = unsafe extern "C" fn(HANDLE, *mut u8, u32, *mut u32, u64, *mut Address, *mut u32, *mut OVERLAPPED) -> i32;
    type SendPacket = unsafe extern "C" fn(HANDLE, *const u8, u32, *mut u32, u64, *const Address, u32, *mut OVERLAPPED) -> i32;
    type Shutdown = unsafe extern "C" fn(HANDLE, u32) -> i32;
    type SetParam = unsafe extern "C" fn(HANDLE, u32, u64) -> i32;
    struct Event(HANDLE);
    impl Drop for Event { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
    impl Event {
        fn new() -> io::Result<Self> {
            let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if raw.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(raw)) }
        }
    }

    // An overlapped operation owns all buffers on this worker until
    // completion, including after cancellation. Never release a pending
    // buffer on a timeout or future drop.
    fn transfer(raw: HANDLE, cancelled: &AtomicBool, deadline: Instant,
        start: impl FnOnce(*mut OVERLAPPED, *mut u32) -> i32) -> io::Result<u32> {
        if cancelled.load(Ordering::Acquire) { return Err(io::ErrorKind::Interrupted.into()); }
        if Instant::now() >= deadline { return Err(io::ErrorKind::TimedOut.into()); }
        let event = Event::new()?;
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        operation.hEvent = event.0;
        let mut count = 0u32;
        let result = start(&mut operation, &mut count);
        if result != 0 { return Ok(count); }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) { return Err(err); }
        let failure = loop {
            if cancelled.load(Ordering::Acquire) { break io::ErrorKind::Interrupted; }
            if Instant::now() >= deadline { break io::ErrorKind::TimedOut; }
            match unsafe { WaitForSingleObject(event.0, 20) } {
                WAIT_OBJECT_0 => {
                    if unsafe { GetOverlappedResult(raw, &mut operation, &mut count, 0) } != 0 { return Ok(count); }
                    return Err(io::Error::last_os_error());
                }
                WAIT_TIMEOUT => {}
                _ => break io::ErrorKind::Other,
            }
        };
        unsafe {
            CancelIoEx(raw, &operation);
            // Even when cancellation raced with completion, this waits
            // for the original operation, not a second operation.
            GetOverlappedResult(raw, &mut operation, &mut count, 1);
        }
        Err(failure.into())
    }
    struct Api {
        open: Open,
        get: GetParam,
        close: Close,
        recv: Recv,
        send: SendPacket,
        shutdown: Shutdown,
        set: SetParam,
        _library: Library,
        _dll: File,
        _sys: File,
    }
    impl Api {
        fn open_handle(&self, filter: &std::ffi::CStr, layer: u32, flags: u64) -> io::Result<Handle> {
            self.open_priority(filter,layer,0,flags)
        }
        fn open_priority(&self,filter:&std::ffi::CStr,layer:u32,priority:i16,flags:u64)->io::Result<Handle> {
            let raw = unsafe { (self.open)(filter.as_ptr(), layer, priority, flags) };
            if raw.is_null() || raw == INVALID_HANDLE_VALUE { return Err(io::Error::last_os_error()); }
            let handle = Handle(raw, self.close);
            for param in [3,4] {
                let mut value = 0;
                if unsafe { (self.get)(handle.0,param,&mut value) } == 0 { return Err(io::Error::last_os_error()); }
                if value != 2 { return Err(io::ErrorKind::Unsupported.into()); }
            }
            Ok(handle)
        }
        fn receive(&self, handle: &Handle, cancelled: &AtomicBool, deadline: Instant) -> io::Result<(Vec<u8>, Address)> {
            let mut packet = vec![0u8; MAX_PACKET];
            let mut address = Address::from_bytes(&[0;80]);
            let mut address_len = 80;
            let count = transfer(handle.0,cancelled,deadline,|operation, count| unsafe {
                (self.recv)(handle.0,packet.as_mut_ptr(),packet.len() as u32,count,0,&mut address,&mut address_len,operation)
            })? as usize;
            if address_len != 80 || count == 0 || count > packet.len() { return Err(io::ErrorKind::InvalidData.into()); }
            packet.truncate(count);
            Ok((packet,address))
        }
        fn receive_event(&self, handle: &Handle, cancelled: &AtomicBool, deadline: Instant) -> io::Result<EndpointCandidate> {
            let mut addr=Address::from_bytes(&[0;80]);
            let mut addr_len=80;
            let count=transfer(handle.0,cancelled,deadline,|operation,count| unsafe {
                (self.recv)(handle.0,std::ptr::null_mut(),0,count,0,&mut addr,&mut addr_len,operation)
            })?;
            if count!=0 || addr_len!=80 { return Err(io::ErrorKind::InvalidData.into()); }
            addr.endpoint_candidate().ok_or_else(||io::ErrorKind::InvalidData.into())
        }
        fn send(&self, handle: &Handle, packet: &[u8], address: &Address, cancelled: &AtomicBool, deadline: Instant) -> io::Result<()> {
            let count = transfer(handle.0,cancelled,deadline,|operation,count| unsafe {
                (self.send)(handle.0,packet.as_ptr(),packet.len() as u32,count,0,address,80,operation)
            })? as usize;
            if count != packet.len() { return Err(io::ErrorKind::WriteZero.into()); }
            Ok(())
        }
        fn bounded(&self, handle: &Handle) -> io::Result<()> {
            for (param,value) in [(0,64),(1,512),(2,1024*1024)] {
                if unsafe { (self.set)(handle.0,param,value) } == 0 { return Err(io::Error::last_os_error()); }
            }
            Ok(())
        }
        fn retire(&self, handle: Handle) -> io::Result<()> {
            if unsafe { (self.shutdown)(handle.0,3) } == 0 { return Err(io::Error::last_os_error()); }
            handle.close()
        }
    }

    type Open = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> HANDLE;
    type GetParam = unsafe extern "C" fn(HANDLE, u32, *mut u64) -> i32;
    type Close = unsafe extern "C" fn(HANDLE) -> i32;
    struct Library(HMODULE);
    impl Drop for Library {
        fn drop(&mut self) { unsafe { FreeLibrary(self.0); } }
    }
    struct Handle(HANDLE, Close);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE { unsafe { (self.1)(self.0); } }
        }
    }
    impl Handle {
        fn close(mut self) -> io::Result<()> {
            let raw = std::mem::replace(&mut self.0, INVALID_HANDLE_VALUE);
            if unsafe { (self.1)(raw) } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }
    }

    fn pinned(path: &Path, expected: [u8; 32]) -> io::Result<File> {
        // The containing directory must be administrator-owned and not
        // writable by untrusted users. Deny reparse points, writers and
        // deletion on the exact DLL/SYS throughout the compatibility probe.
        let mut file = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0
            || !(4096..=16*1024*1024).contains(&metadata.len())
        { return Err(io::ErrorKind::InvalidData.into()); }
        let mut sha = Sha256::new();
        let mut buffer = [0; 16*1024];
        let mut count = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            count += n as u64;
            if count > metadata.len() { return Err(io::ErrorKind::InvalidData.into()); }
            sha.update(&buffer[..n]);
        }
        let actual: [u8;32] = sha.finalize().into();
        if count != metadata.len() || actual != expected { return Err(io::ErrorKind::PermissionDenied.into()); }
        Ok(file)
    }

    /// Explicit probe, not Connect. Default NO_INSTALL; optional lab
    /// installation permits the official DLL to request its signed driver.
    /// Verify the upstream package and signature before supplying hashes.
    /// Running driver version alone does not attest its on-disk identity.
    fn load(directory: &Path, dll: [u8;32], sys: [u8;32]) -> io::Result<Api> {
        valid_pins(dll,sys)?;
        if !directory.is_absolute() { return Err(io::ErrorKind::InvalidInput.into()); }
        let directory = directory.canonicalize()?;
        if !directory.is_dir() { return Err(io::ErrorKind::InvalidInput.into()); }
        let dll_path = directory.join("WinDivert.dll");
        let sys_path = directory.join("WinDivert64.sys");
        let _dll = pinned(&dll_path,dll)?;
        let _sys = pinned(&sys_path,sys)?;
        let mut wide: Vec<u16> = dll_path.as_os_str().encode_wide().collect();
        if wide.contains(&0) { return Err(io::ErrorKind::InvalidInput.into()); }
        wide.push(0);
        // Absolute DLL path; dependencies may only resolve from System32.
        let module = unsafe { LoadLibraryExW(wide.as_ptr(),std::ptr::null_mut(),LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() { return Err(io::Error::last_os_error()); }
        let library = Library(module);
        macro_rules! symbol {
            ($name:literal,$ty:ty) => {{
                let p = unsafe { GetProcAddress(library.0, concat!($name,"\0").as_ptr()) }.ok_or(io::ErrorKind::Unsupported)?;
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize,$ty>(p) }
            }}
        }
        Ok(Api { open: symbol!("WinDivertOpen",Open), get: symbol!("WinDivertGetParam",GetParam),
            close: symbol!("WinDivertClose",Close), recv: symbol!("WinDivertRecvEx",Recv),
            send: symbol!("WinDivertSendEx",SendPacket), shutdown: symbol!("WinDivertShutdown",Shutdown),
            set: symbol!("WinDivertSetParam",SetParam), _library:library, _dll, _sys })
    }

    pub fn probe(directory: &Path, dll: [u8;32], sys: [u8;32], install_lab: bool) -> io::Result<()> {
        let api = load(directory,dll,sys)?;
        let flags = 0x1 | 0x4 | if install_lab { 0 } else { 0x10 };
        for layer in [0,2,3] {
            api.open_handle(c"false",layer,flags)?.close()?;
        }
        Ok(())
    }

    // Laboratory only: both exact loopback endpoints are bound by this
    // worker and kept alive across the entire capture. No user-supplied
    // filter, foreign process, remote target or policy exemption.
    fn udp_lab(api: &Api, v6: bool, cancelled: &AtomicBool) -> io::Result<()> {
        use ring::rand::{SecureRandom,SystemRandom};
        let loopback = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        let client = loopback_udp(loopback)?;
        let peer = loopback_udp(loopback)?;
        let src = client.local_addr()?;
        let dst = peer.local_addr()?;
        client.connect(dst)?;
        peer.connect(src)?;
        for socket in [&client,&peer] {
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        }
        let address = if v6 { "ipv6.SrcAddr == ::1 and ipv6.DstAddr == ::1" }
            else { "ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1" };
        let filter = std::ffi::CString::new(format!(
            "outbound and loopback and !impostor and udp and ({address}) and udp.SrcPort == {} and udp.DstPort == {}",src.port(),dst.port()
        )).map_err(|_|io::ErrorKind::InvalidInput)?;
        let handle = api.open_handle(&filter,0,0x10)?;
        api.bounded(&handle)?;
        for length in [0, 33, 1200] {
            let mut nonce = vec![0;length];
            SystemRandom::new().fill(&mut nonce).map_err(|_|io::Error::other("entropy unavailable"))?;
            if cancelled.load(Ordering::Acquire) { return Err(io::ErrorKind::Interrupted.into()); }
            if client.send(&nonce)? != length { return Err(io::ErrorKind::WriteZero.into()); }
            let deadline = Instant::now() + Duration::from_secs(3);
            let (packet,addr) = api.receive(&handle,cancelled,deadline)?;
            let n = addr.network_inner(&packet,true).map_err(|_|io::ErrorKind::InvalidData)?;
            if n.sniffed || !n.outbound || n.meta.flow.source != src || n.meta.flow.destination != dst
                || n.meta.payload_len != length || !packet.ends_with(&nonce) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // First prove same-packet reinjection on the original peer.
            api.send(&handle,&packet,&addr,cancelled,deadline)?;
            let mut received = vec![0;1201];
            let size = peer.recv(&mut received)?;
            if size != length || received[..size] != nonce { return Err(io::ErrorKind::InvalidData.into()); }
            // Reply is generated from the captured tuple, not caller
            // addresses; loopback must use the outbound direction.
            let plan = UdpReversePlan::from_packet(&addr,&packet,true).ok_or(io::ErrorKind::InvalidData)?;
            let reverse = plan.build(&nonce).ok_or(io::ErrorKind::InvalidData)?;
            let mut reply = addr;
            reply.flags = (1<<17)|(1<<18)|(1<<23) | if v6 { 1<<20 } else { 1<<21 };
            api.send(&handle,&reverse.packet,&reply,cancelled,deadline)?;
            let size = client.recv(&mut received)?;
            if client.peer_addr()? != dst || size != length || received[..size] != nonce { return Err(io::ErrorKind::InvalidData.into()); }
        }
        api.retire(handle)
    }

    fn tcp_lab(api:&Api,v6:bool,cancelled:&AtomicBool) -> io::Result<()> {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        use std::net::SocketAddr;
        let loopback=if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (original,relay,client)={
            let _entered=runtime.enter();
            let bind=||->io::Result<tokio::net::TcpSocket> {
                let socket=if v6 { tokio::net::TcpSocket::new_v6()? } else { tokio::net::TcpSocket::new_v4()? };
                exclusive(&socket)?;
                socket.bind(loopback.parse::<SocketAddr>().map_err(|_|io::ErrorKind::InvalidInput)?)?;
                Ok(socket)
            };
            (bind()?.listen(4)?.into_std()?,bind()?.listen(4)?.into_std()?,bind()?)
        };
        let original_addr=original.local_addr()?;
        let relay_addr=relay.local_addr()?;
        let client_addr=client.local_addr()?;
        let mapping=TcpLoopbackMap::new(client_addr,original_addr,relay_addr).ok_or(io::ErrorKind::InvalidData)?;
        let address=if v6 { "ipv6.SrcAddr == ::1 and ipv6.DstAddr == ::1" }
            else { "ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1" };
        let filter=std::ffi::CString::new(format!(
            "outbound and loopback and !impostor and tcp and ({address}) and ((tcp.SrcPort == {} and tcp.DstPort == {}) or (tcp.SrcPort == {} and tcp.DstPort == {}))",
            client_addr.port(),original_addr.port(),relay_addr.port(),client_addr.port()
        )).map_err(|_|io::ErrorKind::InvalidInput)?;
        let handle=api.open_handle(&filter,0,0x10)?;
        api.bounded(&handle)?;
        let done=AtomicBool::new(false);
        let deadline=Instant::now()+Duration::from_secs(8);
        let result=std::thread::scope(|scope| {
            let task=scope.spawn(|| {
                struct Done<'a>(&'a AtomicBool);
                impl Drop for Done<'_> { fn drop(&mut self) { self.0.store(true,Ordering::Release); } }
                let _done=Done(&done);
                runtime.block_on(async move {
                    let relay=tokio::net::TcpListener::from_std(relay)?;
                    let (left,right)=tokio::time::timeout(Duration::from_secs(6),async {
                        tokio::try_join!(
                            async {
                                let mut stream=client.connect(original_addr).await?;
                                if stream.peer_addr()?!=original_addr { return Err(io::ErrorKind::InvalidData.into()); }
                                stream.write_all(b"theia-tcp-lab").await?;
                                let mut bytes=[0;13];
                                stream.read_exact(&mut bytes).await?;
                                if &bytes!=b"theia-tcp-lab" { return Err(io::ErrorKind::InvalidData.into()); }
                                stream.shutdown().await?;
                                let mut eof=[0;1];
                                if stream.read(&mut eof).await?!=0 { return Err(io::ErrorKind::InvalidData.into()); }
                                Ok::<(),io::Error>(())
                            },
                            async {
                                let (mut stream,peer)=relay.accept().await?;
                                if peer!=client_addr { return Err(io::ErrorKind::InvalidData.into()); }
                                let mut bytes=[0;13];
                                stream.read_exact(&mut bytes).await?;
                                stream.write_all(&bytes).await?;
                                let mut eof=[0;1];
                                if stream.read(&mut eof).await?!=0 { return Err(io::ErrorKind::InvalidData.into()); }
                                stream.shutdown().await?;
                                Ok::<(),io::Error>(())
                            }
                        )
                    }).await.map_err(|_|io::ErrorKind::TimedOut)??;
                    Ok::<(),io::Error>((left,right))
                })
            });
            let pumping=(|| -> io::Result<()> {
                let mut packets=0;
                while !done.load(Ordering::Acquire) {
                    if cancelled.load(Ordering::Acquire) || Instant::now()>=deadline || packets>=256 {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let receive_until=std::cmp::min(deadline,Instant::now()+Duration::from_millis(100));
                    match api.receive(&handle,cancelled,receive_until) {
                        Ok((packet,mut addr)) => {
                            let translated=mapping.rewrite(&addr,&packet).ok_or(io::ErrorKind::InvalidData)?;
                            addr.flags |= (1<<22) | if v6 { 0 } else { 1<<21 };
                            api.send(&handle,&translated,&addr,cancelled,deadline)?;
                            packets+=1;
                        },
                        Err(e) if e.kind()==io::ErrorKind::TimedOut=>{},
                        Err(e)=>return Err(e),
                    }
                }
                if packets==0 { return Err(io::ErrorKind::InvalidData.into()); }
                Ok(())
            })();
            let completed=task.join().map_err(|_|io::Error::other("TCP lab worker panicked"))?;
            pumping?;
            completed?;
            Ok::<(),io::Error>(())
        });
        result?;
        if !matches!(original.accept(),Err(e) if e.kind()==io::ErrorKind::WouldBlock) {
            return Err(io::Error::other("original listener received redirected connection"));
        }
        api.retire(handle)
    }

    // Read the kernel endpoint identity from the actual owned Winsock
    // socket. WinDivert 2.2.2 FLOW/SOCKET EndpointId is the transport
    // endpoint handle; it is not the raw socket descriptor or PID.
    fn socket_endpoint(socket:&impl std::os::windows::io::AsRawSocket)->io::Result<u64> {
        use windows_sys::Win32::Networking::WinSock::{WSAIoctl,WSAGetLastError,SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE};
        let mut endpoint=0u64;
        let mut returned=0u32;
        let rc=unsafe { WSAIoctl(socket.as_raw_socket() as usize,SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE,
            std::ptr::null(),0,(&mut endpoint as *mut u64).cast(),8,&mut returned,std::ptr::null_mut(),None) };
        if rc!=0 { return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() })); }
        if returned!=8 || endpoint==0 { return Err(io::ErrorKind::InvalidData.into()); }
        Ok(endpoint)
    }

    impl crate::routing::carrier_socket::Registrar for CarrierRegistry {
        fn tcp(&self,socket:&tokio::net::TcpSocket,peer:std::net::SocketAddr)->io::Result<crate::routing::carrier_socket::Lease> {
            let lease=self.register(socket_endpoint(socket)?,std::process::id(),EndpointTuple {
                local:socket.local_addr()?,remote:peer,transport:super::super::packet::Transport::Tcp
            }).ok_or(io::ErrorKind::PermissionDenied)?;
            Ok(crate::routing::carrier_socket::Lease::retain(lease))
        }
        fn udp(&self,socket:&tokio::net::UdpSocket,peer:std::net::SocketAddr)->io::Result<crate::routing::carrier_socket::Lease> {
            let lease=self.register(socket_endpoint(socket)?,std::process::id(),EndpointTuple {
                local:socket.local_addr()?,remote:peer,transport:super::super::packet::Transport::Udp
            }).ok_or(io::ErrorKind::PermissionDenied)?;
            Ok(crate::routing::carrier_socket::Lease::retain(lease))
        }
    }

    struct WinsockLease;
    impl WinsockLease {
        fn start()->io::Result<Self> {
            use windows_sys::Win32::Networking::WinSock::{WSAStartup,WSADATA};
            let mut data:WSADATA=unsafe { std::mem::zeroed() };
            let status=unsafe { WSAStartup(0x0202,&mut data) };
            if status!=0 { return Err(io::Error::from_raw_os_error(status)); }
            Ok(Self)
        }
    }
    impl Drop for WinsockLease {
        fn drop(&mut self) { unsafe { windows_sys::Win32::Networking::WinSock::WSACleanup(); } }
    }

    fn exclusive(socket:&impl std::os::windows::io::AsRawSocket)->io::Result<()> {
        use windows_sys::Win32::Networking::WinSock::{setsockopt,WSAGetLastError,SOL_SOCKET,SO_EXCLUSIVEADDRUSE};
        let on=1i32;
        let rc=unsafe { setsockopt(socket.as_raw_socket() as usize,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,
            (&on as *const i32).cast(),4) };
        if rc!=0 { return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() })); }
        Ok(())
    }
    fn bind_udp(address:std::net::SocketAddr)->io::Result<UdpSocket> {
        use std::os::windows::io::{AsRawSocket,FromRawSocket};
        use windows_sys::Win32::Networking::WinSock::{
            socket,bind,WSAGetLastError,AF_INET,AF_INET6,SOCK_DGRAM,IPPROTO_UDP,INVALID_SOCKET,SOCKADDR_INET,
        };
        let family=if address.is_ipv4(){AF_INET}else{AF_INET6};
        let raw=unsafe { socket(i32::from(family),SOCK_DGRAM,IPPROTO_UDP) };
        if raw==INVALID_SOCKET { return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() })); }
        let socket=unsafe { UdpSocket::from_raw_socket(raw as _) };
        exclusive(&socket)?;
        let mut addr:SOCKADDR_INET=unsafe { std::mem::zeroed() };
        let bytes=unsafe { std::slice::from_raw_parts_mut((&mut addr as *mut SOCKADDR_INET).cast::<u8>(),std::mem::size_of::<SOCKADDR_INET>()) };
        if bytes.len()!=28 { return Err(io::ErrorKind::InvalidData.into()); }
        bytes[..2].copy_from_slice(&family.to_ne_bytes());
        bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
        let length=match address {
            std::net::SocketAddr::V4(v4)=>{bytes[4..8].copy_from_slice(&v4.ip().octets());16},
            std::net::SocketAddr::V6(v6)=>{
                if v6.scope_id()!=0 || v6.flowinfo()!=0 { return Err(io::ErrorKind::InvalidInput.into()); }
                bytes[8..24].copy_from_slice(&v6.ip().octets());28
            }
        };
        let rc=unsafe { bind(socket.as_raw_socket() as usize,(&addr as *const SOCKADDR_INET).cast(),length) };
        if rc!=0 { return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() })); }
        Ok(socket)
    }
    fn loopback_udp(address:&str)->io::Result<UdpSocket> {
        bind_udp(address.parse().map_err(|_|io::ErrorKind::InvalidInput)?)
    }

    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel { fn drop(&mut self) { self.0.store(true,Ordering::Release); } }

    /// One explicitly authorized non-loopback echo flow, never a generic
    /// application capture or an externally supplied packet/injection key.
    pub(crate) struct RelayLab {
        pub(crate) key:super::super::packet::FlowKey,
        pub(crate) payloads:Vec<Vec<u8>>,
        reply:Option<tokio::sync::oneshot::Sender<Vec<Vec<u8>>>>,
        worker:tokio::task::JoinHandle<io::Result<()>>,
        _cancel:Cancel,
    }
    impl RelayLab {
        pub(crate) async fn finish(mut self,payloads:Vec<Vec<u8>>)->io::Result<()> {
            self.reply.take().ok_or(io::ErrorKind::BrokenPipe)?.send(payloads)
                .map_err(|_|io::ErrorKind::BrokenPipe)?;
            (&mut self.worker).await.map_err(|_|io::Error::other("WinDivert relay lab worker failed"))?
        }
    }

    pub(crate) async fn begin_udp_relay_lab(directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        target:std::net::SocketAddr)->io::Result<RelayLab> {
        use tokio::sync::oneshot;
        let cancel=Cancel(Arc::new(AtomicBool::new(false)));
        let signal=cancel.0.clone();
        let (ready_tx,ready_rx)=oneshot::channel();
        let (reply_tx,mut reply_rx)=oneshot::channel::<Vec<Vec<u8>>>();
        let mut worker=tokio::task::spawn_blocking(move || {
            use ring::rand::{SecureRandom,SystemRandom};
            if target.port()==0 || target.ip().is_loopback() || target.ip().is_unspecified() || target.ip().is_multicast()
                || matches!(target,std::net::SocketAddr::V4(v) if v.ip().octets()[0]>=224 || v.ip().octets()[0]==0)
                || matches!(target,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.flowinfo()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
            { return Err(io::ErrorKind::InvalidInput.into()); }
            let _winsock=WinsockLease::start()?;
            let api=load(&directory,dll,sys)?;
            // Read-only route observation before sending any application data.
            let scope=crate::network_scope::observe(target).ok_or(io::ErrorKind::PermissionDenied)?;
            let socket=bind_udp(scope.bind_address())?;
            let local=socket.local_addr()?;
            if !scope.matches_local(local) || local.ip()==target.ip() { return Err(io::ErrorKind::InvalidInput.into()); }
            socket.connect(target)?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            let endpoint=socket_endpoint(&socket)?;
            let field=if local.is_ipv4() {"ip"}else{"ipv6"};
            let filter=std::ffi::CString::new(format!(
                "outbound and !loopback and !impostor and udp and {field}.SrcAddr == {} and {field}.DstAddr == {} and udp.SrcPort == {} and udp.DstPort == {}",
                local.ip(),target.ip(),local.port(),target.port()
            )).map_err(|_|io::ErrorKind::InvalidInput)?;
            let guard=api.open_priority(&filter,0,-100,0x12)?;
            let capture=api.open_priority(&filter,0,100,0x10)?;
            api.bounded(&capture)?;
            let injector=api.open_priority(c"false",0,-200,0x18)?;
            let mut payloads=Vec::new();
            let mut captured=None;
            for length in [32,33,1200] {
                let mut nonce=vec![0u8;length];
                SystemRandom::new().fill(&mut nonce).map_err(|_|io::Error::other("entropy unavailable"))?;
                if signal.load(Ordering::Acquire) || crate::network_scope::observe(target)!=Some(scope) {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                if socket.send(&nonce)?!=nonce.len() { return Err(io::ErrorKind::WriteZero.into()); }
                let (packet,address)=api.receive(&capture,&signal,Instant::now()+Duration::from_secs(3))?;
                let observation=address.network(&packet).map_err(|_|io::ErrorKind::InvalidData)?;
                if observation.meta.flow.source!=local || observation.meta.flow.destination!=target
                    || observation.meta.payload_len!=nonce.len() || !packet.ends_with(&nonce)
                    || socket_endpoint(&socket)?!=endpoint {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let plan=UdpReversePlan::from_diverted_packet(&address,&packet).ok_or(io::ErrorKind::PermissionDenied)?;
                if let Some((previous,_))=captured {
                    if previous!=plan { return Err(io::ErrorKind::PermissionDenied.into()); }
                } else {
                    captured=Some((plan,address));
                }
                payloads.push(nonce);
            }
            let (plan,address)=captured.ok_or(io::ErrorKind::InvalidData)?;
            // No original packet is sent through the native interface.
            // Retain the exclusive socket and lower DROP handle while the
            // common authenticated relay processes this bounded batch.
            ready_tx.send((plan.original_flow(),payloads.clone())).map_err(|_|io::ErrorKind::BrokenPipe)?;
            let deadline=Instant::now()+Duration::from_secs(25);
            let payload=loop {
                if signal.load(Ordering::Acquire) || Instant::now()>=deadline { return Err(io::ErrorKind::Interrupted.into()); }
                match reply_rx.try_recv() {
                    Ok(bytes)=>break bytes,
                    Err(oneshot::error::TryRecvError::Empty)=>std::thread::sleep(Duration::from_millis(20)),
                    Err(oneshot::error::TryRecvError::Closed)=>return Err(io::ErrorKind::BrokenPipe.into()),
                }
            };
            let mut expected=payloads;
            if payload.len()!=expected.len() { return Err(io::ErrorKind::InvalidData.into()); }
            for bytes in payload {
                let index=expected.iter().position(|v|*v==bytes).ok_or(io::ErrorKind::PermissionDenied)?;
                expected.swap_remove(index);
                if socket_endpoint(&socket)?!=endpoint || socket.local_addr()?!=local
                    || socket.peer_addr()?!=target || crate::network_scope::observe(target)!=Some(scope) {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let reverse=plan.build(&bytes).ok_or(io::ErrorKind::InvalidData)?;
                let mut incoming=address;
                incoming.flags=(1<<23) | if target.is_ipv6(){1<<20}else{1<<21};
                api.send(&injector,&reverse.packet,&incoming,&signal,Instant::now()+Duration::from_secs(3))?;
                let mut data=[0u8;1201];
                let n=socket.recv(&mut data)?;
                if socket.peer_addr()?!=target || &data[..n]!=bytes {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            api.retire(capture)?;
            api.retire(injector)?;
            drop(socket);
            guard.close()
        });
        let (key,payloads)=match ready_rx.await {
            Ok(data)=>data,
            Err(_)=>{
                (&mut worker).await.map_err(|_|io::Error::other("WinDivert relay lab worker failed"))??;
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        };
        Ok(RelayLab { key,payloads,reply:Some(reply_tx),worker,_cancel:cancel })
    }

    fn guarded_lab(api:&Api,cancelled:&AtomicBool)->io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use std::process::{Child,Command,Stdio};
        let client=loopback_udp("127.0.0.1:0")?;
        let peer=loopback_udp("127.0.0.1:0")?;
        let src=client.local_addr()?;
        let dst=peer.local_addr()?;
        client.connect(dst)?;
        peer.connect(src)?;
        peer.set_read_timeout(Some(Duration::from_millis(450)))?;
        let endpoint=socket_endpoint(&client)?;
        let filter=std::ffi::CString::new(format!(
            "outbound and loopback and !impostor and udp and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and udp.SrcPort == {} and udp.DstPort == {}",src.port(),dst.port()
        )).map_err(|_|io::ErrorKind::InvalidInput)?;
        // Guard is opened before the higher-priority runtime capture.
        // On capture-handle closure, packets in this exact owned scope
        // hit the independent lower-priority kernel DROP handle.
        let guard=api.open_priority(&filter,0,-100,0x12)?;
        let capture=api.open_priority(&filter,0,100,0x10)?;
        api.bounded(&capture)?;
        let injector=api.open_priority(c"false",0,-200,0x18)?;
        let deadline=Instant::now()+Duration::from_secs(3);
        client.send(b"owned-carrier")?;
        let (packet,addr)=api.receive(&capture,cancelled,deadline)?;
        let observation=addr.network_inner(&packet,true).map_err(|_|io::ErrorKind::InvalidData)?;
        // This is a private loopback socket held exclusively by this
        // worker, not a generic endpoint/PID-based application exemption.
        if observation.meta.flow.source!=src || observation.meta.flow.destination!=dst
            || observation.sniffed || !observation.outbound || !packet.ends_with(b"owned-carrier")
            || socket_endpoint(&client)?!=endpoint
        { return Err(io::ErrorKind::PermissionDenied.into()); }
        api.send(&injector,&packet,&addr,cancelled,deadline)?;
        let mut bytes=[0u8;64];
        let count=peer.recv(&mut bytes)?;
        if &bytes[..count]!=b"owned-carrier" { return Err(io::ErrorKind::InvalidData.into()); }

        struct Holder(Child);
        impl Drop for Holder {
            fn drop(&mut self) { let _=self.0.kill();let _=self.0.wait(); }
        }
        // Give a separate process the capture handle and release our own
        // reference, then hard-kill that process. The guard stays in this
        // parent; no foreign process or machine-wide filter is involved.
        let mut holder=Holder(Command::new(std::env::current_exe()?)
            .args(["client","windivert","--guard-holder-lab"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
        let mut duplicate=std::ptr::null_mut();
        if unsafe { DuplicateHandle(GetCurrentProcess(),capture.0,holder.0.as_raw_handle().cast(),
            &mut duplicate,0,0,DUPLICATE_SAME_ACCESS) }==0 || duplicate.is_null() {
            return Err(io::Error::last_os_error());
        }
        capture.close()?;
        if holder.0.try_wait()?.is_some() { return Err(io::ErrorKind::BrokenPipe.into()); }
        holder.0.kill()?;
        holder.0.wait()?;
        if cancelled.load(Ordering::Acquire) { return Err(io::ErrorKind::Interrupted.into()); }
        client.send(b"must-not-leak")?;
        match peer.recv(&mut bytes) {
            Err(e) if matches!(e.kind(),io::ErrorKind::TimedOut|io::ErrorKind::WouldBlock)=>{},
            Ok(_)=>return Err(io::Error::other("guard allowed traffic after runtime handle owner died")),
            Err(e)=>return Err(e),
        }
        // Explicit Disconnect: retire the injection handle before the
        // blocking guard. Direct local delivery is permitted only now.
        api.retire(injector)?;
        guard.close()?;
        client.send(b"explicit-stop")?;
        let n=peer.recv(&mut bytes)?;
        if &bytes[..n]!=b"explicit-stop" { return Err(io::ErrorKind::InvalidData.into()); }
        Ok(())
    }

    fn socket_lab(api:&Api,cancelled:&AtomicBool) -> io::Result<()> {
        // Only capture events belonging to the current process. The
        // socket is held open until the observed connect and close.
        let pid=std::process::id();
        let receiver=loopback_udp("127.0.0.1:0")?;
        let sender=loopback_udp("127.0.0.1:0")?;
        let src=sender.local_addr()?;
        let dst=receiver.local_addr()?;
        let filter=std::ffi::CString::new(format!("processId == {pid} and protocol == 17 and localPort == {}",src.port()))
            .map_err(|_|io::ErrorKind::InvalidInput)?;
        let handle=api.open_handle(&filter,3,0x15)?;
        let flow=api.open_handle(&filter,2,0x15)?;
        api.bounded(&handle)?;
        api.bounded(&flow)?;
        let endpoint=socket_endpoint(&sender)?;
        let registry=CarrierRegistry::default();
        let tuple=EndpointTuple {local:src,remote:dst,transport:super::super::packet::Transport::Udp};
        let lease=registry.register(endpoint,pid,tuple).ok_or(io::ErrorKind::PermissionDenied)?;
        let network_filter=std::ffi::CString::new(format!(
            "outbound and loopback and !impostor and udp and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and udp.SrcPort == {} and udp.DstPort == {}",src.port(),dst.port()
        )).map_err(|_|io::ErrorKind::InvalidInput)?;
        let network=api.open_handle(&network_filter,0,0x10)?;
        api.bounded(&network)?;
        sender.connect(dst)?;
        sender.send(b"correlation-lab")?;
        let deadline=Instant::now()+Duration::from_secs(3);
        let event=api.receive_event(&handle,cancelled,deadline)?;
        if event.pid!=pid || event.layer!=3 || event.event!=4 || event.endpoint!=endpoint
            || event.tuple()!=Some(EndpointTuple { local:src,remote:dst,transport:super::super::packet::Transport::Udp }) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let established=api.receive_event(&flow,cancelled,deadline)?;
        if established.layer!=2 || established.event!=1 || established.endpoint!=endpoint
            || established.pid!=pid || established.tuple()!=event.tuple()
            || socket_endpoint(&sender)?!=endpoint { return Err(io::ErrorKind::InvalidData.into()); }
        let mut frequency=0i64;
        if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency) }==0 || frequency<=0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let max_age=frequency.checked_mul(3).ok_or(io::ErrorKind::InvalidData)?;
        let mut ledger=CandidateLedger::new(8,max_age).ok_or(io::ErrorKind::InvalidData)?;
        ledger.observe(event);
        ledger.observe(established);
        let (packet,address)=api.receive(&network,cancelled,deadline)?;
        let observed=address.network_inner(&packet,true).map_err(|_|io::ErrorKind::InvalidData)?;
        let candidate=ledger.correlate(&observed).ok_or(io::ErrorKind::PermissionDenied)?;
        if candidate!=established || !registry.matches_candidate(&candidate) || !packet.ends_with(b"correlation-lab")
            || socket_endpoint(&sender)?!=endpoint { return Err(io::ErrorKind::PermissionDenied.into()); }
        api.send(&network,&packet,&address,cancelled,deadline)?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes=[0u8;32];
        let (n,from)=receiver.recv_from(&mut bytes)?;
        if from!=src || &bytes[..n]!=b"correlation-lab" { return Err(io::ErrorKind::InvalidData.into()); }
        drop(lease);
        if registry.matches_candidate(&candidate) { return Err(io::ErrorKind::PermissionDenied.into()); }
        drop(sender);
        let closed=api.receive_event(&handle,cancelled,deadline)?;
        if closed.pid!=pid || closed.endpoint!=event.endpoint || closed.event!=7 || closed.timestamp<event.timestamp {
            return Err(io::ErrorKind::InvalidData.into());
        }
        ledger.observe(closed);
        if ledger.correlate(&observed).is_some() { return Err(io::ErrorKind::PermissionDenied.into()); }
        registry.retire();
        api.retire(network)?;
        api.retire(flow)?;
        api.retire(handle)
    }

    /// The async owner never runs driver IO on an executor thread.
    /// Dropping the future requests cancellation, and the worker retains
    /// the DLL, handles and operation buffers until completion.
    pub async fn loopback_acceptance(directory: std::path::PathBuf, dll:[u8;32], sys:[u8;32]) -> io::Result<()> {
        let cancel = Cancel(Arc::new(AtomicBool::new(false)));
        let signal = cancel.0.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _winsock=WinsockLease::start()?;
            let api=load(&directory,dll,sys)?;
            udp_lab(&api,false,&signal)?;
            udp_lab(&api,true,&signal)?;
            tcp_lab(&api,false,&signal)?;
            tcp_lab(&api,true,&signal)?;
            socket_lab(&api,&signal)?;
            guarded_lab(&api,&signal)
        }).await.map_err(|_|io::Error::other("WinDivert worker failed"))?;
        drop(cancel);
        result

    }
}
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use native::{loopback_acceptance, probe};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use native::{begin_udp_relay_lab, RelayLab};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_must_be_nonzero_and_distinct() {
        assert!(valid_pins([0;32],[1;32]).is_err());
        assert!(valid_pins([1;32],[1;32]).is_err());
        assert!(valid_pins([1;32],[2;32]).is_ok());
    }
    #[test]
    fn network_flags_are_checked_and_never_expose_pid() {
        let mut raw = [0u8;80];
        raw[..8].copy_from_slice(&1i64.to_le_bytes());
        raw[8..12].copy_from_slice(&((1u32<<17)|(1<<23)).to_le_bytes());
        raw[16..20].copy_from_slice(&7u32.to_le_bytes());
        let mut udp = [0u8;28];
        udp[0]=0x45;udp[2..4].copy_from_slice(&28u16.to_be_bytes());
        udp[9]=17;udp[12..16].copy_from_slice(&[192,0,2,1]);
        udp[16..20].copy_from_slice(&[198,51,100,2]);
        udp[20..22].copy_from_slice(&1000u16.to_be_bytes());
        udp[22..24].copy_from_slice(&443u16.to_be_bytes());
        udp[24..26].copy_from_slice(&8u16.to_be_bytes());
        let addr=Address::from_bytes(&raw);
        let n=addr.network(&udp).unwrap();
        assert_eq!(n.interface,7);
        assert!(n.outbound && n.transport_checksum_reported_valid);
        assert_eq!(n.meta.payload_len,0);
        assert!(addr.endpoint_candidate().is_none());
        for bit in [0,8,18,19,20,24] {
            let mut bad=raw;
            let f=u32::from_le_bytes(bad[8..12].try_into().unwrap())|(1<<bit);
            bad[8..12].copy_from_slice(&f.to_le_bytes());
            assert!(Address::from_bytes(&bad).network(&udp).is_err());
        }
        for i in 0..udp.len() { assert!(addr.network(&udp[..i]).is_err()); }
    }
    #[test]
    fn reverse_datagrams_preserve_original_peer_and_checksums() {
        for v6 in [false,true] {
            let mut raw = [0u8;80];
            raw[..8].copy_from_slice(&1i64.to_le_bytes());
            let flags = (1u32<<17) | if v6 { 1<<20 } else { 0 };
            raw[8..12].copy_from_slice(&flags.to_le_bytes());
            raw[16..20].copy_from_slice(&7u32.to_le_bytes());
            raw[20..24].copy_from_slice(&3u32.to_le_bytes());
            let mut request = vec![0u8; if v6 { 48 } else { 28 }];
            let off = if v6 {
                request[0]=0x60;request[4..6].copy_from_slice(&8u16.to_be_bytes());request[6]=17;
                request[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
                request[24..40].copy_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
                40
            } else {
                request[0]=0x45;request[2..4].copy_from_slice(&28u16.to_be_bytes());request[9]=17;
                request[12..16].copy_from_slice(&[192,0,2,1]);request[16..20].copy_from_slice(&[198,51,100,2]);
                20
            };
            request[off..off+2].copy_from_slice(&1000u16.to_be_bytes());
            request[off+2..off+4].copy_from_slice(&443u16.to_be_bytes());
            request[off+4..off+6].copy_from_slice(&8u16.to_be_bytes());
            let plan=UdpReversePlan::from_diverted_packet(&Address::from_bytes(&raw),&request).unwrap();
            let original=plan.original_flow();
            for payload in [vec![],vec![3],vec![4;1200],vec![5;crate::protocol::MAX_DATAGRAM]] {
                let reply=plan.build(&payload).unwrap();
                assert_eq!((reply.interface,reply.sub_interface),(7,3));
                let meta=PacketMeta::parse(&reply.packet,7).unwrap();
                assert_eq!(meta.flow.source, original.destination);
                assert_eq!(meta.flow.destination, original.source);
                assert_eq!(&reply.packet[off+8..],payload);
                let len=(8+payload.len()) as u32;
                let pseudo=if v6 { word_sum(&reply.packet[8..40]) } else {
                    assert_eq!(checksum(word_sum(&reply.packet[..20])),0);
                    word_sum(&reply.packet[12..20])
                };
                assert_eq!(checksum(pseudo+17+len+word_sum(&reply.packet[off..])),0);
                assert_ne!(&reply.packet[off+6..off+8], &[0,0]);
            }
            assert!(plan.build(&vec![0;crate::protocol::MAX_DATAGRAM+1]).is_none());
            for changed in [flags | (1<<16), flags & !(1<<17), flags | (1<<19)] {
                raw[8..12].copy_from_slice(&changed.to_le_bytes());
                assert!(UdpReversePlan::from_diverted_packet(&Address::from_bytes(&raw),&request).is_none());
            }
        }
    }

    #[test]
    fn exact_tcp_translation_and_reverse_preserve_sequence_and_options() {
        let map=TcpLoopbackMap::new("127.0.0.1:1234".parse().unwrap(),"127.0.0.1:4321".parse().unwrap(),"127.0.0.1:9876".parse().unwrap()).unwrap();
        let mut raw=[0u8;80];raw[..8].copy_from_slice(&1i64.to_le_bytes());
        raw[8..12].copy_from_slice(&((1u32<<17)|(1<<18)).to_le_bytes());
        raw[16..20].copy_from_slice(&1u32.to_le_bytes());
        let addr=Address::from_bytes(&raw);
        let mut p=vec![0u8;44];
        p[0]=0x45;p[2..4].copy_from_slice(&44u16.to_be_bytes());p[9]=6;
        p[12..16].copy_from_slice(&[127,0,0,1]);p[16..20].copy_from_slice(&[127,0,0,1]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());p[22..24].copy_from_slice(&4321u16.to_be_bytes());
        p[24..28].copy_from_slice(&99u32.to_be_bytes());p[32]=0x60;p[33]=2;
        p[40..44].copy_from_slice(&[2,4,5,180]);
        let out=map.rewrite(&addr,&p).unwrap();
        assert_eq!(&out[22..24],&9876u16.to_be_bytes());
        assert_eq!(&out[24..36],&p[24..36]);
        assert_eq!(&out[40..],&p[40..]);
        assert_eq!(checksum(word_sum(&out[..20])),0);
        assert_eq!(checksum(word_sum(&out[12..20])+6+24+word_sum(&out[20..])),0);
        assert!(map.rewrite(&addr,&out).is_none());
        p[20..22].copy_from_slice(&9876u16.to_be_bytes());p[22..24].copy_from_slice(&1234u16.to_be_bytes());
        let out=map.rewrite(&addr,&p).unwrap();
        assert_eq!(&out[20..22],&4321u16.to_be_bytes());
        assert!(TcpLoopbackMap::new("192.0.2.1:1".parse().unwrap(),"192.0.2.1:2".parse().unwrap(),"192.0.2.1:3".parse().unwrap()).is_none());
    }
    #[test]
    fn correlation_rejects_reuse_ambiguity_missing_events_and_loss() {
        use super::super::packet::{FlowKey,Transport};
        let words=|v:&str| u128::from(v.parse::<std::net::Ipv6Addr>().unwrap()).to_le_bytes();
        let event=EndpointCandidate {endpoint:4,pid:42,timestamp:100,event:4,layer:3,protocol:17,outbound:true,
            local_port:1000,remote_port:443,local_words:words("::ffff:192.0.2.1"),remote_words:words("::ffff:198.51.100.2")};
        let flow=EndpointCandidate {timestamp:105,event:1,layer:2,..event};
        let mut packet=NetworkObservation {timestamp:110,outbound:true,sniffed:false,interface:1,sub_interface:0,
            meta:PacketMeta {flow:FlowKey {source:"192.0.2.1:1000".parse().unwrap(),destination:"198.51.100.2:443".parse().unwrap(),
            transport:Transport::Udp,interface:1},payload_len:3,tcp_flags:None},transport_checksum_reported_valid:true};
        let mut ledger=CandidateLedger::new(4,20).unwrap();
        ledger.observe(flow);assert!(ledger.correlate(&packet).is_none());
        ledger.observe(event);assert_eq!(ledger.correlate(&packet),Some(flow));
        packet.timestamp=121;assert!(ledger.correlate(&packet).is_none());
        packet.timestamp=104;assert!(ledger.correlate(&packet).is_none());
        packet.timestamp=110;
        ledger.observe(EndpointCandidate {event:7,timestamp:111,..event});
        assert!(ledger.correlate(&packet).is_none());
        ledger.observe(event);ledger.observe(flow);
        assert!(ledger.correlate(&packet).is_none());
        let mut ledger=CandidateLedger::new(4,20).unwrap();
        ledger.observe(event);ledger.observe(flow);
        ledger.observe(EndpointCandidate {endpoint:5,..event});
        assert!(ledger.correlate(&packet).is_none());
        ledger.invalidate();
        ledger.observe(event);ledger.observe(flow);
        assert!(ledger.correlate(&packet).is_none());
        let mut small=CandidateLedger::new(1,20).unwrap();
        small.observe(event);small.observe(flow);small.observe(EndpointCandidate {endpoint:5,..event});
        assert!(small.correlate(&packet).is_none());
    }
    #[test]
    fn carrier_registry_is_exact_and_lease_retirement_is_terminal() {
        let local="192.0.2.1:1000".parse().unwrap();
        let remote="198.51.100.2:443".parse().unwrap();
        let tuple=EndpointTuple {local,remote,transport:super::super::packet::Transport::Udp};
        let registry=CarrierRegistry::default();
        let lease=registry.register(9,42,tuple).unwrap();
        let words=|v:&str| u128::from(v.parse::<std::net::Ipv6Addr>().unwrap()).to_le_bytes();
        let event=EndpointCandidate {endpoint:9,pid:42,timestamp:100,event:1,layer:2,protocol:17,outbound:true,
            local_port:1000,remote_port:443,local_words:words("::ffff:192.0.2.1"),remote_words:words("::ffff:198.51.100.2")};
        assert!(registry.matches_candidate(&event));
        assert!(!registry.matches_candidate(&EndpointCandidate {pid:43,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {endpoint:10,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {remote_port:444,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {event:2,..event}));
        drop(lease);
        assert!(!registry.matches_candidate(&event));
        assert!(registry.register(9,42,tuple).is_none());
        assert!(registry.register(10,42,EndpointTuple {remote:"198.51.100.2:444".parse().unwrap(),..tuple}).is_none());
        registry.retire();
    }
    #[test]
    fn flow_event_is_candidate_only_and_wrong_event_is_denied() {
        let mut raw=[0u8;80];
        raw[..8].copy_from_slice(&100i64.to_le_bytes());
        raw[8..12].copy_from_slice(&(2u32|(1<<8)|(1<<16)|(1<<17)).to_le_bytes());
        raw[16..24].copy_from_slice(&9u64.to_le_bytes());
        raw[32..36].copy_from_slice(&42u32.to_le_bytes());
        raw[68..70].copy_from_slice(&1000u16.to_le_bytes());
        raw[70..72].copy_from_slice(&443u16.to_le_bytes());
        raw[72]=17;
        let c=Address::from_bytes(&raw).endpoint_candidate().unwrap();
        assert_eq!((c.endpoint,c.pid,c.local_port,c.remote_port),(9,42,1000,443));
        assert!(Address::from_bytes(&raw).network(&[]).is_err());
        raw[9]=7;
        assert!(Address::from_bytes(&raw).endpoint_candidate().is_none());
        raw[8]=3;
        assert!(Address::from_bytes(&raw).endpoint_candidate().is_some());
        raw[32..36].fill(0);
        assert!(Address::from_bytes(&raw).endpoint_candidate().is_none());
    }
}
