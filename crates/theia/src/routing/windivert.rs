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

/// A bounded, interface-scoped capture experiment. All packets in this
/// experiment are dropped, even if a known tuple is seen. No application
/// hash, endpoint candidate, or carrier lease can authorize reinjection.
/// Counters are the only externally observable output.
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
const MAX_SCOPE_PACKETS: usize = 16_384;
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScopeCaptureStats {
    pub tcp_v4: usize,
    pub tcp_v6: usize,
    pub udp_v4: usize,
    pub udp_v6: usize,
    pub unsupported_or_malformed: usize,
    pub distinct_tuples: usize,
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
impl ScopeCaptureStats {
    pub fn observed(&self) -> usize {
        self.tcp_v4+self.tcp_v6+self.udp_v4+self.udp_v6+self.unsupported_or_malformed
    }
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
struct ScopeCaptureLedger {
    interface:u32,
    stats:ScopeCaptureStats,
    tuples:std::collections::HashSet<super::packet::FlowKey>,
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
impl ScopeCaptureLedger {
    fn new(interface:u32)->Option<Self> {
        (interface!=0).then(||Self{interface,stats:ScopeCaptureStats::default(),tuples:Default::default()})
    }
    fn observe(&mut self,address:&Address,packet:&[u8])->Result<(),ParseError> {
        use super::packet::Transport;
        if self.stats.observed()>=MAX_SCOPE_PACKETS {
            return Err(ParseError::Invalid);
        }
        // Check the ownership of the capture scope even for packets whose
        // L3/L4 format is unsupported. Inconsistent metadata ends the
        // experiment, rather than silently accepting a different scope.
        if address.timestamp<=0 || address.flags&0xffff!=0 ||
            address.flags&(1<<17)==0 || address.flags&((1<<16)|(1<<18))!=0 ||
            address.flags>>24!=0 || address.reserved!=0 ||
            u32::from_le_bytes(address.data[..4].try_into().unwrap())!=self.interface {
            return Err(ParseError::Invalid);
        }
        let observation=match address.network(packet) {
            Ok(observation)=>observation,
            Err(_)=>{
                self.stats.unsupported_or_malformed+=1;
                return Ok(());
            }
        };
        let key=observation.meta.flow;
        match (key.transport,key.source.is_ipv6()) {
            (Transport::Tcp,false)=>self.stats.tcp_v4+=1,
            (Transport::Tcp,true)=>self.stats.tcp_v6+=1,
            (Transport::Udp,false)=>self.stats.udp_v4+=1,
            (Transport::Udp,true)=>self.stats.udp_v6+=1,
        }
        // The entire capture epoch is bounded. Never reuse a tuple as
        // socket identity, never retain payload, never emit target data.
        self.tuples.insert(key);
        self.stats.distinct_tuples=self.tuples.len();
        Ok(())
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
        if history.terminal {
            // A recycled endpoint can now describe a different tuple. Do
            // not silently ignore the new owner and trust another candidate.
            if matches!((event.layer,event.event),(2,1)|(3,4)) {
                self.invalidate();
            }
            return;
        }
        if matches!((event.layer,event.event),(2,2)|(3,7)) {
            history.closed_tuple=event.tuple();
            let conflicts=[history.connect,history.flow].into_iter().flatten().any(|previous| {
                previous.pid!=event.pid || previous.timestamp>event.timestamp ||
                    history.closed_tuple.is_some_and(|tuple|previous.tuple()!=Some(tuple))
            });
            if conflicts || (history.closed_tuple.is_none() && history.connect.is_none() && history.flow.is_none()) {
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
        self.correlate_pair(packet).map(|(_,flow)|flow)
    }
    fn correlate_pair(&self,packet:&NetworkObservation)->Option<(EndpointCandidate,EndpointCandidate)> {
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
            matched=Some((a,b));
        }
        matched
    }
}

/// Capture-time diagnostic only. Even a unique live endpoint candidate
/// does not attach that endpoint to the NETWORK packet. This enum has no
/// Known application or carrier-authorization variant.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum CaptureAttribution {
    Unknown,
    CorrelatedEndpoint,
}
impl CaptureAttribution {
    pub fn application_evidence(self)->super::Evidence<super::ApplicationId> {
        // Do not infer the sender or loaded executable from correlation.
        super::Evidence::Unknown
    }
}

#[cfg(any(test,all(target_os="windows",target_arch="x86_64")))]
struct CaptureCorrelation {
    ledger:CandidateLedger,
    start:i64,
    correlated:usize,
    unknown:usize,
}
#[cfg(any(test,all(target_os="windows",target_arch="x86_64")))]
impl CaptureCorrelation {
    fn new(start:i64,max_age:i64)->Option<Self> {
        if start<=0 {return None;}
        Some(Self{ledger:CandidateLedger::new(4096,max_age)?,start,correlated:0,unknown:0})
    }
    fn observe(&mut self,event:EndpointCandidate) {
        if event.timestamp>=self.start {self.ledger.observe(event);}
    }
    fn invalidate(&mut self) {self.ledger.invalidate();}
    fn classify(&mut self,packet:&NetworkObservation)->CaptureAttribution {
        if packet.timestamp>=self.start && self.ledger.correlate(packet).is_some() {
            self.correlated+=1;
            CaptureAttribution::CorrelatedEndpoint
        } else {
            self.unknown+=1;
            CaptureAttribution::Unknown
        }
    }
}

#[cfg(all(target_os="windows",target_arch="x86_64"))]
pub(crate) enum RelayScope {
    Targets(Vec<std::net::SocketAddr>),
    /// No destination or PID exemptions inside the captured interface.
    /// The separately reviewed carrier interface is OUTSIDE this lab.
    Interface{capture:u32,carrier:u32},
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
    lab_blocked_ips:Vec<std::net::IpAddr>,
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    lab_interfaces:Option<(u32,u32)>,
}
#[derive(Clone,Copy)]
struct CarrierEntry {
    generation:u64,
    pid:u32,
    tuple:EndpointTuple,
    registered_at:i64,
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
    #[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn for_redirect_lab(targets:&[std::net::SocketAddr])->Option<Self> {
        if !validate_redirect_lab_targets(targets) { return None; }
        Some(Self {state:std::sync::Arc::new(std::sync::Mutex::new(CarrierState {
            lab_blocked_ips:targets.iter().map(|t|t.ip()).collect(),
            ..CarrierState::default()
        }))})
    }
    fn register(&self,endpoint:u64,pid:u32,tuple:EndpointTuple,registered_at:i64)->Option<CarrierLease> {
        if registered_at<=0 || endpoint==0 || pid==0 || tuple.local.port()==0 || tuple.remote.port()==0
            || tuple.local.ip().is_unspecified() || tuple.remote.ip().is_unspecified()
            || tuple.local.ip().is_multicast() || tuple.remote.ip().is_multicast()
            || tuple.local.is_ipv4()!=tuple.remote.is_ipv4() || tuple.local==tuple.remote
            || matches!(tuple.local,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
            || matches!(tuple.remote,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
        { return None; }
        let mut state=self.state.lock().ok()?;
        if state.retired || state.lab_blocked_ips.contains(&tuple.remote.ip()) { return None; }
        // Never reuse a retired kernel endpoint in the same epoch.
        if state.entries.len()>=4096 || state.entries.contains_key(&endpoint)
            || state.entries.values().any(|e|e.tuple==tuple)
        { state.retired=true;return None; }
        state.next=state.next.checked_add(1)?;
        let generation=state.next;
        state.entries.insert(endpoint,CarrierEntry {generation,pid,tuple,registered_at,live:true});
        Some(CarrierLease {registry:self.clone(),endpoint,generation})
    }
    pub fn retire(&self) {
        if let Ok(mut state)=self.state.lock() { state.retired=true; }
    }
    fn matches_event(entry:&CarrierEntry,event:&EndpointCandidate)->bool {
        entry.live && entry.pid==event.pid && event.timestamp>=entry.registered_at &&
            event.outbound && event.tuple()==Some(entry.tuple) &&
            matches!((event.layer,event.event),(2,1)|(3,4))
    }
    /// A single event is useful for diagnostic tests only. It must not
    /// be used as a NETWORK packet exemption.
    #[cfg(test)]
    fn matches_candidate(&self,event:&EndpointCandidate)->bool {
        self.state.lock().ok().is_some_and(|state|!state.retired &&
            state.entries.get(&event.endpoint).is_some_and(|entry|Self::matches_event(entry,event)))
    }
    /// Both event layers must agree with the live registration, and
    /// neither event may predate registration in the same QPC clock.
    /// This still cannot attest packet ownership or authorize a permit.
    pub fn matches_packet_candidate(&self,ledger:&CandidateLedger,packet:&NetworkObservation)->bool {
        let Some((connect,flow))=ledger.correlate_pair(packet) else { return false; };
        self.state.lock().ok().is_some_and(|state|!state.retired &&
            state.entries.get(&flow.endpoint).is_some_and(|entry|
                Self::matches_event(entry,&connect) && Self::matches_event(entry,&flow)))
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

/// An epoch-bound reverse capability, not a proof of socket ownership.
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
pub(crate) struct ScopeUdpFlow {
    plan:UdpReversePlan,
    address:Address,
    retired:std::sync::atomic::AtomicBool,
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
impl ScopeUdpFlow {
    pub(crate) fn key(&self)->super::packet::FlowKey { self.plan.original_flow() }
    pub(crate) fn live(&self)->bool { !self.retired.load(std::sync::atomic::Ordering::Acquire) }
    pub(crate) fn close(&self) { self.retired.store(true,std::sync::atomic::Ordering::Release); }
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
struct ScopeUdpLedger {
    flows:std::collections::HashMap<super::packet::FlowKey,std::sync::Arc<ScopeUdpFlow>>,
    max_live:usize,
    max_epoch:usize,
    retired:bool,
}
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
impl ScopeUdpLedger {
    fn new(max_live:usize,max_epoch:usize)->Option<Self> {
        if !(1..=64).contains(&max_live) || max_epoch<max_live || max_epoch>4096 { return None; }
        Some(Self {flows:Default::default(),max_live,max_epoch,retired:false})
    }
    fn observe(&mut self,plan:UdpReversePlan,address:Address)->Option<(std::sync::Arc<ScopeUdpFlow>,bool)> {
        use std::sync::{Arc,atomic::AtomicBool};
        if self.retired { return None; }
        let key=plan.original_flow();
        if let Some(current)=self.flows.get(&key) {
            if !current.live() || current.plan!=plan || address.timestamp<current.address.timestamp {
                return None;
            }
            return Some((current.clone(),false));
        }
        if self.flows.len()>=self.max_epoch ||
            self.flows.values().filter(|flow|flow.live()).count()>=self.max_live { return None; }
        let flow=Arc::new(ScopeUdpFlow{plan,address,retired:AtomicBool::new(false)});
        self.flows.insert(key,flow.clone());
        Some((flow,true))
    }
    fn owns(&self,flow:&std::sync::Arc<ScopeUdpFlow>)->bool {
        !self.retired && flow.live() &&
            self.flows.get(&flow.key()).is_some_and(|current|std::sync::Arc::ptr_eq(current,flow))
    }
    fn retire(&mut self) {
        self.retired=true;
        for flow in self.flows.values() { flow.close(); }
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

/// Non-loopback TCP reflection candidate. Windows sees the diverted
/// original SYN as an inbound connection from the remote address to a
/// dedicated local listener. The return path is reflected back to the
/// original client socket. This is intentionally separate from admission:
/// the live backend must prove the listener, original endpoint, route,
/// capture ownership and policy before any injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRedirectToken {
    generation: u64,
    original: super::packet::FlowKey,
}
impl TcpRedirectToken {
    pub fn original(self) -> super::packet::FlowKey { self.original }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpReflectionState {
    Syn,
    SynAck(u32),
    Accepted(u32),
    Retired,
}
struct TcpReflection {
    token: TcpRedirectToken,
    listener: std::net::SocketAddr,
    sub_interface: u32,
    first_timestamp: i64,
    initial_seq: u32,
    state: TcpReflectionState,
}
pub struct TcpRedirectTable {
    entries: std::collections::HashMap<super::packet::FlowKey,TcpReflection>,
    max_live: usize,
    max_epoch: usize,
    generation: u64,
    retired: bool,
}
impl TcpRedirectTable {
    pub fn new(max_live:usize,max_epoch:usize)->Option<Self> {
        if !(1..=64).contains(&max_live) || max_epoch<max_live || max_epoch>4096 { return None; }
        Some(Self { entries:std::collections::HashMap::new(),max_live,max_epoch,generation:0,retired:false })
    }
    pub fn retire(&mut self) { self.retired=true; }
    /// Reserve a distinct, already-bound local listener for this exact
    /// SYN. No reuse within an epoch, even after FIN/RST/task completion.
    /// TCP Fast Open/early data is denied until independently accepted.
    pub fn begin(&mut self,address:&Address,packet:&[u8],listener:std::net::SocketAddr)->Option<TcpRedirectToken> {
        use super::packet::Transport;
        if self.retired { return None; }
        let obs=address.network(packet).ok()?;
        let key=obs.meta.flow;
        let (seq,_,off)=tcp_numbers(packet)?;
        let flags=obs.meta.tcp_flags?;
        if !obs.outbound || obs.sniffed || key.transport!=Transport::Tcp
            || flags & !0xc0 != 2 || obs.meta.payload_len!=0 || off==0
            || listener.port()==0 || listener.ip()!=key.source.ip()
            || listener==key.source || key.source.ip()==key.destination.ip()
            || !reflect_address(key.source) || !reflect_address(key.destination) { return None; }
        let peer=std::net::SocketAddr::new(key.destination.ip(),key.source.port());
        if self.entries.contains_key(&key)
            || self.entries.values().any(|e| {
                let old=e.token.original;
                let old_peer=std::net::SocketAddr::new(old.destination.ip(),old.source.port());
                // Both directions must remain unambiguous, including
                // retired mappings for the duration of this capture epoch.
                e.listener==listener || (old.interface==key.interface &&
                    ((old.source==listener && old.destination==peer) ||
                     (e.listener==key.source && old_peer==key.destination)))
            })
            || self.entries.len()>=self.max_epoch
            || self.entries.values().filter(|e|e.state!=TcpReflectionState::Retired).count()>=self.max_live { return None; }
        self.generation=self.generation.checked_add(1)?;
        let token=TcpRedirectToken {generation:self.generation,original:key};
        self.entries.insert(key,TcpReflection {token,listener,sub_interface:obs.sub_interface,
            first_timestamp:obs.timestamp,initial_seq:seq,state:TcpReflectionState::Syn});
        Some(token)
    }
    /// The accept operation must be performed on the reserved listener,
    /// not an unrelated stream or a client-supplied target header.
    pub fn accept(&mut self,token:TcpRedirectToken,local:std::net::SocketAddr,peer:std::net::SocketAddr)->bool {
        if self.retired { return false; }
        let Some(entry)=self.entries.get_mut(&token.original) else { return false; };
        let expected_peer=std::net::SocketAddr::new(token.original.destination.ip(),token.original.source.port());
        if entry.token!=token || entry.listener!=local || peer!=expected_peer { return false; }
        let TcpReflectionState::SynAck(seq)=entry.state else { return false; };
        entry.state=TcpReflectionState::Accepted(seq);
        true
    }
    /// Derive the token from an actual accept on a reserved listener.
    /// The caller must own the listener and verify the accepted socket.
    pub fn accept_captured(&mut self,local:std::net::SocketAddr,peer:std::net::SocketAddr)->Option<TcpRedirectToken> {
        let token={
            let mut candidates=self.entries.values().filter(|entry| {
                let key=entry.token.original;
                entry.listener==local && std::net::SocketAddr::new(key.destination.ip(),key.source.port())==peer
            }).map(|entry|entry.token);
            let token=candidates.next()?;
            if candidates.next().is_some() { return None; }
            token
        };
        self.accept(token,local,peer).then_some(token)
    }
    pub fn complete(&mut self,token:TcpRedirectToken)->bool {
        let Some(entry)=self.entries.get_mut(&token.original) else { return false; };
        if entry.token!=token || entry.state==TcpReflectionState::Retired { return false; }
        entry.state=TcpReflectionState::Retired;
        true
    }
    /// Resolve the captured outbound tuple, including the dedicated relay
    /// direction, without accepting a caller-supplied generation. This
    /// is demultiplexing only, not a proof of socket ownership.
    pub fn lookup(&self,address:&Address,packet:&[u8])->Option<TcpRedirectToken> {
        if self.retired { return None; }
        let obs=address.network(packet).ok()?;
        if obs.sniffed || !obs.outbound { return None; }
        let mut found=None;
        for entry in self.entries.values() {
            let key=entry.token.original;
            let peer=std::net::SocketAddr::new(key.destination.ip(),key.source.port());
            if obs.interface!=key.interface || obs.meta.flow.transport!=key.transport ||
                !(obs.meta.flow==key ||
                    (obs.meta.flow.source==entry.listener && obs.meta.flow.destination==peer)) { continue; }
            if found.is_some() || entry.state==TcpReflectionState::Retired ||
                obs.sub_interface!=entry.sub_interface || obs.timestamp<entry.first_timestamp { return None; }
            found=Some(entry.token);
        }
        found
    }
    /// Produces an inbound packet candidate for the exact generation;
    /// does not transmit or authorize a packet. The TCP stack remains
    /// responsible for sequence/window validation after the handshake.
    pub fn reflect(&mut self,token:TcpRedirectToken,address:&Address,packet:&[u8])->Option<ReverseDatagram> {
        if self.lookup(address,packet)!=Some(token) { return None; }
        let obs=address.network(packet).ok()?;
        let entry=self.entries.get_mut(&token.original)?;
        let key=token.original;
        if entry.token!=token || entry.state==TcpReflectionState::Retired || obs.sniffed || !obs.outbound
            || obs.interface!=key.interface || obs.sub_interface!=entry.sub_interface
            || obs.timestamp<entry.first_timestamp || obs.meta.flow.transport!=key.transport { return None; }
        let peer=std::net::SocketAddr::new(key.destination.ip(),key.source.port());
        let client=obs.meta.flow==key;
        let relay=obs.meta.flow.source==entry.listener && obs.meta.flow.destination==peer;
        if !client && !relay { return None; }
        let (seq,ack,off)=tcp_numbers(packet)?;
        let flags=obs.meta.tcp_flags?;
        if flags & 2 !=0 {
            if obs.meta.payload_len!=0 { return None; }
            if client {
                if flags & !0xc0!=2 || seq!=entry.initial_seq || matches!(entry.state,TcpReflectionState::Accepted(_)) { return None; }
            } else {
                if flags & !0xc0!=0x12 || ack!=entry.initial_seq.wrapping_add(1) { return None; }
                match entry.state {
                    TcpReflectionState::Syn=>entry.state=TcpReflectionState::SynAck(seq),
                    TcpReflectionState::SynAck(previous) if previous==seq=>{},
                    _=>return None,
                }
            }
        } else {
            // Do not reflect unsolicited data before the SYN/SYN-ACK pair.
            // A final handshake ACK or its attached data is delivered only
            // to the reserved local listener, never to the remote network.
            match entry.state {
                TcpReflectionState::Syn if flags&4==0=>return None,
                TcpReflectionState::SynAck(server) if client && flags&4==0 &&
                    (flags&16==0 || ack!=server.wrapping_add(1) || seq!=entry.initial_seq.wrapping_add(1))=>return None,
                TcpReflectionState::SynAck(_) if relay && flags&4==0=>return None,
                _=>{},
            }
        }
        let (source,destination)=if client { (peer,entry.listener) } else { (key.destination,key.source) };
        let mut out=packet.to_vec();
        match (source.ip(),destination.ip()) {
            (std::net::IpAddr::V4(a),std::net::IpAddr::V4(b)) if off==20=>{
                out[12..16].copy_from_slice(&a.octets());
                out[16..20].copy_from_slice(&b.octets());
                out[10..12].fill(0);
                let sum=checksum(word_sum(&out[..20]));
                out[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (std::net::IpAddr::V6(a),std::net::IpAddr::V6(b)) if off==40=>{
                out[8..24].copy_from_slice(&a.octets());
                out[24..40].copy_from_slice(&b.octets());
            }
            _=>return None,
        }
        out[off..off+2].copy_from_slice(&source.port().to_be_bytes());
        out[off+2..off+4].copy_from_slice(&destination.port().to_be_bytes());
        out[off+16..off+18].fill(0);
        let pseudo=if off==20 {word_sum(&out[12..20])}else{word_sum(&out[8..40])};
        let sum=checksum(pseudo+6+(out.len()-off) as u32+word_sum(&out[off..]));
        out[off+16..off+18].copy_from_slice(&sum.to_be_bytes());
        let after=PacketMeta::parse(&out,key.interface).ok()?;
        if after.flow.source!=source || after.flow.destination!=destination || after.tcp_flags!=obs.meta.tcp_flags
            || after.payload_len!=obs.meta.payload_len { return None; }
        if flags&4!=0 { entry.state=TcpReflectionState::Retired; }
        Some(ReverseDatagram {packet:out,interface:key.interface,sub_interface:entry.sub_interface})
    }
}
/// Explicit isolated fixture destinations. Never use a caller-supplied
/// filter expression, hostname, wildcard or broad carrier permit.
pub(crate) fn validate_redirect_lab_targets(targets:&[std::net::SocketAddr])->bool {
    !targets.is_empty() && targets.len()<=8 &&
        targets.iter().all(|target|reflect_address(*target)) &&
        targets.iter().enumerate().all(|(i,target)|!targets[..i].contains(target))
}
fn reflect_address(address:std::net::SocketAddr)->bool {
    let ip=address.ip();
    address.port()!=0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()
        && match address {
            std::net::SocketAddr::V4(v)=>v.ip().octets()[0]>0 && v.ip().octets()[0]<224,
            std::net::SocketAddr::V6(v)=>v.scope_id()==0 && v.flowinfo()==0 &&
                v.ip().to_ipv4_mapped().is_none() && !v.ip().is_unicast_link_local(),
        }
}
fn tcp_numbers(packet:&[u8])->Option<(u32,u32,usize)> {
    let off=match packet.first().copied()? {
        0x45 if *packet.get(9)?==6=>20,
        v if v>>4==6 && *packet.get(6)?==6=>40,
        _=>return None,
    };
    Some((u32::from_be_bytes(packet.get(off+4..off+8)?.try_into().ok()?),
        u32::from_be_bytes(packet.get(off+8..off+12)?.try_into().ok()?),off))
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

    fn registration_timestamp()->io::Result<i64> {
        let mut ticks=0i64;
        if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut ticks) }==0 || ticks<=0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(ticks)
    }

    impl CarrierRegistry {
        pub(crate) fn for_interface_lab(capture:u32,carrier:u32)->io::Result<Self> {
            if capture==carrier {return Err(io::ErrorKind::InvalidInput.into());}
            interface_identity(capture)?;
            interface_identity(carrier)?;
            Ok(Self{state:Arc::new(Mutex::new(CarrierState {
                lab_interfaces:Some((capture,carrier)),..CarrierState::default()
            }))})
        }
        fn pin_lab_carrier(&self,socket:&impl std::os::windows::io::AsRawSocket,
            local:std::net::SocketAddr,peer:std::net::SocketAddr)->io::Result<()> {
            let pair=self.state.lock().map_err(|_|io::ErrorKind::PermissionDenied)?.lab_interfaces;
            let Some((capture,carrier))=pair else {return Ok(());};
            interface_identity(capture)?;
            interface_identity(carrier)?;
            let (source,index)=crate::local_proxy::windows_route_binding(peer).ok_or(io::ErrorKind::PermissionDenied)?;
            if index!=carrier || source.ip()!=local.ip() {return Err(io::ErrorKind::PermissionDenied.into());}
            // IP_UNICAST_IF uses network order for IPv4, host order for
            // IPv6. Pin the actual socket before its first connect/send.
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{setsockopt,getsockopt,WSAGetLastError,IPPROTO_IP,IPPROTO_IPV6};
            let level=if local.is_ipv4(){IPPROTO_IP}else{IPPROTO_IPV6};
            let value=if local.is_ipv4(){carrier.to_be()}else{carrier};
            let raw=socket.as_raw_socket() as usize;
            if unsafe{setsockopt(raw,level,31,(&value as *const u32).cast(),4)}!=0 {
                return Err(io::Error::from_raw_os_error(unsafe{WSAGetLastError()}));
            }
            let mut observed=0u32;
            let mut len=4i32;
            if unsafe{getsockopt(raw,level,31,(&mut observed as *mut u32).cast(),&mut len)}!=0 ||
                len!=4 || observed!=value {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if crate::local_proxy::windows_route_binding(peer)!=Some((source,index)) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(())
        }
    }
    impl crate::routing::carrier_socket::Registrar for CarrierRegistry {
        fn tcp(&self,socket:&tokio::net::TcpSocket,peer:std::net::SocketAddr)->io::Result<crate::routing::carrier_socket::Lease> {
            verify_carrier_socket(socket)?;
            self.pin_lab_carrier(socket,socket.local_addr()?,peer)?;
            let lease=self.register(socket_endpoint(socket)?,std::process::id(),EndpointTuple {
                local:socket.local_addr()?,remote:peer,transport:super::super::packet::Transport::Tcp
            },registration_timestamp()?).ok_or(io::ErrorKind::PermissionDenied)?;
            Ok(crate::routing::carrier_socket::Lease::retain(lease))
        }
        fn udp(&self,socket:&tokio::net::UdpSocket,peer:std::net::SocketAddr)->io::Result<crate::routing::carrier_socket::Lease> {
            verify_carrier_socket(socket)?;
            self.pin_lab_carrier(socket,socket.local_addr()?,peer)?;
            let lease=self.register(socket_endpoint(socket)?,std::process::id(),EndpointTuple {
                local:socket.local_addr()?,remote:peer,transport:super::super::packet::Transport::Udp
            },registration_timestamp()?).ok_or(io::ErrorKind::PermissionDenied)?;
            Ok(crate::routing::carrier_socket::Lease::retain(lease))
        }
        fn retire(&self)->io::Result<()> {
            let mut state=self.state.lock().map_err(|_|io::ErrorKind::PermissionDenied)?;
            state.retired=true;
            for entry in state.entries.values_mut() { entry.live=false; }
            Ok(())
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
    fn verify_carrier_socket(socket:&impl std::os::windows::io::AsRawSocket)->io::Result<()> {
        use windows_sys::Win32::{
            Foundation::{GetHandleInformation,HANDLE_FLAG_INHERIT,HANDLE},
            Networking::WinSock::{getsockopt,WSAGetLastError,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,SO_REUSEADDR},
        };
        let raw=socket.as_raw_socket() as usize;
        let mut flags=0u32;
        if unsafe {GetHandleInformation(raw as HANDLE,&mut flags)}==0 {
            return Err(io::Error::last_os_error());
        }
        if flags&HANDLE_FLAG_INHERIT!=0 {return Err(io::ErrorKind::PermissionDenied.into());}
        let option=|name:i32|->io::Result<i32>{
            let mut value=0i32;
            let mut len=4i32;
            if unsafe {getsockopt(raw,SOL_SOCKET,name,(&mut value as *mut i32).cast(),&mut len)}!=0 {
                return Err(io::Error::from_raw_os_error(unsafe {WSAGetLastError()}));
            }
            if len!=4 {return Err(io::ErrorKind::InvalidData.into());}
            Ok(value)
        };
        if option(SO_EXCLUSIVEADDRUSE)?==0 || option(SO_REUSEADDR)?!=0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    pub(crate) fn prepare_carrier_tcp(socket:&tokio::net::TcpSocket)->io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Foundation::{SetHandleInformation,HANDLE_FLAG_INHERIT,HANDLE};
        if unsafe {SetHandleInformation(socket.as_raw_socket() as usize as HANDLE,HANDLE_FLAG_INHERIT,0)}==0 {
            return Err(io::Error::last_os_error());
        }
        exclusive(socket)?;
        verify_carrier_socket(socket)
    }
    pub(crate) fn bind_carrier_udp(address:std::net::SocketAddr)->io::Result<tokio::net::UdpSocket> {
        // The socket must remain valid beyond this call. Hold one
        // process-lifetime WSAStartup reference (OS releases it at exit).
        static WINSOCK:std::sync::OnceLock<Result<WinsockLease,i32>>=std::sync::OnceLock::new();
        if let Err(code)=WINSOCK.get_or_init(||WinsockLease::start().map_err(|e|e.raw_os_error().unwrap_or(1))) {
            return Err(io::Error::from_raw_os_error(*code));
        }
        let socket=bind_udp(address)?;
        verify_carrier_socket(&socket)?;
        socket.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(socket)
    }
    fn bind_udp(address:std::net::SocketAddr)->io::Result<UdpSocket> {
        use std::os::windows::io::{AsRawSocket,FromRawSocket};
        use windows_sys::Win32::Networking::WinSock::{
            WSASocketW,bind,WSAGetLastError,AF_INET,AF_INET6,SOCK_DGRAM,IPPROTO_UDP,INVALID_SOCKET,SOCKADDR_INET,
            WSA_FLAG_OVERLAPPED,WSA_FLAG_NO_HANDLE_INHERIT,
        };
        let family=if address.is_ipv4(){AF_INET}else{AF_INET6};
        let raw=unsafe { WSASocketW(i32::from(family),SOCK_DGRAM,IPPROTO_UDP,std::ptr::null(),0,
            WSA_FLAG_OVERLAPPED|WSA_FLAG_NO_HANDLE_INHERIT) };
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


    // Common capture adapter for EXTERNAL applications on explicit lab
    // destinations. The packet worker never opens a remote socket, trusts
    // a PID, or passes an original packet. All routing remains in NativeIngress.
    use std::{net::SocketAddr, sync::Mutex};
    use tokio::sync::{mpsc,oneshot};
    use super::super::packet::{FlowKey,Transport};

    pub(crate) struct ScopeTcp {
        token:TcpRedirectToken,
        listener:tokio::net::TcpListener,
        table:Arc<Mutex<TcpRedirectTable>>,
    }
    impl ScopeTcp {
        pub(crate) async fn accept(&self)->io::Result<(FlowKey,tokio::net::TcpStream)> {
            let (stream,peer)=tokio::time::timeout(Duration::from_secs(8),self.listener.accept()).await
                .map_err(|_|io::ErrorKind::TimedOut)??;
            if stream.peer_addr()?!=peer ||
                !self.table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?
                    .accept(self.token,stream.local_addr()?,peer) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok((self.token.original(),stream))
        }
    }
    impl Drop for ScopeTcp {
        fn drop(&mut self) {
            if let Ok(mut table)=self.table.lock() { table.complete(self.token); }
        }
    }

    pub(crate) struct ScopeUdpPacket {
        pub(crate) flow:Arc<ScopeUdpFlow>,
        pub(crate) payload:Vec<u8>,
    }
    pub(crate) enum ScopeRelayEvent {
        Tcp(ScopeTcp),
        Udp(ScopeUdpPacket),
    }
    struct ScopeReply {
        flow:Arc<ScopeUdpFlow>,
        payload:Vec<u8>,
        sent:oneshot::Sender<io::Result<()>>,
    }
    #[derive(Clone)]
    pub(crate) struct ScopeReplies(mpsc::Sender<ScopeReply>);
    impl ScopeReplies {
        pub(crate) async fn send(&self,flow:Arc<ScopeUdpFlow>,payload:Vec<u8>)->io::Result<()> {
            if !flow.live() || payload.len()>crate::protocol::MAX_DATAGRAM {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let (sent,ack)=oneshot::channel();
            self.0.send(ScopeReply{flow,payload,sent}).await.map_err(|_|io::ErrorKind::BrokenPipe)?;
            ack.await.map_err(|_|io::ErrorKind::BrokenPipe)?
        }
    }
    pub(crate) struct ScopeRelayLab {
        pub(crate) events:mpsc::Receiver<ScopeRelayEvent>,
        pub(crate) replies:ScopeReplies,
        pub(crate) ended:oneshot::Receiver<()>,
        worker:tokio::task::JoinHandle<io::Result<()>>,
        cancel:Cancel,
    }
    impl ScopeRelayLab {
        pub(crate) async fn finish(mut self)->io::Result<()> {
            self.cancel.0.store(true,Ordering::Release);
            (&mut self.worker).await.map_err(|_|io::Error::other("WinDivert capture worker failed"))?
        }
    }

    fn destination_filter(targets:&[SocketAddr],source:bool)->io::Result<String> {
        if !validate_redirect_lab_targets(targets) { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut terms=Vec::new();
        for target in targets {
            let layer=if target.is_ipv4() {"ip"} else {"ipv6"};
            let field=if source {"SrcAddr"} else {"DstAddr"};
            let term=format!("{layer}.{field} == {}",target.ip());
            if !terms.contains(&term) { terms.push(term); }
        }
        Ok(terms.join(" or "))
    }

    #[derive(Clone,Copy,PartialEq,Eq)]
    struct RedirectRoute {
        scope:crate::network_scope::Scope,
        interface:u32,
        identity:(u64,u32,u16,u16,[u8;8]),
    }
    impl RedirectRoute {
        fn observe(target:SocketAddr)->io::Result<Self> {
            let denied=||io::Error::from(io::ErrorKind::PermissionDenied);
            let scope=crate::network_scope::observe(target).ok_or_else(denied)?;
            let (source,interface)=crate::local_proxy::windows_route_binding(target).ok_or_else(denied)?;
            if source.ip()==target.ip() || !scope.matches_local(source) { return Err(denied()); }
            let identity=interface_identity(interface)?;
            if crate::network_scope::observe(target)!=Some(scope) { return Err(denied()); }
            Ok(Self{scope,interface,identity})
        }
        fn matches(&self,key:FlowKey)->bool {
            key.interface==self.interface && self.scope.matches_local(key.source)
        }
    }


    // These private observers are opened before NETWORK capture and live
    // for the same bounded lab epoch. No flow is ever passed or assigned
    // an application hash because an event happened to match its tuple.
    struct LiveCaptureObservers {
        stop:Arc<AtomicBool>,
        lost:Arc<AtomicBool>,
        receiver:std::sync::mpsc::Receiver<EndpointCandidate>,
        workers:Vec<std::thread::JoinHandle<()>>,
        correlation:CaptureCorrelation,
    }
    impl LiveCaptureObservers {
        fn start(directory:&std::path::Path,dll:[u8;32],sys:[u8;32])->io::Result<Self> {
            use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;
            let mut frequency=0i64;
            if unsafe {QueryPerformanceFrequency(&mut frequency)}==0 || frequency<=0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let start=registration_timestamp()?;
            let max_age=frequency.checked_mul(2).ok_or(io::ErrorKind::InvalidData)?;
            let correlation=CaptureCorrelation::new(start,max_age).ok_or(io::ErrorKind::InvalidData)?;
            let (sender,receiver)=std::sync::mpsc::sync_channel(1024);
            let stop=Arc::new(AtomicBool::new(false));
            let lost=Arc::new(AtomicBool::new(false));
            let mut owner=Self{stop,lost,receiver,workers:Vec::new(),correlation};
            for layer in [2u32,3u32] {
                let directory=directory.to_path_buf();
                let stop=owner.stop.clone();
                let lost=owner.lost.clone();
                let sender=sender.clone();
                let (ready_tx,ready_rx)=std::sync::mpsc::sync_channel(1);
                let worker=std::thread::Builder::new().name(format!("theia-endpoint-{layer}")).spawn(move || {
                    let result=(||->io::Result<()> {
                        let api=load(&directory,dll,sys)?;
                        // Include close/delete events and competing
                        // endpoints. Never filter to the current PID.
                        let handle=api.open_handle(c"outbound and (protocol == 6 or protocol == 17)",layer,0x15)?;
                        api.bounded(&handle)?;
                        ready_tx.send(()).map_err(|_|io::ErrorKind::BrokenPipe)?;
                        while !stop.load(Ordering::Acquire) {
                            match api.receive_event(&handle,&stop,Instant::now()+Duration::from_millis(100)) {
                                Ok(event)=>{
                                    if event.layer!=layer || sender.try_send(event).is_err() {
                                        return Err(io::ErrorKind::InvalidData.into());
                                    }
                                },
                                Err(_) if stop.load(Ordering::Acquire)=>break,
                                Err(e) if e.kind()==io::ErrorKind::TimedOut=>{},
                                Err(e)=>return Err(e),
                            }
                        }
                        api.retire(handle)
                    })();
                    if result.is_err() {lost.store(true,Ordering::Release);}
                })?;
                owner.workers.push(worker);
                ready_rx.recv_timeout(Duration::from_secs(5))
                    .map_err(|_|io::ErrorKind::TimedOut)?;
            }
            Ok(owner)
        }
        fn observe_packet(&mut self,packet:&NetworkObservation)->CaptureAttribution {
            for _ in 0..1024 {
                match self.receiver.try_recv() {
                    Ok(event)=>self.correlation.observe(event),
                    Err(std::sync::mpsc::TryRecvError::Empty)=>break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected)=>{
                        self.lost.store(true,Ordering::Release);break;
                    }
                }
            }
            if self.lost.load(Ordering::Acquire) {self.correlation.invalidate();}
            self.correlation.classify(packet)
        }
        fn report(&self) {
            eprintln!("WinDivert capture attribution: correlated candidates={}, unresolved={}, trusted application=0, observer invalidated={}",
                self.correlation.correlated,self.correlation.unknown,
                self.correlation.ledger.poisoned || self.lost.load(Ordering::Acquire));
        }
    }
    impl Drop for LiveCaptureObservers {
        fn drop(&mut self) {
            self.stop.store(true,Ordering::Release);
            for worker in self.workers.drain(..) {let _=worker.join();}
        }
    }

    pub(crate) async fn begin_scope_relay_lab(directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        scope:RelayScope,seconds:u32)->io::Result<ScopeRelayLab> {
        if !(5..=120).contains(&seconds) {return Err(io::ErrorKind::InvalidInput.into());}
        let (targets,interfaces)=match scope {
            RelayScope::Targets(targets) if validate_redirect_lab_targets(&targets)=>(targets,None),
            RelayScope::Interface{capture,carrier} if capture!=carrier && capture!=0 && carrier!=0=>(Vec::new(),Some((capture,carrier))),
            _=>return Err(io::ErrorKind::InvalidInput.into()),
        };
        let cancel=Cancel(Arc::new(AtomicBool::new(false)));
        let signal=cancel.0.clone();
        let runtime=tokio::runtime::Handle::current();
        let (ready_tx,ready_rx)=oneshot::channel();
        let (end_tx,ended)=oneshot::channel();
        let (event_tx,events)=mpsc::channel(64);
        let (reply_tx,mut reply_rx)=mpsc::channel::<ScopeReply>(64);
        let mut worker=tokio::task::spawn_blocking(move || {
            let _winsock=WinsockLease::start()?;
            let api=load(&directory,dll,sys)?;
            // Observe every target before capture; fail if the target is
            // local or shares a route source with its own address.
            let scopes=targets.iter().map(|target|Ok((*target,RedirectRoute::observe(*target)?)))
                .collect::<io::Result<Vec<_>>>()?;
            let epoch=crate::network_scope::generation().ok_or(io::ErrorKind::PermissionDenied)?;
            let pinned=interfaces.map(|(capture,carrier)|Ok::<_,io::Error>((capture,interface_identity(capture)?,
                carrier,interface_identity(carrier)?))).transpose()?;
            let (outgoing,guard)=if let Some((capture,_,_,_))=pinned {
                (format!("outbound and !loopback and ifIdx == {capture}"),format!("!loopback and ifIdx == {capture}"))
            } else {
                let outgoing=format!("outbound and !loopback and ({})",destination_filter(&targets,false)?);
                let guard=format!("({outgoing}) or (inbound and !loopback and ({}))",destination_filter(&targets,true)?);
                (outgoing,guard)
            };
            // All protocols and both directions in the selected scope.
            let guard_filter=std::ffi::CString::new(guard).map_err(|_|io::ErrorKind::InvalidInput)?;
            let capture_filter=std::ffi::CString::new(outgoing).map_err(|_|io::ErrorKind::InvalidInput)?;
            let mut attribution=LiveCaptureObservers::start(&directory,dll,sys)?;
            let guard=api.open_priority(&guard_filter,0,-100,0x12)?;
            let capture=api.open_priority(&capture_filter,0,100,0x14)?;
            api.bounded(&capture)?;
            let injector=api.open_priority(c"false",0,-200,0x18)?;
            let table=Arc::new(Mutex::new(TcpRedirectTable::new(64,4096).ok_or(io::ErrorKind::InvalidInput)?));
            let mut udp=ScopeUdpLedger::new(64,4096).ok_or(io::ErrorKind::InvalidInput)?;
            let deadline=Instant::now()+Duration::from_secs(u64::from(seconds));
            ready_tx.send(()).map_err(|_|io::ErrorKind::BrokenPipe)?;
            let result=(||->io::Result<()> {
                let mut packets=0usize;
                while !signal.load(Ordering::Acquire) && Instant::now()<deadline {
                    if packets>=65_536 { return Err(io::ErrorKind::OutOfMemory.into()); }
                    if let Some((capture,capture_id,carrier,carrier_id))=pinned {
                        if interface_identity(capture)?!=capture_id || interface_identity(carrier)?!=carrier_id ||
                            crate::network_scope::generation()!=Some(epoch) {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                    } else if scopes.iter().any(|(target,scope)|RedirectRoute::observe(*target).ok()!=Some(*scope)) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    // Bound command work so an active downlink cannot
                    // starve new TCP handshakes or UDP uploads.
                    for _ in 0..16 {
                        let command=match reply_rx.try_recv() {
                            Ok(command)=>command,
                            Err(mpsc::error::TryRecvError::Empty)=>break,
                            Err(mpsc::error::TryRecvError::Disconnected)=>return Err(io::ErrorKind::BrokenPipe.into()),
                        };
                        let ScopeReply{flow,payload,sent}=command;
                        if sent.is_closed() || !udp.owns(&flow) {
                            let _=sent.send(Err(io::ErrorKind::PermissionDenied.into()));
                            continue;
                        }
                        let reverse=flow.plan.build(&payload).ok_or(io::ErrorKind::InvalidData)?;
                        let mut incoming=flow.address;
                        incoming.flags=(1<<23)|if flow.key().source.is_ipv6(){1<<20}else{1<<21};
                        // The originating task keeps its FlowLease while
                        // awaiting this ack. Cancel the actual overlapped
                        // operation when that flow is retired, not merely
                        // future enqueue attempts.
                        if sent.is_closed() || signal.load(Ordering::Acquire) || !udp.owns(&flow) {
                            let _=sent.send(Err(io::ErrorKind::PermissionDenied.into()));
                            continue;
                        }
                        let result=api.send(&injector,&reverse.packet,&incoming,&flow.retired,
                            std::cmp::min(deadline,Instant::now()+Duration::from_secs(1)));
                        let ok=result.is_ok();
                        let revoked=!flow.live();
                        let _=sent.send(result);
                        if !ok && !revoked { return Err(io::Error::other("UDP reverse injection failed")); }
                    }
                    let receive_until=std::cmp::min(deadline,Instant::now()+Duration::from_millis(10));
                    let (packet,address)=match api.receive(&capture,&signal,receive_until) {
                        Ok(data)=>data,
                        Err(_) if signal.load(Ordering::Acquire)=>break,
                        Err(error) if error.kind()==io::ErrorKind::TimedOut=>continue,
                        Err(error)=>return Err(error),
                    };
                    packets+=1;
                    let Ok(obs)=address.network(&packet) else { continue; };
                    if !obs.outbound || obs.sniffed { return Err(io::ErrorKind::PermissionDenied.into()); }
                    let candidate=attribution.observe_packet(&obs);
                    // The common Redirect adapter still receives Unknown
                    // application evidence. A candidate is not permission
                    // to bypass capture or a policy rule.
                    if candidate.application_evidence()!=super::super::Evidence::Unknown {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    let key=obs.meta.flow;
                    // Match route source even for the reverse TCP listener
                    // direction (the target IP stays the same).
                    if let Some((capture,_,_,_))=pinned {
                        if key.interface!=capture || !reflect_address(key.destination) ||
                            !RedirectRoute::observe(key.destination).is_ok_and(|route|route.matches(key)) {
                            continue;
                        }
                    } else if !scopes.iter().any(|(target,scope)|target.ip()==key.destination.ip() &&
                        scope.matches(key)) { continue; }
                    let allowed_target=pinned.is_some() || targets.contains(&key.destination);
                    match key.transport {
                        Transport::Tcp=>{
                            let existing=table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?.lookup(&address,&packet);
                            let token=match existing {
                                Some(token)=>token,
                                None=>{
                                    if !allowed_target || obs.meta.payload_len!=0 ||
                                        !obs.meta.tcp_flags.is_some_and(|flags|flags & !0xc0 == 2) { continue; }
                                    // A different exclusive listener is reserved for
                                    // every SYN. No source-port or target-port guessing.
                                    let listener={
                                        let _entered=runtime.enter();
                                        let socket=if key.source.is_ipv4(){tokio::net::TcpSocket::new_v4()?}
                                            else {tokio::net::TcpSocket::new_v6()?};
                                        exclusive(&socket)?;
                                        socket.bind(SocketAddr::new(key.source.ip(),0))?;
                                        socket.listen(1)?
                                    };
                                    let local=listener.local_addr()?;
                                    let token=table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?
                                        .begin(&address,&packet,local);
                                    let Some(token)=token else { continue; };
                                    // On queue saturation the dropped reservation
                                    // retires the tuple; no SYN is reflected.
                                    if event_tx.try_send(ScopeRelayEvent::Tcp(ScopeTcp{
                                        token,listener,table:table.clone()
                                    })).is_err() { continue; }
                                    token
                                }
                            };
                            let reverse=table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?
                                .reflect(token,&address,&packet);
                            let Some(reverse)=reverse else { continue; };
                            let mut incoming=address;
                            incoming.flags=(1<<22)|if key.source.is_ipv6(){1<<20}else{1<<21};
                            api.send(&injector,&reverse.packet,&incoming,&signal,deadline)?;
                        }
                        Transport::Udp=>{
                            if !allowed_target || obs.meta.payload_len>crate::protocol::MAX_DATAGRAM { continue; }
                            let Some(plan)=UdpReversePlan::from_diverted_packet(&address,&packet) else { continue; };
                            let Some(start)=packet.len().checked_sub(obs.meta.payload_len) else { continue; };
                            let Some((flow,first))=udp.observe(plan,address) else { continue; };
                            if event_tx.try_send(ScopeRelayEvent::Udp(ScopeUdpPacket{
                                flow:flow.clone(),payload:packet[start..].to_vec()
                            })).is_err() {
                                // A first packet that never reaches the
                                // owner must not consume a live slot forever.
                                if first { flow.close(); }
                                crate::traffic::udp_queue_drop();
                            }
                        }
                    }
                }
                Ok(())
            })();
            // Revoke all local capabilities before telling the async
            // owner to join relays; keep both guard handles alive until
            // the owner has explicitly requested teardown.
            if let Ok(mut t)=table.lock() { t.retire(); }
            udp.retire();
            attribution.report();
            drop(attribution);
            let _=end_tx.send(());
            drop(event_tx);
            drop(reply_rx);
            while !signal.load(Ordering::Acquire) { std::thread::sleep(Duration::from_millis(10)); }
            let r1=api.retire(capture);
            let r2=api.retire(injector);
            let r3=guard.close();
            result?;
            r1?;r2?;r3
        });
        if ready_rx.await.is_err() {
            (&mut worker).await.map_err(|_|io::Error::other("WinDivert scope worker failed"))??;
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(ScopeRelayLab{events,replies:ScopeReplies(reply_tx),ended,worker,cancel})
    }

    /// One explicitly authorized non-loopback echo flow, never a generic
    /// application capture or an externally supplied packet/injection key.
    /// The worker owns the exact socket, capture, guard and injector. It
    /// waits for each carrier reply before issuing the next datagram.
    pub(crate) const UDP_LAB_DATAGRAMS: usize = 3;
    pub(crate) struct RelayLab {
        pub(crate) key:super::super::packet::FlowKey,
        reply:tokio::sync::mpsc::Sender<Vec<u8>>,
        worker:tokio::task::JoinHandle<io::Result<()>>,
        _cancel:Cancel,
    }
    impl RelayLab {
        pub(crate) fn respond(&self,payload:Vec<u8>)->io::Result<()> {
            self.reply.try_send(payload).map_err(|_|io::ErrorKind::BrokenPipe.into())
        }
        pub(crate) async fn finish(mut self)->io::Result<()> {
            (&mut self.worker).await.map_err(|_|io::Error::other("WinDivert relay lab worker failed"))?
        }
    }

    pub(crate) async fn begin_udp_relay_lab(directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        target:std::net::SocketAddr,
        captured_tx:tokio::sync::mpsc::Sender<(super::super::packet::FlowKey,Vec<u8>)>)->io::Result<RelayLab> {
        use tokio::sync::{mpsc,oneshot};
        let cancel=Cancel(Arc::new(AtomicBool::new(false)));
        let signal=cancel.0.clone();
        let (ready_tx,ready_rx)=oneshot::channel();
        let (reply_tx,mut reply_rx)=mpsc::channel::<Vec<u8>>(1);
        let mut worker=tokio::task::spawn_blocking(move || {
            use ring::rand::{SecureRandom,SystemRandom};
            if target.port()==0 || target.ip().is_loopback() || target.ip().is_unspecified() || target.ip().is_multicast()
                || matches!(target,std::net::SocketAddr::V4(v) if v.ip().octets()[0]>=224 || v.ip().octets()[0]==0)
                || matches!(target,std::net::SocketAddr::V6(v) if v.scope_id()!=0 || v.flowinfo()!=0 || v.ip().to_ipv4_mapped().is_some() || v.ip().is_unicast_link_local())
            { return Err(io::ErrorKind::InvalidInput.into()); }
            let _winsock=WinsockLease::start()?;
            let api=load(&directory,dll,sys)?;
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
            let deadline=Instant::now()+Duration::from_secs(25);
            let result=(||->io::Result<()> {
                let mut ready=Some(ready_tx);
                let mut first_plan=None;
                for length in [32,33,1200] {
                    let mut nonce=vec![0u8;length];
                    SystemRandom::new().fill(&mut nonce).map_err(|_|io::Error::other("entropy unavailable"))?;
                    if signal.load(Ordering::Acquire) || Instant::now()>=deadline
                        || crate::network_scope::observe(target)!=Some(scope)
                        || socket_endpoint(&socket)?!=endpoint
                    { return Err(io::ErrorKind::PermissionDenied.into()); }
                    if socket.send(&nonce)?!=nonce.len() { return Err(io::ErrorKind::WriteZero.into()); }
                    let (packet,address)=api.receive(&capture,&signal,
                        std::cmp::min(deadline,Instant::now()+Duration::from_secs(3)))?;
                    let observation=address.network(&packet).map_err(|_|io::ErrorKind::InvalidData)?;
                    if observation.meta.flow.source!=local || observation.meta.flow.destination!=target
                        || observation.meta.payload_len!=nonce.len() || !packet.ends_with(&nonce)
                        || socket_endpoint(&socket)?!=endpoint {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    let plan=UdpReversePlan::from_diverted_packet(&address,&packet).ok_or(io::ErrorKind::PermissionDenied)?;
                    if let Some(previous)=first_plan {
                        if previous!=plan { return Err(io::ErrorKind::PermissionDenied.into()); }
                    } else {
                        first_plan=Some(plan);
                        ready.take().ok_or(io::ErrorKind::BrokenPipe)?.send(plan.original_flow())
                            .map_err(|_|io::ErrorKind::BrokenPipe)?;
                    }
                    // Transfer the bytes actually observed by NETWORK.
                    // Queue full/closed is terminal in this acceptance
                    // fixture; no original datagram is reinjected.
                    let start=packet.len().checked_sub(observation.meta.payload_len)
                        .ok_or(io::ErrorKind::InvalidData)?;
                    captured_tx.try_send((plan.original_flow(),packet[start..].to_vec()))
                        .map_err(|_|io::ErrorKind::BrokenPipe)?;
                    let bytes=loop {
                        if signal.load(Ordering::Acquire) || Instant::now()>=deadline {
                            return Err(io::ErrorKind::Interrupted.into());
                        }
                        match reply_rx.try_recv() {
                            Ok(bytes)=>break bytes,
                            Err(mpsc::error::TryRecvError::Empty)=>std::thread::sleep(Duration::from_millis(10)),
                            Err(mpsc::error::TryRecvError::Disconnected)=>return Err(io::ErrorKind::BrokenPipe.into()),
                        }
                    };
                    if bytes!=nonce || socket_endpoint(&socket)?!=endpoint
                        || socket.local_addr()?!=local || socket.peer_addr()?!=target
                        || crate::network_scope::observe(target)!=Some(scope) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    let reverse=plan.build(&bytes).ok_or(io::ErrorKind::InvalidData)?;
                    let mut incoming=address;
                    incoming.flags=(1<<23) | if target.is_ipv6(){1<<20}else{1<<21};
                    api.send(&injector,&reverse.packet,&incoming,&signal,deadline)?;
                    let mut data=[0u8;1201];
                    let n=socket.recv(&mut data)?;
                    if socket.peer_addr()?!=target || &data[..n]!=bytes {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                }
                Ok(())
            })();
            // The owned source must close before removing the exact
            // capture and lower DROP handle, including on relay errors.
            drop(socket);
            result?;
            api.retire(capture)?;
            api.retire(injector)?;
            guard.close()
        });
        let key=match ready_rx.await {
            Ok(data)=>data,
            Err(_)=>{
                (&mut worker).await.map_err(|_|io::Error::other("WinDivert relay lab worker failed"))??;
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        };
        Ok(RelayLab { key,reply:reply_tx,worker,_cancel:cancel })
    }

    /// Real non-loopback TCP reflection for an explicitly authorized
    /// owned echo socket. Keep the lower DROP handle until the async
    /// sockets close, including after a capture error.
    /// Not a generic application or persistent guard.
    pub(crate) async fn run_tcp_relay_lab<F,Fut>(
        directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        target:std::net::SocketAddr,relay:F,
    )->io::Result<()>
    where F:FnOnce(super::super::packet::FlowKey,tokio::net::TcpStream)->Fut,
        Fut:std::future::Future<Output=io::Result<()>>
    {
        use ring::rand::{SecureRandom,SystemRandom};
        use tokio::{io::{AsyncReadExt,AsyncWriteExt},sync::oneshot};
        use std::{net::SocketAddr,sync::Mutex};
        if !reflect_address(target) { return Err(io::ErrorKind::InvalidInput.into()); }
        let cancel=Cancel(Arc::new(AtomicBool::new(false)));
        let signal=cancel.0.clone();
        let _winsock=WinsockLease::start()?;
        let scope=crate::network_scope::observe(target).ok_or(io::ErrorKind::PermissionDenied)?;
        let bind=||->io::Result<tokio::net::TcpSocket> {
            let socket=if target.is_ipv4(){tokio::net::TcpSocket::new_v4()?}
                else{tokio::net::TcpSocket::new_v6()?};
            exclusive(&socket)?;
            socket.bind(scope.bind_address())?;
            Ok(socket)
        };
        let client=bind()?;
        let listener=bind()?.listen(1)?;
        let client_addr=client.local_addr()?;
        let listener_addr=listener.local_addr()?;
        if !scope.matches_local(client_addr) || !scope.matches_local(listener_addr)
            || client_addr==listener_addr || client_addr.ip()==target.ip()
            || !reflect_address(client_addr) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let endpoint=socket_endpoint(&client)?;
        let peer=SocketAddr::new(target.ip(),client_addr.port());
        let table=Arc::new(Mutex::new(TcpRedirectTable::new(1,1).ok_or(io::ErrorKind::InvalidInput)?));
        let capture_table=table.clone();
        let (ready_tx,ready_rx)=oneshot::channel();
        let (failed_tx,mut failed_rx)=oneshot::channel::<()>();
        let mut challenge=[0u8;128];
        SystemRandom::new().fill(&mut challenge).map_err(|_|io::Error::other("entropy unavailable"))?;
        let worker=tokio::task::spawn_blocking(move || {
            let _winsock=WinsockLease::start()?;
            let api=load(&directory,dll,sys)?;
            let field=if target.is_ipv4(){"ip"}else{"ipv6"};
            let filter=std::ffi::CString::new(format!(
                "outbound and !loopback and !impostor and tcp and {field}.SrcAddr == {} and {field}.DstAddr == {} and ((tcp.SrcPort == {} and tcp.DstPort == {}) or (tcp.SrcPort == {} and tcp.DstPort == {}))",
                client_addr.ip(),target.ip(),client_addr.port(),target.port(),listener_addr.port(),peer.port()
            )).map_err(|_|io::ErrorKind::InvalidInput)?;
            let guard=api.open_priority(&filter,0,-100,0x12)?;
            let capture=api.open_priority(&filter,0,100,0x10)?;
            api.bounded(&capture)?;
            let injector=api.open_priority(c"false",0,-200,0x18)?;
            ready_tx.send(()).map_err(|_|io::ErrorKind::BrokenPipe)?;
            let deadline=Instant::now()+Duration::from_secs(30);
            let result=(||->io::Result<()> {
                let mut packets=0usize;
                while !signal.load(Ordering::Acquire) {
                    if Instant::now()>=deadline || packets>=512
                        || crate::network_scope::observe(target)!=Some(scope) {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let receive_until=std::cmp::min(deadline,Instant::now()+Duration::from_millis(100));
                    let (packet,address)=match api.receive(&capture,&signal,receive_until) {
                        Ok(data)=>data,
                        Err(_) if signal.load(Ordering::Acquire)=>break,
                        Err(error) if error.kind()==io::ErrorKind::TimedOut=>continue,
                        Err(error)=>return Err(error),
                    };
                    let observation=address.network(&packet).map_err(|_|io::ErrorKind::InvalidData)?;
                    let key=observation.meta.flow;
                    let reverse={
                        let mut table=capture_table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?;
                        let token=match table.lookup(&address,&packet) {
                            Some(token)=>token,
                            None if packets==0 && key.source==client_addr && key.destination==target=>
                                table.begin(&address,&packet,listener_addr).ok_or(io::ErrorKind::PermissionDenied)?,
                            _=>return Err(io::ErrorKind::PermissionDenied.into()),
                        };
                        table.reflect(token,&address,&packet).ok_or(io::ErrorKind::PermissionDenied)?
                    };
                    if signal.load(Ordering::Acquire) { break; }
                    if crate::network_scope::observe(target)!=Some(scope) ||
                        reverse.interface!=observation.interface || reverse.sub_interface!=observation.sub_interface {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    let mut incoming=address;
                    incoming.flags=(1<<22) | if target.is_ipv6(){1<<20}else{1<<21};
                    match api.send(&injector,&reverse.packet,&incoming,&signal,deadline) {
                        Ok(())=>packets+=1,
                        Err(_) if signal.load(Ordering::Acquire)=>break,
                        Err(error)=>return Err(error),
                    }
                }
                if packets==0 { return Err(io::ErrorKind::InvalidData.into()); }
                Ok(())
            })();
            if result.is_err() { let _=failed_tx.send(()); }
            // Keep the drop rule active until the socket-owning future
            // has been destroyed, even on RecvEx/SendEx failure.
            while !signal.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
            let capture_result=api.retire(capture);
            let inject_result=api.retire(injector);
            let guard_result=guard.close();
            result?;
            capture_result?;
            inject_result?;
            guard_result
        });
        if ready_rx.await.is_err() { return Err(io::ErrorKind::UnexpectedEof.into()); }
        // Both socket-owning futures are dropped before the Cancel
        // signal, including on timeout, worker error or cancellation.
        let result=tokio::select! {
            biased;
            _=&mut failed_rx=>Err(io::Error::other("TCP capture worker failed")),
            result=tokio::time::timeout(Duration::from_secs(25),async move {
                tokio::try_join!(
                    async {
                        let mut stream=client.connect(target).await?;
                        if stream.local_addr()?!=client_addr || stream.peer_addr()?!=target
                            || socket_endpoint(&stream)?!=endpoint
                            || crate::network_scope::observe(target)!=Some(scope) {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                        stream.write_all(&challenge[..64]).await?;
                        stream.write_all(&challenge[64..]).await?;
                        let mut echoed=[0u8;128];
                        stream.read_exact(&mut echoed).await?;
                        if echoed!=challenge || socket_endpoint(&stream)?!=endpoint {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                        stream.shutdown().await?;
                        let mut eof=[0u8;1];
                        if stream.read(&mut eof).await?!=0 { return Err(io::ErrorKind::InvalidData.into()); }
                        Ok::<(),io::Error>(())
                    },
                    async {
                        let (stream,accepted_peer)=listener.accept().await?;
                        if accepted_peer!=peer || stream.peer_addr()?!=peer ||
                            stream.local_addr()?!=listener_addr ||
                            crate::network_scope::observe(target)!=Some(scope) {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                        let token=table.lock().map_err(|_|io::ErrorKind::PermissionDenied)?
                            .accept_captured(listener_addr,accepted_peer).ok_or(io::ErrorKind::PermissionDenied)?;
                        drop(listener);
                        relay(token.original(),stream).await
                    }
                )?;
                Ok::<(),io::Error>(())
            })=>match result {
                Ok(result)=>result,
                Err(_)=>Err(io::ErrorKind::TimedOut.into()),
            },
        };
        drop(cancel);
        let completed=worker.await.map_err(|_|io::Error::other("TCP capture worker panicked"))?;
        result?;
        completed
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

    // Diagnostic only: a process handle pins the process object, not the
    // loaded image section. Never turn a pathname hash into Evidence::Known.
    struct ProcessImage {
        process: Event,
        pid: u32,
        creation: u64,
        path: std::path::PathBuf,
        digest: [u8;32],
        _image: File,
    }
    impl ProcessImage {
        fn identity(handle:HANDLE,pid:u32)->io::Result<(u64,std::path::PathBuf)> {
            use windows_sys::Win32::{
                Foundation::FILETIME,
                System::Threading::{GetProcessId,GetProcessTimes,QueryFullProcessImageNameW},
            };
            use std::os::windows::ffi::OsStringExt;
            if unsafe { GetProcessId(handle) }!=pid || unsafe { WaitForSingleObject(handle,0) }!=WAIT_TIMEOUT {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let mut creation:FILETIME=unsafe {std::mem::zeroed()};
            let mut exit=creation;
            let mut kernel=creation;
            let mut user=creation;
            if unsafe {GetProcessTimes(handle,&mut creation,&mut exit,&mut kernel,&mut user)}==0 {
                return Err(io::Error::last_os_error());
            }
            let birth=(u64::from(creation.dwHighDateTime)<<32)|u64::from(creation.dwLowDateTime);
            let mut buf=vec![0u16;32768];
            let mut len=buf.len() as u32;
            if unsafe {QueryFullProcessImageNameW(handle,0,buf.as_mut_ptr(),&mut len)}==0 {
                return Err(io::Error::last_os_error());
            }
            if birth==0 || len==0 || len as usize>=buf.len() || buf[..len as usize].contains(&0) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let path=std::path::PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize]));
            if !path.is_absolute() { return Err(io::ErrorKind::InvalidData.into()); }
            Ok((birth,path))
        }
        fn inspect(pid:u32)->io::Result<Self> {
            use windows_sys::Win32::System::Threading::{OpenProcess,PROCESS_QUERY_LIMITED_INFORMATION};
            if pid==0 { return Err(io::ErrorKind::InvalidInput.into()); }
            let raw=unsafe {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x0010_0000,0,pid)};
            if raw.is_null() { return Err(io::Error::last_os_error()); }
            let process=Event(raw);
            let (creation,path)=Self::identity(process.0,pid)?;
            let mut image=OpenOptions::new().read(true).share_mode(1).custom_flags(0x0020_0000).open(&path)?;
            let meta=image.metadata()?;
            if !meta.is_file() || meta.file_attributes()&0x400!=0 || !(1..=128*1024*1024).contains(&meta.len()) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut sha=Sha256::new();
            let mut count=0u64;
            let mut buffer=[0u8;65536];
            loop {
                let n=image.read(&mut buffer)?;
                if n==0 {break;}
                count=count.checked_add(n as u64).ok_or(io::ErrorKind::InvalidData)?;
                if count>meta.len() {return Err(io::ErrorKind::InvalidData.into());}
                sha.update(&buffer[..n]);
            }
            if count!=meta.len() || Self::identity(process.0,pid)?!=(creation,path.clone()) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(Self {process,pid,creation,path,digest:sha.finalize().into(),_image:image})
        }
        fn revalidate(&self,event:&EndpointCandidate)->io::Result<[u8;32]> {
            if event.pid!=self.pid || Self::identity(self.process.0,self.pid)?!=(self.creation,self.path.clone()) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(self.digest)
        }
    }

    fn socket_lab(api:&Api,cancelled:&AtomicBool) -> io::Result<()> {
        // Only capture events belonging to the current process. The
        // socket is held open until the observed connect and close.
        let pid=std::process::id();
        let image=ProcessImage::inspect(pid)?;
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
        let lease=registry.register(endpoint,pid,tuple,registration_timestamp()?).ok_or(io::ErrorKind::PermissionDenied)?;
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
        if image.revalidate(&candidate)?!=image.digest || candidate!=established || !registry.matches_packet_candidate(&ledger,&observed) || !packet.ends_with(b"correlation-lab")
            || socket_endpoint(&sender)?!=endpoint { return Err(io::ErrorKind::PermissionDenied.into()); }
        api.send(&network,&packet,&address,cancelled,deadline)?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes=[0u8;32];
        let (n,from)=receiver.recv_from(&mut bytes)?;
        if from!=src || &bytes[..n]!=b"correlation-lab" { return Err(io::ErrorKind::InvalidData.into()); }
        // Isolated fixture only: two exclusively bound loopback sockets,
        // never an application-wide or destination-wide production exemption.
        // Demonstrate actual kernel filtering, not merely a registry match.
        use ring::rand::{SecureRandom,SystemRandom};
        let other=loopback_udp("127.0.0.1:0")?;
        other.connect(dst)?;
        let other_src=other.local_addr()?;
        if other_src==src { return Err(io::ErrorKind::InvalidData.into()); }
        let base=format!(
            "outbound and loopback and !impostor and udp and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and udp.DstPort == {} and (udp.SrcPort == {} or udp.SrcPort == {})",
            dst.port(),src.port(),other_src.port()
        );
        let excluded=std::ffi::CString::new(format!("({base}) and udp.SrcPort != {}",src.port()))
            .map_err(|_|io::ErrorKind::InvalidInput)?;
        let guard=api.open_priority(&excluded,0,-100,0x12)?;
        let capture=api.open_priority(&excluded,0,100,0x14)?;
        api.bounded(&capture)?;
        api.retire(network)?;
        let mut allowed_nonce=[0u8;32];
        let mut denied_nonce=[0u8;32];
        let mut revoked_nonce=[0u8;32];
        let rng=SystemRandom::new();
        for nonce in [&mut allowed_nonce,&mut denied_nonce,&mut revoked_nonce] {
            rng.fill(nonce).map_err(|_|io::Error::other("entropy unavailable"))?;
        }
        if other.send(&denied_nonce)?!=denied_nonce.len() || sender.send(&allowed_nonce)?!=allowed_nonce.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let (p,a)=api.receive(&capture,cancelled,Instant::now()+Duration::from_secs(3))?;
        let n=a.network_inner(&p,true).map_err(|_|io::ErrorKind::InvalidData)?;
        if n.sniffed || !n.outbound || n.meta.flow.source!=other_src || n.meta.flow.destination!=dst
            || n.meta.payload_len!=denied_nonce.len() || !p.ends_with(&denied_nonce) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (size,from)=receiver.recv_from(&mut bytes)?;
        if from!=src || bytes[..size]!=allowed_nonce { return Err(io::ErrorKind::InvalidData.into()); }

        // Revoke by installing stricter handles before dropping the lease.
        // No transition in the fixture leaves the negative socket unguarded.
        let all=std::ffi::CString::new(base).map_err(|_|io::ErrorKind::InvalidInput)?;
        let revoke_guard=api.open_priority(&all,0,-99,0x12)?;
        let revoke_capture=api.open_priority(&all,0,101,0x14)?;
        api.bounded(&revoke_capture)?;
        drop(lease);
        if registry.matches_packet_candidate(&ledger,&observed) { return Err(io::ErrorKind::PermissionDenied.into()); }
        if sender.send(&revoked_nonce)?!=revoked_nonce.len() { return Err(io::ErrorKind::WriteZero.into()); }
        let (p,a)=api.receive(&revoke_capture,cancelled,Instant::now()+Duration::from_secs(3))?;
        let n=a.network_inner(&p,true).map_err(|_|io::ErrorKind::InvalidData)?;
        if n.sniffed || !n.outbound || n.meta.flow.source!=src || n.meta.flow.destination!=dst
            || n.meta.payload_len!=revoked_nonce.len() || !p.ends_with(&revoked_nonce) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        receiver.set_read_timeout(Some(Duration::from_millis(250)))?;
        match receiver.recv_from(&mut bytes) {
            Err(e) if matches!(e.kind(),io::ErrorKind::TimedOut|io::ErrorKind::WouldBlock)=>{},
            Err(e)=>return Err(e),
            Ok(_)=>return Err(io::ErrorKind::PermissionDenied.into()),
        }
        drop(other);
        drop(sender);
        api.retire(revoke_capture)?;
        api.retire(capture)?;
        api.retire(revoke_guard)?;
        api.retire(guard)?;
        let closed=api.receive_event(&handle,cancelled,Instant::now()+Duration::from_secs(3))?;
        if closed.pid!=pid || closed.endpoint!=event.endpoint || closed.event!=7 || closed.timestamp<event.timestamp {
            return Err(io::ErrorKind::InvalidData.into());
        }
        ledger.observe(closed);
        if ledger.correlate(&observed).is_some() { return Err(io::ErrorKind::PermissionDenied.into()); }
        registry.retire();
        api.retire(flow)?;
        api.retire(handle)
    }

    fn interface_identity(index:u32)->io::Result<(u64,u32,u16,u16,[u8;8])> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2,MIB_IF_ROW2};
        if index==0 { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut row:MIB_IF_ROW2=unsafe {std::mem::zeroed()};
        row.InterfaceIndex=index;
        let status=unsafe {GetIfEntry2(&mut row)};
        if status!=0 { return Err(io::Error::from_raw_os_error(status as i32)); }
        let luid=unsafe {row.InterfaceLuid.Value};
        // IF_TYPE_SOFTWARE_LOOPBACK == 24.
        if row.InterfaceIndex!=index || row.Type==24 || luid==0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let id=row.InterfaceGuid;
        Ok((luid,id.data1,id.data2,id.data3,id.data4))
    }

    /// Real diverted packets from arbitrary processes on one explicitly
    /// selected disposable-machine interface. No SOCKS, echo socket or
    /// application-specific filter. All captured packets are dropped; the
    /// lower DROP handle protects overflow while these handles live.
    /// This does not install persistent protection or prove attribution.
    pub async fn scope_drop_acceptance(directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        interface:u32,seconds:u32)->io::Result<ScopeCaptureStats> {
        if !(1..=30).contains(&seconds) || interface==0 { return Err(io::ErrorKind::InvalidInput.into()); }
        let cancel=Cancel(Arc::new(AtomicBool::new(false)));
        let signal=cancel.0.clone();
        let result=tokio::task::spawn_blocking(move || {
            let identity=interface_identity(interface)?;
            let api=load(&directory,dll,sys)?;
            let filter=std::ffi::CString::new(format!("outbound and !loopback and ifIdx == {interface}"))
                .map_err(|_|io::ErrorKind::InvalidInput)?;
            let guard=api.open_priority(&filter,0,-100,0x12)?;
            let capture=api.open_priority(&filter,0,100,0x14)?;
            api.bounded(&capture)?;
            let mut ledger=ScopeCaptureLedger::new(interface).ok_or(io::ErrorKind::InvalidInput)?;
            let deadline=Instant::now()+Duration::from_secs(u64::from(seconds));
            let result=(||->io::Result<ScopeCaptureStats> {
                while Instant::now()<deadline && ledger.stats.observed()<MAX_SCOPE_PACKETS {
                    if signal.load(Ordering::Acquire) { return Err(io::ErrorKind::Interrupted.into()); }
                    if interface_identity(interface)?!=identity { return Err(io::ErrorKind::PermissionDenied.into()); }
                    let receive_until=std::cmp::min(deadline,Instant::now()+Duration::from_millis(100));
                    match api.receive(&capture,&signal,receive_until) {
                        Ok((packet,address))=>{
                            ledger.observe(&address,&packet).map_err(|_|io::ErrorKind::InvalidData)?;
                        },
                        Err(error) if error.kind()==io::ErrorKind::TimedOut=>{},
                        Err(error)=>return Err(error),
                    }
                }
                if interface_identity(interface)?!=identity { return Err(io::ErrorKind::PermissionDenied.into()); }
                Ok(ledger.stats)
            })();
            // The capture handle is retired before the lower drop handle.
            // There is no injector and no path that forwards payload.
            let retired=api.retire(capture);
            let released=guard.close();
            let stats=result?;
            retired?;
            released?;
            Ok(stats)
        }).await.map_err(|_|io::Error::other("WinDivert scope worker failed"))?;
        drop(cancel);
        result
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
pub use native::{loopback_acceptance, probe, scope_drop_acceptance};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use native::{begin_udp_relay_lab, run_tcp_relay_lab, RelayLab, UDP_LAB_DATAGRAMS,
    begin_scope_relay_lab, ScopeRelayEvent, ScopeUdpPacket, ScopeReplies,
    prepare_carrier_tcp,bind_carrier_udp};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_correlation_cannot_be_application_evidence() {
        use super::super::{Evidence,packet::{FlowKey,Transport}};
        let source="192.0.2.1:1234".parse().unwrap();
        let destination="198.51.100.2:443".parse().unwrap();
        let words=|v:&str|u128::from(v.parse::<std::net::Ipv6Addr>().unwrap()).to_le_bytes();
        let event=EndpointCandidate{endpoint:1,pid:42,timestamp:100,layer:3,event:4,protocol:17,
            outbound:true,local_port:1234,remote_port:443,local_words:words("::ffff:192.0.2.1"),
            remote_words:words("::ffff:198.51.100.2")};
        let packet=NetworkObservation{timestamp:110,outbound:true,sniffed:false,interface:7,sub_interface:0,
            meta:PacketMeta{flow:FlowKey{source,destination,transport:Transport::Udp,interface:7},
                payload_len:1,tcp_flags:None},transport_checksum_reported_valid:true};
        let mut capture=CaptureCorrelation::new(90,100).unwrap();
        capture.observe(EndpointCandidate{timestamp:89,..event});
        assert_eq!(capture.classify(&packet),CaptureAttribution::Unknown);
        capture.observe(event);
        capture.observe(EndpointCandidate{layer:2,event:1,timestamp:101,..event});
        let matched=capture.classify(&packet);
        assert_eq!(matched,CaptureAttribution::CorrelatedEndpoint);
        assert_eq!(matched.application_evidence(),Evidence::Unknown);
        capture.observe(EndpointCandidate{event:7,timestamp:111,..event});
        assert_eq!(capture.classify(&NetworkObservation{timestamp:112,..packet}),CaptureAttribution::Unknown);
        capture.invalidate();
        assert_eq!(capture.classify(&packet),CaptureAttribution::Unknown);
        assert_eq!((capture.correlated,capture.unknown),(1,3));
    }

    #[test]
    fn scope_udp_reverse_capability_is_epoch_and_interface_bound() {
        let mut raw=[0u8;80];
        raw[..8].copy_from_slice(&100i64.to_le_bytes());
        raw[8..12].copy_from_slice(&(1u32<<17).to_le_bytes());
        raw[16..20].copy_from_slice(&7u32.to_le_bytes());
        let addr=Address::from_bytes(&raw);
        let mut packet=[0u8;28];
        packet[0]=0x45;packet[2..4].copy_from_slice(&28u16.to_be_bytes());packet[9]=17;
        packet[12..16].copy_from_slice(&[192,0,2,1]);packet[16..20].copy_from_slice(&[198,51,100,2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        let plan=UdpReversePlan::from_diverted_packet(&addr,&packet).unwrap();
        let mut ledger=ScopeUdpLedger::new(2,3).unwrap();
        let (a,first)=ledger.observe(plan,addr).unwrap();
        assert!(first && ledger.owns(&a));
        let (same,first)=ledger.observe(plan,addr).unwrap();
        assert!(!first && std::sync::Arc::ptr_eq(&a,&same));
        let mut stale=addr;stale.timestamp=99;
        assert!(ledger.observe(plan,stale).is_none());
        let mut wrong=addr;wrong.data[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(ledger.observe(UdpReversePlan::from_diverted_packet(&wrong,&packet).unwrap(),wrong).is_none());
        packet[20..22].copy_from_slice(&1235u16.to_be_bytes());
        let second_plan=UdpReversePlan::from_diverted_packet(&addr,&packet).unwrap();
        let (b,_)=ledger.observe(second_plan,addr).unwrap();
        assert!(ledger.owns(&b));
        packet[20..22].copy_from_slice(&1236u16.to_be_bytes());
        let third_plan=UdpReversePlan::from_diverted_packet(&addr,&packet).unwrap();
        assert!(ledger.observe(third_plan,addr).is_none());
        a.close();
        assert!(!ledger.owns(&a));
        assert!(ledger.observe(plan,addr).is_none());
        let (c,_)=ledger.observe(third_plan,addr).unwrap();
        assert!(ledger.owns(&c));
        let response=c.plan.build(b"non-echo server reply").unwrap();
        let parsed=PacketMeta::parse(&response.packet,7).unwrap();
        assert_eq!(parsed.flow.source,c.key().destination);
        assert_eq!(parsed.flow.destination,c.key().source);
        assert!(response.packet.ends_with(b"non-echo server reply"));
        ledger.retire();
        assert!(!ledger.owns(&b) && !ledger.owns(&c));
        assert!(ledger.observe(third_plan,addr).is_none());
        let mut other_epoch=ScopeUdpLedger::new(1,1).unwrap();
        let (new,_)=other_epoch.observe(plan,addr).unwrap();
        assert!(other_epoch.owns(&new) && !other_epoch.owns(&a));
    }
    #[test]
    fn scope_targets_are_literal_bounded_and_carrier_cannot_recurse() {
        let v4="192.0.2.1:443".parse().unwrap();
        let v6="[2001:db8::1]:443".parse().unwrap();
        assert!(validate_redirect_lab_targets(&[v4,v6]));
        assert!(!validate_redirect_lab_targets(&[]));
        assert!(!validate_redirect_lab_targets(&[v4,v4]));
        assert!(!validate_redirect_lab_targets(&["127.0.0.1:443".parse().unwrap()]));
        assert!(!validate_redirect_lab_targets(&["[fe80::1]:443".parse().unwrap()]));
        let registry=CarrierRegistry::for_redirect_lab(&[v4,v6]).unwrap();
        let tuple=EndpointTuple{local:"192.0.2.2:40000".parse().unwrap(),remote:v4,
            transport:super::super::packet::Transport::Tcp};
        assert!(registry.register(1,1,tuple,1).is_none());
        assert!(registry.register(1,1,EndpointTuple{remote:"192.0.2.1:8443".parse().unwrap(),..tuple},1).is_none());
        assert!(registry.register(2,1,EndpointTuple{remote:"198.51.100.1:443".parse().unwrap(),..tuple},1).is_some());
    }
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
    fn scope_drop_observes_arbitrary_tuples_without_authorizing_them() {
        let mut raw=[0u8;80];
        raw[..8].copy_from_slice(&1i64.to_le_bytes());
        raw[8..12].copy_from_slice(&(1u32<<17).to_le_bytes());
        raw[16..20].copy_from_slice(&7u32.to_le_bytes());
        let addr=Address::from_bytes(&raw);
        let mut udp=[0u8;28];
        udp[0]=0x45;udp[2..4].copy_from_slice(&28u16.to_be_bytes());udp[9]=17;
        udp[12..16].copy_from_slice(&[192,0,2,1]);udp[16..20].copy_from_slice(&[198,51,100,2]);
        udp[20..22].copy_from_slice(&1000u16.to_be_bytes());
        udp[22..24].copy_from_slice(&443u16.to_be_bytes());udp[24..26].copy_from_slice(&8u16.to_be_bytes());
        let mut ledger=ScopeCaptureLedger::new(7).unwrap();
        ledger.observe(&addr,&udp).unwrap();
        ledger.observe(&addr,&udp).unwrap();
        udp[20..22].copy_from_slice(&1001u16.to_be_bytes());
        ledger.observe(&addr,&udp).unwrap();
        let mut tcp=[0u8;40];
        tcp[..20].copy_from_slice(&udp[..20]);tcp[2..4].copy_from_slice(&40u16.to_be_bytes());tcp[9]=6;
        tcp[20..24].copy_from_slice(&udp[20..24]);tcp[32]=0x50;tcp[33]=2;
        ledger.observe(&addr,&tcp).unwrap();
        let mut v6=[0u8;48];
        v6[0]=0x60;v6[4..6].copy_from_slice(&8u16.to_be_bytes());v6[6]=17;
        v6[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6[24..40].copy_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6[40..48].copy_from_slice(&udp[20..28]);
        raw[8..12].copy_from_slice(&((1u32<<17)|(1<<20)).to_le_bytes());
        ledger.observe(&Address::from_bytes(&raw),&v6).unwrap();
        assert_eq!(ledger.stats.udp_v4,3);
        assert_eq!(ledger.stats.tcp_v4,1);
        assert_eq!(ledger.stats.udp_v6,1);
        assert_eq!(ledger.stats.distinct_tuples,4);
        ledger.observe(&addr,&[0]).unwrap();
        assert_eq!(ledger.stats.unsupported_or_malformed,1);
        raw[16..20].copy_from_slice(&8u32.to_le_bytes());
        assert!(ledger.observe(&Address::from_bytes(&raw),&v6).is_err());
        assert!(ScopeCaptureLedger::new(0).is_none());
        let mut sniffed=addr;
        sniffed.flags|=1<<16;
        assert!(ledger.observe(&sniffed,&udp).is_err());
        assert_eq!(ledger.stats.observed(),6);
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
        // A close event that conflicts with a live endpoint must
        // invalidate the epoch, not leave other candidate permits usable.
        let other=EndpointCandidate {endpoint:5,local_port:1001,..event};
        let other_flow=EndpointCandidate {timestamp:105,event:1,layer:2,..other};
        let mut other_packet=packet;
        other_packet.meta.flow.source.set_port(1001);
        let mut conflict=CandidateLedger::new(4,20).unwrap();
        conflict.observe(event);conflict.observe(flow);
        conflict.observe(other);conflict.observe(other_flow);
        assert_eq!(conflict.correlate(&other_packet),Some(other_flow));
        conflict.observe(EndpointCandidate {event:7,timestamp:111,pid:43,..event});
        assert!(conflict.correlate(&other_packet).is_none());
        let mut reuse=CandidateLedger::new(4,20).unwrap();
        reuse.observe(event);reuse.observe(flow);
        reuse.observe(other);reuse.observe(other_flow);
        reuse.observe(EndpointCandidate {event:7,timestamp:111,..event});
        reuse.observe(EndpointCandidate {timestamp:112,local_port:1002,..event});
        assert!(reuse.correlate(&other_packet).is_none());
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
        let lease=registry.register(9,42,tuple,99).unwrap();
        let words=|v:&str| u128::from(v.parse::<std::net::Ipv6Addr>().unwrap()).to_le_bytes();
        let event=EndpointCandidate {endpoint:9,pid:42,timestamp:100,event:1,layer:2,protocol:17,outbound:true,
            local_port:1000,remote_port:443,local_words:words("::ffff:192.0.2.1"),remote_words:words("::ffff:198.51.100.2")};
        assert!(registry.matches_candidate(&event));
        assert!(!registry.matches_candidate(&EndpointCandidate {pid:43,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {endpoint:10,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {remote_port:444,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {event:2,..event}));
        assert!(!registry.matches_candidate(&EndpointCandidate {timestamp:98,..event}));
        let packet=NetworkObservation {
            timestamp:110,outbound:true,sniffed:false,interface:7,sub_interface:2,
            meta:PacketMeta {flow:super::super::packet::FlowKey {
                source:local,destination:remote,transport:tuple.transport,interface:7,
            },payload_len:3,tcp_flags:None},transport_checksum_reported_valid:true,
        };
        let mut ledger=CandidateLedger::new(4,20).unwrap();
        ledger.observe(event);
        assert!(!registry.matches_packet_candidate(&ledger,&packet));
        let connect=EndpointCandidate {layer:3,event:4,timestamp:99,..event};
        ledger.observe(connect);
        assert!(registry.matches_packet_candidate(&ledger,&packet));
        let mut stale=CandidateLedger::new(4,20).unwrap();
        stale.observe(EndpointCandidate {timestamp:98,..connect});
        stale.observe(event);
        assert!(!registry.matches_packet_candidate(&stale,&packet));
        drop(lease);
        assert!(!registry.matches_packet_candidate(&ledger,&packet));
        assert!(!registry.matches_candidate(&event));
        assert!(registry.register(9,42,tuple,101).is_none());
        assert!(registry.register(10,42,EndpointTuple {remote:"198.51.100.2:444".parse().unwrap(),..tuple},101).is_none());
        registry.retire();
    }
    #[test]
    fn nonloopback_tcp_reflection_is_generation_bound_and_requires_handshake() {
        use std::net::SocketAddr;
        for v6 in [false,true] {
            let client:SocketAddr=if v6 {"[2001:db8::1]:1234"}else{"192.0.2.1:1234"}.parse().unwrap();
            let remote:SocketAddr=if v6 {"[2001:db8::2]:443"}else{"198.51.100.2:443"}.parse().unwrap();
            let listener=SocketAddr::new(client.ip(),49001);
            let peer=SocketAddr::new(remote.ip(),client.port());
            let mut raw=[0u8;80];
            raw[..8].copy_from_slice(&100i64.to_le_bytes());
            raw[8..12].copy_from_slice(&((1u32<<17)|if v6{1<<20}else{0}).to_le_bytes());
            raw[16..20].copy_from_slice(&7u32.to_le_bytes());
            raw[20..24].copy_from_slice(&2u32.to_le_bytes());
            let addr=Address::from_bytes(&raw);
            let packet=|a:SocketAddr,b:SocketAddr,seq:u32,ack:u32,flags:u8,payload:&[u8]| {
                let mut out=vec![0u8;if v6{60}else{40}];
                let off=if v6 {
                    out[0]=0x60;out[4..6].copy_from_slice(&((20+payload.len()) as u16).to_be_bytes());out[6]=6;
                    let (std::net::IpAddr::V6(a),std::net::IpAddr::V6(b))=(a.ip(),b.ip())else{panic!()};
                    out[8..24].copy_from_slice(&a.octets());out[24..40].copy_from_slice(&b.octets());40
                }else{
                    out[0]=0x45;out[2..4].copy_from_slice(&((40+payload.len()) as u16).to_be_bytes());out[9]=6;
                    let (std::net::IpAddr::V4(a),std::net::IpAddr::V4(b))=(a.ip(),b.ip())else{panic!()};
                    out[12..16].copy_from_slice(&a.octets());out[16..20].copy_from_slice(&b.octets());20
                };
                out[off..off+2].copy_from_slice(&a.port().to_be_bytes());out[off+2..off+4].copy_from_slice(&b.port().to_be_bytes());
                out[off+4..off+8].copy_from_slice(&seq.to_be_bytes());out[off+8..off+12].copy_from_slice(&ack.to_be_bytes());
                out[off+12]=0x50;out[off+13]=flags;out.extend_from_slice(payload);out
            };
            let mut table=TcpRedirectTable::new(1,4).unwrap();
            assert!(table.begin(&addr,&packet(client,remote,9,0,2,b"x"),listener).is_none());
            let syn=packet(client,remote,9,0,2,b"");
            let token=table.begin(&addr,&syn,listener).unwrap();
            assert_eq!(table.lookup(&addr,&syn),Some(token));
            assert_eq!(table.lookup(&addr,&packet(listener,peer,30,10,0x12,b"")),Some(token));
            assert!(table.begin(&addr,&syn,listener).is_none());
            let mut concurrent=TcpRedirectTable::new(2,4).unwrap();
            let client2=SocketAddr::new(client.ip(),client.port()+1);
            let listener2=SocketAddr::new(client.ip(),listener.port()+1);
            let peer2=SocketAddr::new(remote.ip(),client2.port());
            let syn2=packet(client2,remote,50,0,2,b"");
            let first=concurrent.begin(&addr,&syn,listener).unwrap();
            let second=concurrent.begin(&addr,&syn2,listener2).unwrap();
            assert_ne!(first,second);
            assert_eq!(concurrent.lookup(&addr,&syn2),Some(second));
            assert!(concurrent.reflect(first,&addr,&syn2).is_none());
            assert!(concurrent.reflect(second,&addr,&syn2).is_some());
            assert!(concurrent.reflect(first,&addr,&syn).is_some());
            assert!(concurrent.reflect(second,&addr,&packet(listener2,peer2,70,51,0x12,b"")).is_some());
            assert!(concurrent.reflect(first,&addr,&packet(listener,peer,30,10,0x12,b"")).is_some());
            assert!(concurrent.reflect(second,&addr,&packet(client2,remote,51,71,0x10,b"")).is_some());
            assert!(concurrent.reflect(first,&addr,&packet(client,remote,10,31,0x10,b"")).is_some());
            assert_eq!(concurrent.accept_captured(listener2,peer2),Some(second));
            assert_eq!(concurrent.accept_captured(listener,peer),Some(first));
            assert!(concurrent.complete(first));
            assert!(concurrent.reflect(first,&addr,&packet(client,remote,10,31,0x18,b"stale")).is_none());
            assert!(concurrent.reflect(second,&addr,&packet(client2,remote,51,71,0x18,b"live")).is_some());
            let mut collision=TcpRedirectTable::new(2,4).unwrap();
            collision.begin(&addr,&syn,listener).unwrap();
            assert!(collision.begin(&addr,&packet(listener,peer,44,0,2,b""),SocketAddr::new(client.ip(),49002)).is_none());
            assert!(!table.accept(token,listener,peer));
            let out=table.reflect(token,&addr,&syn).unwrap();
            let parsed=PacketMeta::parse(&out.packet,7).unwrap();
            assert_eq!(parsed.flow.source,peer);assert_eq!(parsed.flow.destination,listener);
            assert!(table.reflect(token,&addr,&packet(client,remote,10,0,0x10,b"x")).is_none());
            assert!(table.reflect(token,&addr,&packet(listener,peer,30,11,0x12,b"")).is_none());
            let out=table.reflect(token,&addr,&packet(listener,peer,30,10,0x12,b"")).unwrap();
            let parsed=PacketMeta::parse(&out.packet,7).unwrap();
            assert_eq!(parsed.flow.source,remote);assert_eq!(parsed.flow.destination,client);
            assert!(!table.accept(token,listener,remote));
            assert!(table.reflect(token,&addr,&packet(client,remote,10,31,0x10,b"")).is_some());
            assert_eq!(table.accept_captured(listener,peer),Some(token));
            assert_eq!(table.accept_captured(listener,peer),None);
            assert!(!table.accept(token,listener,peer));
            let data=packet(client,remote,10,31,0x18,b"hello");
            let out=table.reflect(token,&addr,&data).unwrap();
            assert!(out.packet.ends_with(b"hello"));
            let off=if v6{40}else{20};
            let pseudo=if v6{word_sum(&out.packet[8..40])}else{word_sum(&out.packet[12..20])};
            assert_eq!(checksum(pseudo+6+(out.packet.len()-off) as u32+word_sum(&out.packet[off..])),0);
            assert!(table.complete(token));
            assert!(table.lookup(&addr,&data).is_none());
            assert!(table.reflect(token,&addr,&data).is_none());
            assert!(table.begin(&addr,&syn,listener).is_none());
        }
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
