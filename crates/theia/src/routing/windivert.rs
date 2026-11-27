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
        if self.timestamp <= 0 || self.flags & 0xffff != 0
            || self.flags & ((1 << 18) | (1 << 19)) != 0
            || self.flags >> 24 != 0 || self.reserved != 0
            || packet.len() > MAX_PACKET
        {
            return Err(ParseError::Unsupported);
        }
        let interface = u32::from_le_bytes(self.data[..4].try_into().unwrap());
        let sub_interface = u32::from_le_bytes(self.data[4..8].try_into().unwrap());
        if interface == 0 { return Err(ParseError::Invalid); }
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
        use super::packet::Transport;
        use std::net::IpAddr;
        let n = address.network(packet).ok()?;
        let key = n.meta.flow;
        let valid = |ip: IpAddr| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
                && match ip {
                    IpAddr::V4(v) => v.octets()[0] != 0 && v.octets()[0] < 224,
                    IpAddr::V6(v) => !v.is_unicast_link_local() && v.to_ipv4_mapped().is_none(),
                }
        };
        if !n.outbound || n.sniffed || key.transport != Transport::Udp
            || key.source.ip() == key.destination.ip()
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
        Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE},
        System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
    };
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
    pub fn probe(directory: &Path, dll: [u8;32], sys: [u8;32], install_lab: bool) -> io::Result<()> {
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
        let open: Open = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Open>(GetProcAddress(library.0,c"WinDivertOpen".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
        let get: GetParam = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, GetParam>(GetProcAddress(library.0,c"WinDivertGetParam".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
        let close: Close = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Close>(GetProcAddress(library.0,c"WinDivertClose".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
        // Require ABI symbols needed for later packet and event processing
        // without exposing a production send/receive path prematurely.
        for symbol in [c"WinDivertRecvEx",c"WinDivertSendEx",c"WinDivertShutdown",c"WinDivertSetParam",c"WinDivertHelperCalcChecksums"] {
            if unsafe { GetProcAddress(library.0,symbol.as_ptr().cast()) }.is_none() {
                return Err(io::ErrorKind::Unsupported.into());
            }
        }
        let flags = 0x1 | 0x4 | if install_lab { 0 } else { 0x10 };
        for layer in [0,2,3] {
            let raw = unsafe { open(c"false".as_ptr(),layer,0,flags) };
            if raw == INVALID_HANDLE_VALUE || raw.is_null() { return Err(io::Error::last_os_error()); }
            let handle = Handle(raw,close);
            for param in [3,4] {
                let mut value = 0;
                if unsafe { get(handle.0,param,&mut value) } == 0 { return Err(io::Error::last_os_error()); }
                if value != 2 { return Err(io::ErrorKind::Unsupported.into()); }
            }
            handle.close()?;
        }
        Ok(())
    }
}
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use native::probe;

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
