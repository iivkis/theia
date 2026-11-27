//! WinDivert 2.2.2 is the target Windows transport. The ABI is defined
//! independently from the upstream C header, not linked to a custom SYS.
//! NETWORK metadata never authenticates an application or a socket.
//! The probe only opens match-none read-only handles; it cannot set ready.
use super::packet::{PacketMeta, ParseError};
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
        let open: Open = unsafe { std::mem::transmute(GetProcAddress(library.0,c"WinDivertOpen".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
        let get: GetParam = unsafe { std::mem::transmute(GetProcAddress(library.0,c"WinDivertGetParam".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
        let close: Close = unsafe { std::mem::transmute(GetProcAddress(library.0,c"WinDivertClose".as_ptr().cast()).ok_or(io::ErrorKind::Unsupported)?) };
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
