//! Optional single-worker laboratory collector. The ELF object is pinned
//! by a trusted SHA-256 before loading; maps and links are never published.
//! No route authorization is derived from a parsed event alone.
use super::{linux_events::{CorroboratedFlow, KernelFlowEvent}, linux_attribution::socket_cookie};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_int, c_long, c_void},
    fs::{self, File},
    io, mem,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    ptr::{self, NonNull},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};
use subtle::ConstantTimeEq;

const MAX_OBJECT: usize = 8 * 1024 * 1024;
const MAX_BUFFER: usize = 1024;
const MAX_CPUS: usize = 8192;
const CGROUP2_SUPER_MAGIC: i64 = 0x63677270;
const PROGRAMS: [&[u8]; 4] = [
    b"theia_connect4\0", b"theia_connect6\0", b"theia_sendmsg4\0", b"theia_sendmsg6\0",
];

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_mem(data: *const c_void, size: usize, opts: *const c_void) -> *mut c_void;
    fn bpf_object__load(object: *mut c_void) -> c_int;
    fn bpf_object__close(object: *mut c_void);
    fn bpf_object__find_program_by_name(object: *const c_void, name: *const c_char) -> *mut c_void;
    fn bpf_program__attach_cgroup(program: *const c_void, cgroup_fd: c_int) -> *mut c_void;
    fn bpf_link__destroy(link: *mut c_void) -> c_int;
    fn bpf_object__find_map_fd_by_name(object: *const c_void, name: *const c_char) -> c_int;
    fn libbpf_get_error(pointer: *const c_void) -> c_long;
    fn libbpf_num_possible_cpus() -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn ring_buffer__new(fd: c_int, callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int,
        context: *mut c_void, opts: *const c_void) -> *mut c_void;
    fn ring_buffer__poll(ring: *mut c_void, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(ring: *mut c_void);
}

fn denied() -> io::Error { io::Error::from(io::ErrorKind::PermissionDenied) }
fn invalid() -> io::Error { io::Error::from(io::ErrorKind::InvalidData) }
fn checked_pointer(p: *mut c_void) -> io::Result<NonNull<c_void>> {
    let code = unsafe { libbpf_get_error(p) };
    if code != 0 { return Err(io::Error::from_raw_os_error(i32::try_from(-code).unwrap_or(libc::EINVAL))); }
    NonNull::new(p).ok_or_else(denied)
}
fn result(code: c_int) -> io::Result<()> {
    if code == 0 { Ok(()) } else if code < 0 { Err(io::Error::from_raw_os_error(code.checked_neg().unwrap_or(libc::EINVAL))) } else { Err(invalid()) }
}
fn check_cgroup(cgroup: &File) -> io::Result<()> {
    let m = cgroup.metadata()?;
    let root = fs::metadata("/sys/fs/cgroup")?;
    let mut stat: libc::statfs = unsafe { mem::zeroed() };
    if unsafe { libc::fstatfs(cgroup.as_raw_fd(), &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
    if stat.f_type as i64 != CGROUP2_SUPER_MAGIC || !m.is_dir()
        || m.uid() != 0 || m.mode() & 0o022 != 0
        || (m.dev(), m.ino()) == (root.dev(), root.ino()) {
        return Err(denied());
    }
    Ok(())
}
fn check_object(bytes: &[u8], expected: [u8;32]) -> io::Result<()> {
    if bytes.len() < 64 || bytes.len() > MAX_OBJECT || !bytes.starts_with(b"\x7fELF") || expected == [0;32] {
        return Err(invalid());
    }
    let actual: [u8;32] = Sha256::digest(bytes).into();
    if !bool::from(actual.ct_eq(&expected)) { return Err(denied()); }
    Ok(())
}

struct Object(NonNull<c_void>);
impl Drop for Object { fn drop(&mut self) { unsafe { bpf_object__close(self.0.as_ptr()); } } }
struct Link(NonNull<c_void>);
impl Drop for Link { fn drop(&mut self) { unsafe { bpf_link__destroy(self.0.as_ptr()); } } }
struct Ring(NonNull<c_void>);
impl Drop for Ring { fn drop(&mut self) { unsafe { ring_buffer__free(self.0.as_ptr()); } } }

struct Buffer {
    queue: VecDeque<KernelFlowEvent>,
    failed: bool,
}
impl Buffer {
    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.failed || self.queue.len() == MAX_BUFFER { self.failed = true; return Err(denied()); }
        match KernelFlowEvent::parse(data) {
            Ok(event) => { self.queue.push_back(event); Ok(()) }
            Err(error) => { self.failed = true; Err(error) }
        }
    }
}
unsafe extern "C" fn sample(context: *mut c_void, data: *mut c_void, len: usize) -> c_int {
    // libbpf invokes the callback synchronously on the collector worker.
    // Reject invalid length before creating a slice, avoid unwinding.
    if context.is_null() || data.is_null() || len != 88 { return -libc::EINVAL; }
    let state = unsafe { &mut *context.cast::<Buffer>() };
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
    if state.push(bytes).is_ok() { 0 } else { -libc::ENOBUFS }
}

/// Proven private ring-buffer provenance, not proof of the sender of a
/// captured packet. Session close or any lost event invalidates all tokens.
pub struct CollectedEvent {
    event: KernelFlowEvent,
    live: Arc<AtomicBool>,
}
impl CollectedEvent {
    /// Correlate a live collector event with an actual packet selected
    /// by the dedicated kernel socket rule. A matching tuple alone is
    /// insufficient: the private queue proof and kernel cookie must agree.
    /// Shared-socket sender attribution remains diagnostic.
    pub fn corroborate_packet(
        &self,
        rules: &super::linux_rules::LabRules,
        packet: &super::nfqueue::Packet<'_>,
        fd: i32,
    ) -> io::Result<CorroboratedFlow> {
        if !self.live.load(Ordering::Acquire) { return Err(denied()); }
        let proof = rules.captured_socket(packet)?;
        if proof.cookie() != self.event.cookie { return Err(denied()); }
        let flow = self.event.corroborate(fd)?;
        if flow.cookie() != proof.cookie() || flow.key() != proof.key()
            || !self.live.load(Ordering::Acquire) || rules.captured_socket(packet)? != proof {
            return Err(denied());
        }
        Ok(flow)
    }

    pub fn corroborate_socket(&self, fd: i32, socket: &impl AsRawFd) -> io::Result<CorroboratedFlow> {
        if !self.live.load(Ordering::Acquire) || socket_cookie(socket)? != self.event.cookie {
            return Err(denied());
        }
        let flow = self.event.corroborate(fd)?;
        if !self.live.load(Ordering::Acquire) || socket_cookie(socket)? != flow.cookie() { return Err(denied()); }
        Ok(flow)
    }
}

/// Dedicated non-Send worker owner. Fields drop in dependency order:
/// ring, links, object, then callback storage.
pub struct Collector {
    ring: Ring,
    _links: Vec<Link>,
    _object: Object,
    buffer: Box<Buffer>,
    lost_fd: c_int,
    losses: Vec<u64>,
    live: Arc<AtomicBool>,
}

impl Collector {
    /// Requires a trusted cgroup file descriptor and a digest from an
    /// independently approved build manifest, not from an untrusted ELF.
    /// No default/root cgroup attachment, pinning or external ring input.
    pub fn attach(bytes: &[u8], expected: [u8;32], cgroup: &File) -> io::Result<Self> {
        check_object(bytes, expected)?;
        check_cgroup(cgroup)?;
        let object = Object(checked_pointer(unsafe {
            bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), ptr::null())
        })?);
        result(unsafe { bpf_object__load(object.0.as_ptr()) })?;
        let map_fd = |name: &[u8]| {
            let fd = unsafe { bpf_object__find_map_fd_by_name(object.0.as_ptr(), name.as_ptr().cast()) };
            if fd < 0 { Err(denied()) } else { Ok(fd) }
        };
        let lost_fd = map_fd(b"lost_events\0")?;
        let ring_fd = map_fd(b"flow_events\0")?;
        let cpus = usize::try_from(unsafe { libbpf_num_possible_cpus() }).map_err(|_| denied())?;
        if cpus == 0 || cpus > MAX_CPUS { return Err(denied()); }
        let mut buffer = Box::new(Buffer { queue: VecDeque::with_capacity(MAX_BUFFER), failed: false });
        let ring = Ring(checked_pointer(unsafe { ring_buffer__new(ring_fd, sample,
            (&mut *buffer as *mut Buffer).cast(), ptr::null()) })?);
        let mut links = Vec::with_capacity(PROGRAMS.len());
        for name in PROGRAMS {
            let program = unsafe { bpf_object__find_program_by_name(object.0.as_ptr(), name.as_ptr().cast()) };
            if program.is_null() { return Err(denied()); }
            links.push(Link(checked_pointer(unsafe { bpf_program__attach_cgroup(program, cgroup.as_raw_fd()) })?));
        }
        let mut owner = Self { ring, _links: links, _object: object, buffer, lost_fd, losses: vec![0; cpus], live: Arc::new(AtomicBool::new(true)) };
        owner.check_loss()?;
        Ok(owner)
    }
    fn check_loss(&mut self) -> io::Result<()> {
        let key = 0u32;
        let rc = unsafe { bpf_map_lookup_elem(self.lost_fd, (&key as *const u32).cast(), self.losses.as_mut_ptr().cast()) };
        if rc != 0 || self.losses.iter().any(|count| *count != 0) || self.buffer.failed {
            self.live.store(false, Ordering::Release);
            self.buffer.queue.clear();
            return Err(denied());
        }
        Ok(())
    }
    /// Blocking bounded poll; execute only on the dedicated collector worker.
    /// Loss is terminal for the entire session, not just for one event.
    pub fn poll(&mut self, timeout_ms: u32) -> io::Result<Option<CollectedEvent>> {
        if timeout_ms > 250 || !self.live.load(Ordering::Acquire) { return Err(denied()); }
        self.check_loss()?;
        if self.buffer.queue.is_empty() {
            let rc = unsafe { ring_buffer__poll(self.ring.0.as_ptr(), timeout_ms as c_int) };
            if rc < 0 {
                self.live.store(false, Ordering::Release);
                self.buffer.queue.clear();
                return Err(io::Error::from_raw_os_error(rc.checked_neg().unwrap_or(libc::EINVAL)));
            }
        }
        self.check_loss()?;
        while let Some(event) = self.buffer.queue.pop_front() {
            if event.fresh().is_ok() { return Ok(Some(CollectedEvent { event, live: self.live.clone() })); }
        }
        Ok(None)
    }
}
impl Drop for Collector {
    fn drop(&mut self) { self.live.store(false, Ordering::Release); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_wrong_object_before_libbpf() {
        let mut object = [0u8;64];
        object[..4].copy_from_slice(b"\x7fELF");
        assert!(check_object(&object, [1;32]).is_err());
        assert!(check_object(&object, Sha256::digest(object).into()).is_ok());
        object[0] = 0;
        assert!(check_object(&object, Sha256::digest(object).into()).is_err());
    }
    #[test]
    fn malformed_ring_record_poison_is_permanent() {
        let mut buffer = Buffer { queue: VecDeque::with_capacity(MAX_BUFFER), failed: false };
        assert!(buffer.push(&[0;88]).is_err());
        assert!(buffer.failed);
        assert!(buffer.push(&[0;88]).is_err());
    }
}
