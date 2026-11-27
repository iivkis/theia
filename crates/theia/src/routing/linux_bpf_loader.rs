//! Optional single-worker laboratory collector. The ELF object is pinned
//! by a trusted SHA-256 before loading; maps and links are never published.
//! No route authorization is derived from a parsed event alone.
use super::{
    linux_attribution::socket_cookie,
    linux_events::{CorroboratedFlow, KernelFlowEvent, KernelPacketEvent, PACKET_EVENT_SIZE},
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_int, c_long, c_void},
    fs::{self, File},
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    ptr::{self, NonNull},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use subtle::ConstantTimeEq;

const MAX_OBJECT: usize = 8 * 1024 * 1024;
const MAX_BUFFER: usize = 1024;
const MAX_CPUS: usize = 8192;
const CGROUP2_SUPER_MAGIC: i64 = 0x63677270;
const PROGRAMS: [&[u8]; 4] = [
    b"theia_connect4\0",
    b"theia_connect6\0",
    b"theia_sendmsg4\0",
    b"theia_sendmsg6\0",
];

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_mem(data: *const c_void, size: usize, opts: *const c_void) -> *mut c_void;
    fn bpf_object__load(object: *mut c_void) -> c_int;
    fn bpf_object__close(object: *mut c_void);
    fn bpf_object__find_program_by_name(object: *const c_void, name: *const c_char) -> *mut c_void;
    fn bpf_program__attach_cgroup(program: *const c_void, cgroup_fd: c_int) -> *mut c_void;
    fn bpf_program__set_autoload(program: *mut c_void, autoload: bool) -> c_int;
    fn bpf_link__destroy(link: *mut c_void) -> c_int;
    fn bpf_object__find_map_fd_by_name(object: *const c_void, name: *const c_char) -> c_int;
    fn libbpf_get_error(pointer: *const c_void) -> c_long;
    fn libbpf_num_possible_cpus() -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn ring_buffer__new(
        fd: c_int,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int,
        context: *mut c_void,
        opts: *const c_void,
    ) -> *mut c_void;
    fn ring_buffer__poll(ring: *mut c_void, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(ring: *mut c_void);
}

fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}
fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
fn checked_pointer(p: *mut c_void) -> io::Result<NonNull<c_void>> {
    let code = unsafe { libbpf_get_error(p) };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(-code).unwrap_or(libc::EINVAL),
        ));
    }
    NonNull::new(p).ok_or_else(denied)
}
fn result(code: c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else if code < 0 {
        Err(io::Error::from_raw_os_error(
            code.checked_neg().unwrap_or(libc::EINVAL),
        ))
    } else {
        Err(invalid())
    }
}
fn check_cgroup(cgroup: &File) -> io::Result<()> {
    let m = cgroup.metadata()?;
    let root = fs::metadata("/sys/fs/cgroup")?;
    let mut stat: libc::statfs = unsafe { mem::zeroed() };
    if unsafe { libc::fstatfs(cgroup.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.f_type as i64 != CGROUP2_SUPER_MAGIC
        || !m.is_dir()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || (m.dev(), m.ino()) == (root.dev(), root.ino())
    {
        return Err(denied());
    }
    Ok(())
}
fn check_object(bytes: &[u8], expected: [u8; 32]) -> io::Result<()> {
    if bytes.len() < 64
        || bytes.len() > MAX_OBJECT
        || !bytes.starts_with(b"\x7fELF")
        || expected == [0; 32]
    {
        return Err(invalid());
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if !bool::from(actual.ct_eq(&expected)) {
        return Err(denied());
    }
    Ok(())
}

struct Object(NonNull<c_void>);
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            bpf_object__close(self.0.as_ptr());
        }
    }
}
struct Link(NonNull<c_void>);
impl Drop for Link {
    fn drop(&mut self) {
        unsafe {
            bpf_link__destroy(self.0.as_ptr());
        }
    }
}
struct Ring(NonNull<c_void>);
impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            ring_buffer__free(self.0.as_ptr());
        }
    }
}

// Keep a private duplicate of the kernel loss-map FD alive with each event.
// A collector poll alone cannot establish that no event was lost since that
// poll. Recheck around corroboration, and permanently revoke on uncertainty.
struct LossMonitor {
    fd: OwnedFd,
    cpus: usize,
    live: Arc<AtomicBool>,
}
impl LossMonitor {
    fn new(fd: c_int, cpus: usize, live: Arc<AtomicBool>) -> io::Result<Self> {
        if cpus == 0 || cpus > MAX_CPUS {
            return Err(denied());
        }
        let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            cpus,
            live,
        })
    }
    fn check(&self) -> io::Result<()> {
        if !self.live.load(Ordering::Acquire) {
            return Err(denied());
        }
        let key = 0u32;
        // The pinned ELF declares a per-CPU u64 counter. libbpf's CPU
        // count is bounded at attach; the output is aligned and initialized.
        let mut losses = vec![0u64; self.cpus];
        let rc = unsafe {
            bpf_map_lookup_elem(
                self.fd.as_raw_fd(),
                (&key as *const u32).cast(),
                losses.as_mut_ptr().cast(),
            )
        };
        if rc != 0 || losses.iter().any(|count| *count != 0) {
            self.live.store(false, Ordering::Release);
            return Err(denied());
        }
        if !self.live.load(Ordering::Acquire) {
            return Err(denied());
        }
        Ok(())
    }
}

struct Buffer {
    queue: VecDeque<KernelFlowEvent>,
    failed: bool,
    live: Arc<AtomicBool>,
}
impl Buffer {
    fn poison(&mut self) {
        self.failed = true;
        self.live.store(false, Ordering::Release);
        self.queue.clear();
    }
    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.failed || !self.live.load(Ordering::Acquire) || self.queue.len() == MAX_BUFFER {
            self.poison();
            return Err(denied());
        }
        match KernelFlowEvent::parse(data) {
            Ok(event) => {
                self.queue.push_back(event);
                Ok(())
            }
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }
}
unsafe extern "C" fn sample(context: *mut c_void, data: *mut c_void, len: usize) -> c_int {
    // libbpf invokes the callback synchronously on the collector worker.
    // Reject invalid length before creating a slice, avoid unwinding.
    if context.is_null() {
        return -libc::EINVAL;
    }
    let state = unsafe { &mut *context.cast::<Buffer>() };
    if data.is_null() || len != 88 {
        state.poison();
        return -libc::EINVAL;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
    if state.push(bytes).is_ok() {
        0
    } else {
        -libc::ENOBUFS
    }
}

/// Proven private ring-buffer provenance, not proof of the sender of a
/// captured packet. Session close or any lost event invalidates all tokens.
pub struct CollectedEvent {
    event: KernelFlowEvent,
    loss: Arc<LossMonitor>,
}
/// A diagnostic capture proof borrows the actual queue packet and its
/// live collector event. It cannot be constructed from public parsed bytes,
/// copied into a later packet, or kept after the kernel verdict.
pub struct CapturedObservation<'a, 'queue> {
    event: &'a CollectedEvent,
    rules: &'a super::linux_rules::LabRules,
    packet: &'a super::nfqueue::Packet<'queue>,
    fd: i32,
    flow: CorroboratedFlow,
}

impl CapturedObservation<'_, '_> {
    pub fn flow(&self) -> CorroboratedFlow {
        self.flow
    }

    /// Revalidate the live socket, private ring and queue identity, and
    /// event age after any awaited work. Never upgrades sender attribution.
    pub fn revalidate(&self) -> io::Result<CorroboratedFlow> {
        let observed = self
            .event
            .corroborate_packet(self.rules, self.packet, self.fd)?;
        if observed != self.flow {
            return Err(denied());
        }
        Ok(observed)
    }
}

impl CollectedEvent {
    pub fn capture_observation<'a, 'queue>(
        &'a self,
        rules: &'a super::linux_rules::LabRules,
        packet: &'a super::nfqueue::Packet<'queue>,
        fd: i32,
    ) -> io::Result<CapturedObservation<'a, 'queue>> {
        let flow = self.corroborate_packet(rules, packet, fd)?;
        Ok(CapturedObservation {
            event: self,
            rules,
            packet,
            fd,
            flow,
        })
    }

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
        self.loss.check()?;
        let proof = rules.captured_socket(packet)?;
        if proof.cookie() != self.event.cookie {
            return Err(denied());
        }
        let flow = self.event.corroborate(fd)?;
        if flow.cookie() != proof.cookie()
            || flow.key() != proof.key()
            || rules.captured_socket(packet)? != proof
        {
            return Err(denied());
        }
        self.loss.check()?;
        self.event.fresh()?;
        Ok(flow)
    }

    pub fn corroborate_socket(
        &self,
        fd: i32,
        socket: &impl AsRawFd,
    ) -> io::Result<CorroboratedFlow> {
        self.loss.check()?;
        if socket_cookie(socket)? != self.event.cookie {
            return Err(denied());
        }
        let flow = self.event.corroborate(fd)?;
        if socket_cookie(socket)? != flow.cookie() {
            return Err(denied());
        }
        self.loss.check()?;
        self.event.fresh()?;
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
    loss: Arc<LossMonitor>,
}

impl Collector {
    /// Requires a trusted cgroup file descriptor and a digest from an
    /// independently approved build manifest, not from an untrusted ELF.
    /// No default/root cgroup attachment, pinning or external ring input.
    pub fn attach(bytes: &[u8], expected: [u8; 32], cgroup: &File) -> io::Result<Self> {
        check_object(bytes, expected)?;
        check_cgroup(cgroup)?;
        let object = Object(checked_pointer(unsafe {
            bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), ptr::null())
        })?);
        // The flow-only collector has no packet ring consumer.
        // Never attach or load the optional egress program here.
        let egress = unsafe {
            bpf_object__find_program_by_name(object.0.as_ptr(), c"theia_egress".as_ptr())
        };
        if egress.is_null() {
            return Err(denied());
        }
        result(unsafe { bpf_program__set_autoload(egress, false) })?;
        result(unsafe { bpf_object__load(object.0.as_ptr()) })?;
        let map_fd = |name: &[u8]| {
            let fd =
                unsafe { bpf_object__find_map_fd_by_name(object.0.as_ptr(), name.as_ptr().cast()) };
            if fd < 0 {
                Err(denied())
            } else {
                Ok(fd)
            }
        };
        let lost_fd = map_fd(b"lost_events\0")?;
        let ring_fd = map_fd(b"flow_events\0")?;
        let cpus = usize::try_from(unsafe { libbpf_num_possible_cpus() }).map_err(|_| denied())?;
        if cpus == 0 || cpus > MAX_CPUS {
            return Err(denied());
        }
        let live = Arc::new(AtomicBool::new(true));
        let loss = Arc::new(LossMonitor::new(lost_fd, cpus, live.clone())?);
        let mut buffer = Box::new(Buffer {
            queue: VecDeque::with_capacity(MAX_BUFFER),
            failed: false,
            live,
        });
        let ring = Ring(checked_pointer(unsafe {
            ring_buffer__new(
                ring_fd,
                sample,
                (&mut *buffer as *mut Buffer).cast(),
                ptr::null(),
            )
        })?);
        let mut links = Vec::with_capacity(PROGRAMS.len());
        for name in PROGRAMS {
            let program = unsafe {
                bpf_object__find_program_by_name(object.0.as_ptr(), name.as_ptr().cast())
            };
            if program.is_null() {
                return Err(denied());
            }
            links.push(Link(checked_pointer(unsafe {
                bpf_program__attach_cgroup(program, cgroup.as_raw_fd())
            })?));
        }
        let mut owner = Self {
            ring,
            _links: links,
            _object: object,
            buffer,
            loss,
        };
        owner.check_loss()?;
        Ok(owner)
    }
    fn check_loss(&mut self) -> io::Result<()> {
        if self.buffer.failed || self.loss.check().is_err() {
            self.buffer.poison();
            return Err(denied());
        }
        Ok(())
    }
    /// Blocking bounded poll; execute only on the dedicated collector worker.
    /// Loss is terminal for the entire session, not just for one event.
    pub fn poll(&mut self, timeout_ms: u32) -> io::Result<Option<CollectedEvent>> {
        let mut wait = timeout_ms;
        for _ in 0..MAX_BUFFER {
            let Some(record) = self.poll_record(wait)? else {
                return Ok(None);
            };
            if record.event.fresh().is_ok() {
                return Ok(Some(record));
            }
            wait = 0;
        }
        self.buffer.poison();
        Err(denied())
    }

    /// Keep stale records for the verdict collector's ambiguity
    /// tombstones. An expired event cannot grant access, but an observed
    /// conflicting sender must not disappear merely because it expired.
    fn poll_record(&mut self, timeout_ms: u32) -> io::Result<Option<CollectedEvent>> {
        if timeout_ms > 250 || !self.loss.live.load(Ordering::Acquire) {
            return Err(denied());
        }
        self.check_loss()?;
        if self.buffer.queue.is_empty() {
            let rc = unsafe { ring_buffer__poll(self.ring.0.as_ptr(), timeout_ms as c_int) };
            if rc < 0 {
                self.buffer.poison();
                return Err(io::Error::from_raw_os_error(
                    rc.checked_neg().unwrap_or(libc::EINVAL),
                ));
            }
        }
        self.check_loss()?;
        Ok(self.buffer.queue.pop_front().map(|event| CollectedEvent {
            event,
            loss: self.loss.clone(),
        }))
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.loss.live.store(false, Ordering::Release);
    }
}

/// Live pre-verdict reader for one explicitly owned, tagged socket.
/// Owns the private cgroup collector from before the socket was
/// connected. A flow record is not an authenticated sender identity;
/// this gate only narrows the existing socket proof and never upgrades
/// application evidence. No public raw-record insertion API.
pub struct VerdictCollector {
    collector: Collector,
    expected_cookie: u64,
    fd: i32,
    candidate: Option<CollectedEvent>,
    retired: bool,
}
impl VerdictCollector {
    pub fn new(collector: Collector, socket: &impl AsRawFd, fd: i32) -> io::Result<Self> {
        if fd < 0 {
            return Err(denied());
        }
        Ok(Self {
            collector,
            expected_cookie: socket_cookie(socket)?,
            fd,
            candidate: None,
            retired: false,
        })
    }

    fn observe(&mut self, record: CollectedEvent) -> io::Result<()> {
        if record.event.cookie != self.expected_cookie {
            return Ok(());
        }
        if let Some(previous) = &self.candidate {
            if !previous.event.same_actor(&record.event)
                || record.event.timestamp() < previous.event.timestamp()
            {
                self.retired = true;
                return Err(denied());
            }
        }
        self.candidate = Some(record);
        Ok(())
    }

    fn drain(&mut self) -> io::Result<()> {
        if self.retired {
            return Err(denied());
        }
        for _ in 0..MAX_BUFFER {
            match self.collector.poll_record(0) {
                Ok(Some(record)) => self.observe(record)?,
                Ok(None) => return Ok(()),
                Err(error) => {
                    self.retired = true;
                    return Err(error);
                }
            }
        }
        self.retired = true;
        Err(denied())
    }

    /// Called while the packet is held in NFQUEUE, both before and after
    /// policy evaluation. Drain the actual private ring, never the
    /// downstream cgroup_skb egress observations. A busy/overflowed or
    /// revoked session cannot silently fall back to a cached identity.
    pub(crate) fn verify(
        &mut self,
        rules: &super::linux_rules::LabRules,
        packet: &super::nfqueue::Packet<'_>,
        proof: super::linux_rules::CapturedSocket,
    ) -> io::Result<CorroboratedFlow> {
        if self.retired || proof.cookie() != self.expected_cookie {
            return Err(denied());
        }
        self.drain()?;
        let candidate = self.candidate.as_ref().ok_or_else(denied)?;
        let actor = candidate.event;
        let observed = candidate.corroborate_packet(rules, packet, self.fd)?;
        // Hashing /proc/PID/exe may take time. Consume newly arrived
        // competing events before allowing this diagnostic gate to
        // succeed. The final kernel verdict remains separately guarded.
        self.drain()?;
        let current = self.candidate.as_ref().ok_or_else(denied)?;
        current.loss.check()?;
        current.event.fresh()?;
        if !current.event.same_actor(&actor)
            || observed.cookie() != proof.cookie()
            || observed.key() != proof.key()
            || rules.captured_socket(packet)? != proof
        {
            self.retired = true;
            return Err(denied());
        }
        Ok(observed)
    }
}

// Separate collector for actual cgroup egress skb observations. Its
// private ring cannot be fed by the public packet parser. It is not
// a pre-verdict NFQUEUE packet proof, and cannot authorize a route.
struct PacketBuffer {
    queue: VecDeque<KernelPacketEvent>,
    live: Arc<AtomicBool>,
}
impl PacketBuffer {
    fn poison(&mut self) {
        self.live.store(false, Ordering::Release);
        self.queue.clear();
    }
    fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        if !self.live.load(Ordering::Acquire) || self.queue.len() >= MAX_BUFFER {
            self.poison();
            return Err(denied());
        }
        match KernelPacketEvent::parse(bytes) {
            Ok(event) => {
                self.queue.push_back(event);
                Ok(())
            }
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }
}
unsafe extern "C" fn packet_sample(context: *mut c_void, data: *mut c_void, len: usize) -> c_int {
    if context.is_null() {
        return -libc::EINVAL;
    }
    let buffer = unsafe { &mut *context.cast::<PacketBuffer>() };
    if data.is_null() || len != PACKET_EVENT_SIZE {
        buffer.poison();
        return -libc::EINVAL;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
    if buffer.push(bytes).is_ok() {
        0
    } else {
        -libc::ENOBUFS
    }
}

pub struct CollectedPacket {
    event: KernelPacketEvent,
    loss: Arc<LossMonitor>,
}
impl CollectedPacket {
    /// Returns only kernel socket identity and observed L3/L4 tuple.
    /// Same cookie from a live descriptor corroborates the socket, not
    /// the task that called send (shared sockets, retransmits, softirq).
    pub fn observation(&self) -> io::Result<KernelPacketEvent> {
        self.loss.check()?;
        self.event.fresh()?;
        Ok(self.event)
    }
    pub fn corroborate_socket(&self, socket: &impl AsRawFd) -> io::Result<KernelPacketEvent> {
        let event = self.observation()?;
        if socket_cookie(socket)? != event.cookie() {
            return Err(denied());
        }
        self.loss.check()?;
        event.fresh()?;
        Ok(event)
    }
    /// Correlation is diagnostic only. Both independently pinned
    /// collector sessions must remain live and both records fresh.
    pub fn corroborate_flow(&self, flow: &CollectedEvent, fd: i32) -> io::Result<CorroboratedFlow> {
        let event = self.observation()?;
        flow.loss.check()?;
        if !event.matches_flow(&flow.event) {
            return Err(denied());
        }
        let observed = flow.event.corroborate(fd)?;
        let mut key = event.key();
        key.interface = 0;
        if observed.key() != key || observed.cookie() != event.cookie() {
            return Err(denied());
        }
        flow.loss.check()?;
        flow.event.fresh()?;
        self.loss.check()?;
        event.fresh()?;
        Ok(observed)
    }
}

pub struct PacketCollector {
    ring: Ring,
    _link: Link,
    _object: Object,
    buffer: Box<PacketBuffer>,
    loss: Arc<LossMonitor>,
}
impl PacketCollector {
    /// Requires an explicitly selected root-owned non-root cgroup and
    /// independently pinned ELF; does not attach to host by default.
    pub fn attach(bytes: &[u8], expected: [u8; 32], cgroup: &File) -> io::Result<Self> {
        check_object(bytes, expected)?;
        check_cgroup(cgroup)?;
        let object = Object(checked_pointer(unsafe {
            bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), ptr::null())
        })?);
        for name in PROGRAMS {
            let program = unsafe {
                bpf_object__find_program_by_name(object.0.as_ptr(), name.as_ptr().cast())
            };
            if program.is_null() {
                return Err(denied());
            }
            result(unsafe { bpf_program__set_autoload(program, false) })?;
        }
        let program = unsafe {
            bpf_object__find_program_by_name(object.0.as_ptr(), c"theia_egress".as_ptr())
        };
        if program.is_null() {
            return Err(denied());
        }
        result(unsafe { bpf_object__load(object.0.as_ptr()) })?;
        let map = |name: &[u8]| -> io::Result<c_int> {
            let fd =
                unsafe { bpf_object__find_map_fd_by_name(object.0.as_ptr(), name.as_ptr().cast()) };
            if fd < 0 {
                Err(denied())
            } else {
                Ok(fd)
            }
        };
        let cpus = usize::try_from(unsafe { libbpf_num_possible_cpus() }).map_err(|_| denied())?;
        let live = Arc::new(AtomicBool::new(true));
        let loss = Arc::new(LossMonitor::new(
            map(b"lost_events\0")?,
            cpus,
            live.clone(),
        )?);
        let mut buffer = Box::new(PacketBuffer {
            queue: VecDeque::with_capacity(MAX_BUFFER),
            live,
        });
        let ring = Ring(checked_pointer(unsafe {
            ring_buffer__new(
                map(b"packet_events\0")?,
                packet_sample,
                (&mut *buffer as *mut PacketBuffer).cast(),
                ptr::null(),
            )
        })?);
        let link = Link(checked_pointer(unsafe {
            bpf_program__attach_cgroup(program, cgroup.as_raw_fd())
        })?);
        loss.check()?;
        Ok(Self {
            ring,
            _link: link,
            _object: object,
            buffer,
            loss,
        })
    }
    pub fn poll(&mut self, timeout_ms: u32) -> io::Result<Option<CollectedPacket>> {
        if timeout_ms > 250 {
            return Err(denied());
        }
        if self.loss.check().is_err() {
            self.buffer.poison();
            return Err(denied());
        }
        if self.buffer.queue.is_empty() {
            let status = unsafe { ring_buffer__poll(self.ring.0.as_ptr(), timeout_ms as c_int) };
            if status < 0 {
                self.buffer.poison();
                return Err(io::Error::from_raw_os_error(
                    status.checked_neg().unwrap_or(libc::EINVAL),
                ));
            }
        }
        if self.loss.check().is_err() {
            self.buffer.poison();
            return Err(denied());
        }
        while let Some(event) = self.buffer.queue.pop_front() {
            if event.fresh().is_ok() {
                return Ok(Some(CollectedPacket {
                    event,
                    loss: self.loss.clone(),
                }));
            }
        }
        Ok(None)
    }
}
impl Drop for PacketCollector {
    fn drop(&mut self) {
        self.buffer.poison();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_callback_records_are_bounded_and_loss_revokes_queued_evidence() {
        let mut flow = [0u8; 88];
        for offset in [0, 8, 16, 24] {
            flow[offset..offset+8].copy_from_slice(&1u64.to_ne_bytes());
        }
        flow[32..40].copy_from_slice(&0x1_0000_0001u64.to_ne_bytes());
        flow[48..52].copy_from_slice(&4u32.to_ne_bytes());
        flow[52..56].copy_from_slice(&17u32.to_ne_bytes());
        flow[56..60].copy_from_slice(&1u32.to_ne_bytes());
        flow[64..68].copy_from_slice(&[192, 0, 2, 1]);
        flow[80..82].copy_from_slice(&443u16.to_ne_bytes());
        let live = Arc::new(AtomicBool::new(true));
        let mut buffer = Buffer { queue: VecDeque::new(), failed: false, live: live.clone() };
        assert_eq!(unsafe { sample(ptr::null_mut(), flow.as_mut_ptr().cast(), flow.len()) }, -libc::EINVAL);
        for _ in 0..MAX_BUFFER {
            assert_eq!(unsafe { sample((&mut buffer as *mut Buffer).cast(), flow.as_mut_ptr().cast(), flow.len()) }, 0);
        }
        assert_eq!(buffer.queue.len(), MAX_BUFFER);
        assert_eq!(unsafe { sample((&mut buffer as *mut Buffer).cast(), flow.as_mut_ptr().cast(), flow.len()) }, -libc::ENOBUFS);
        assert!(buffer.queue.is_empty());
        assert!(!live.load(Ordering::Acquire));
        assert!(buffer.push(&flow).is_err());

        let mut packet = [0u8; PACKET_EVENT_SIZE];
        packet[0..8].copy_from_slice(&1u64.to_ne_bytes());
        packet[8..16].copy_from_slice(&1u64.to_ne_bytes());
        packet[16..20].copy_from_slice(&4u32.to_ne_bytes());
        packet[20..24].copy_from_slice(&17u32.to_ne_bytes());
        packet[24..28].copy_from_slice(&1u32.to_ne_bytes());
        packet[28..32].copy_from_slice(&28u32.to_ne_bytes());
        packet[32..36].copy_from_slice(&[192, 0, 2, 2]);
        packet[48..52].copy_from_slice(&[192, 0, 2, 1]);
        packet[64..66].copy_from_slice(&40000u16.to_ne_bytes());
        packet[66..68].copy_from_slice(&443u16.to_ne_bytes());
        let live = Arc::new(AtomicBool::new(true));
        let mut buffer = PacketBuffer { queue: VecDeque::new(), live: live.clone() };
        assert_eq!(unsafe { packet_sample(ptr::null_mut(), packet.as_mut_ptr().cast(), packet.len()) }, -libc::EINVAL);
        for _ in 0..MAX_BUFFER {
            assert_eq!(unsafe { packet_sample((&mut buffer as *mut PacketBuffer).cast(), packet.as_mut_ptr().cast(), packet.len()) }, 0);
        }
        assert_eq!(buffer.queue.len(), MAX_BUFFER);
        assert_eq!(unsafe { packet_sample((&mut buffer as *mut PacketBuffer).cast(), packet.as_mut_ptr().cast(), packet.len()) }, -libc::ENOBUFS);
        assert!(!live.load(Ordering::Acquire));
        assert!(buffer.queue.is_empty());
        assert!(buffer.push(&packet).is_err());
    }

    #[test]
    fn libbpf_error_and_cgroup_validation_fail_closed_before_attachment() {
        assert!(result(0).is_ok());
        assert_eq!(result(-libc::EPERM).unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(result(1).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(result(i32::MIN).unwrap_err().raw_os_error(), Some(libc::EINVAL));
        assert!(checked_pointer(ptr::null_mut()).is_err());
        // The kernel root cgroup is explicitly forbidden; /dev/null is not
        // a cgroup at all. Neither check attaches anything to the host.
        assert!(check_cgroup(&File::open("/sys/fs/cgroup").unwrap()).is_err());
        assert!(check_cgroup(&File::open("/dev/null").unwrap()).is_err());
        assert!(LossMonitor::new(-1, 0, Arc::new(AtomicBool::new(true))).is_err());
        assert!(LossMonitor::new(-1, 1, Arc::new(AtomicBool::new(true))).is_err());
    }

    #[test]
    fn malformed_packet_callback_revokes_packet_session() {
        let live = Arc::new(AtomicBool::new(true));
        let mut buffer = PacketBuffer {
            queue: VecDeque::new(),
            live: live.clone(),
        };
        assert!(buffer.push(&[0; PACKET_EVENT_SIZE]).is_err());
        assert!(!live.load(Ordering::Acquire));
        assert_eq!(
            unsafe {
                packet_sample(
                    (&mut buffer as *mut PacketBuffer).cast(),
                    ptr::null_mut(),
                    PACKET_EVENT_SIZE,
                )
            },
            -libc::EINVAL
        );
    }
    #[test]
    fn rejects_wrong_object_before_libbpf() {
        let mut object = [0u8; 64];
        object[..4].copy_from_slice(b"\x7fELF");
        assert!(check_object(&object, [1; 32]).is_err());
        assert!(check_object(&object, Sha256::digest(object).into()).is_ok());
        object[0] = 0;
        assert!(check_object(&object, Sha256::digest(object).into()).is_err());
    }
    #[test]
    fn malformed_ring_record_poison_is_permanent() {
        let live = Arc::new(AtomicBool::new(true));
        let mut buffer = Buffer {
            queue: VecDeque::with_capacity(MAX_BUFFER),
            failed: false,
            live: live.clone(),
        };
        assert!(buffer.push(&[0; 88]).is_err());
        assert!(buffer.failed);
        assert!(!live.load(Ordering::Acquire));
        assert!(buffer.push(&[0; 88]).is_err());
    }

    #[test]
    fn malformed_callback_revokes_already_issued_events() {
        let live = Arc::new(AtomicBool::new(true));
        let mut buffer = Buffer {
            queue: VecDeque::new(),
            failed: false,
            live: live.clone(),
        };
        let rc = unsafe { sample((&mut buffer as *mut Buffer).cast(), ptr::null_mut(), 88) };
        assert_eq!(rc, -libc::EINVAL);
        assert!(buffer.failed);
        assert!(!live.load(Ordering::Acquire));
    }

    #[test]
    fn unreadable_loss_map_revokes_shared_session() {
        let live = Arc::new(AtomicBool::new(true));
        let file = File::open("/dev/null").unwrap();
        let monitor = LossMonitor::new(file.as_raw_fd(), 1, live.clone()).unwrap();
        drop(file);
        assert!(monitor.check().is_err());
        assert!(!live.load(Ordering::Acquire));
        assert!(monitor.check().is_err());
    }
}
