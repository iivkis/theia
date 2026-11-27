//! Linux NFQUEUE transport using the kernel NETLINK_NETFILTER UAPI.
//! No nftables rules are installed here. Opening a queue is not proof of
//! system ingress readiness; Redirect/Modify require a higher-layer adapter.
//! Dropping an undecided packet sends NF_DROP. Closing a failed queue leaves
//! externally owned non-bypass queue rules fail-closed.
use super::{packet::PacketMeta, PacketAction};
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

const HEADER: usize = 16;
const NFGEN: usize = 4;
const MAX_MESSAGE: usize = 128 * 1024;
const SUBSYS: u16 = 3 << 8;
const PACKET: u16 = SUBSYS;
const VERDICT: u16 = SUBSYS | 1;
const CONFIG: u16 = SUBSYS | 2;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const ERROR: u16 = 2;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
fn native16(data: &[u8]) -> u16 {
    u16::from_ne_bytes(data.try_into().expect("checked field"))
}
fn native32(data: &[u8]) -> u32 {
    u32::from_ne_bytes(data.try_into().expect("checked field"))
}
fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data.try_into().expect("checked field"))
}
pub(super) fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub(super) fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    let len16 = u16::try_from(len).expect("fixed bounded command");
    out.extend_from_slice(&len16.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(align4(out.len()), 0);
}
pub(super) fn message(kind: u16, flags: u16, sequence: u32, queue: u16, attrs: &[u8]) -> Vec<u8> {
    let len = HEADER + NFGEN + attrs.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // kernel assigns the sender port
    out.extend_from_slice(&[0, 0]); // AF_UNSPEC, nfnetlink v0
    out.extend_from_slice(&queue.to_be_bytes());
    out.extend_from_slice(attrs);
    out
}
pub(super) fn checked_header(data: &[u8]) -> io::Result<(u16, u32, &[u8])> {
    let header = data.get(..HEADER).ok_or_else(invalid)?;
    let len = native32(&header[..4]) as usize;
    // NFQUEUE uses skb_zerocopy for its final payload, so the kernel
    // can report an exact, unaligned nlmsg_len and datagram length.
    if len < HEADER || (len != data.len() && align4(len) != data.len()) {
        return Err(invalid());
    }
    let body = data.get(HEADER..len).ok_or_else(invalid)?;
    Ok((native16(&header[4..6]), native32(&header[8..12]), body))
}
pub(super) fn next_attr<'a>(rest: &mut &'a [u8]) -> io::Result<Option<(u16, &'a [u8])>> {
    if rest.is_empty() {
        return Ok(None);
    }
    let header = rest.get(..4).ok_or_else(invalid)?;
    let len = usize::from(native16(&header[..2]));
    if len < 4 || align4(len) > rest.len() {
        return Err(invalid());
    }
    let kind = native16(&header[2..4]) & 0x3fff;
    let value = &rest[4..len];
    *rest = &rest[align4(len)..];
    Ok(Some((kind, value)))
}

struct Captured {
    id: u32,
    bytes: Vec<u8>,
    meta: Option<PacketMeta>,
    checksum_pending: bool,
    local_output: bool,
}
// The kernel's final NFQA_PAYLOAD is attached without tail padding.
fn next_packet_attr<'a>(rest: &mut &'a [u8]) -> io::Result<Option<(u16, &'a [u8])>> {
    if let Some(header) = rest.get(..4) {
        let len = usize::from(native16(&header[..2]));
        let kind = native16(&header[2..4]) & 0x3fff;
        if kind == 10 && len == rest.len() && len >= 4 {
            let value = &rest[4..];
            *rest = &[];
            return Ok(Some((kind, value)));
        }
    }
    next_attr(rest)
}

fn decode(data: &[u8], queue: u16) -> io::Result<Captured> {
    let (kind, _, body) = checked_header(data)?;
    let nfgen = body.get(..NFGEN).ok_or_else(invalid)?;
    if kind != PACKET || nfgen[1] != 0 || u16::from_be_bytes([nfgen[2], nfgen[3]]) != queue {
        return Err(invalid());
    }
    let mut rest = &body[NFGEN..];
    let (mut id, mut payload, mut captured_len, mut skb, mut input, mut output) =
        (None, None, None, None, None, None);
    let mut ethertype = 0;
    let mut local_output = false;
    while let Some((kind, value)) = next_packet_attr(&mut rest)? {
        match kind {
            1 if id.is_none() && value.len() == 7 => {
                id = Some(be32(&value[..4]));
                ethertype = u16::from_be_bytes([value[4], value[5]]);
                local_output = value[6] == 3; // NF_INET_LOCAL_OUT
            }
            5 if input.is_none() && value.len() == 4 => input = Some(be32(value)),
            6 if output.is_none() && value.len() == 4 => output = Some(be32(value)),
            10 if payload.is_none() => payload = Some(value),
            13 if captured_len.is_none() && value.len() == 4 => {
                captured_len = Some(be32(value) as usize)
            }
            14 if skb.is_none() && value.len() == 4 => skb = Some(be32(value)),
            1 | 5 | 6 | 10 | 13 | 14 => return Err(invalid()),
            _ => {}
        }
    }
    let id = id.ok_or_else(invalid)?;
    let bytes = payload.unwrap_or_default();
    let skb = skb.unwrap_or(0);
    let family_ok = matches!(
        (nfgen[0], ethertype, bytes.first().map(|b| b >> 4)),
        (2, 0x0800, Some(4)) | (10, 0x86dd, Some(6))
    );
    let complete = captured_len.is_none_or(|len| len == bytes.len());
    let meta = if family_ok && complete && skb & 2 == 0 && skb & !7 == 0 {
        PacketMeta::parse(bytes, output.or(input).unwrap_or(0)).ok()
    } else {
        None
    };
    Ok(Captured {
        id,
        bytes: bytes.to_vec(),
        meta,
        checksum_pending: skb & 5 != 0,
        local_output,
    })
}

pub(super) fn kernel_address() -> libc::sockaddr_nl {
    // All padding and groups are zero; no multicast subscription.
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address
}
pub(super) fn send(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let kernel = kernel_address();
    let sent = unsafe {
        libc::sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != bytes.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}
pub(super) fn receive(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let mut sender = kernel_address();
    let mut len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let read = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC,
            (&mut sender as *mut libc::sockaddr_nl).cast(),
            &mut len,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read == 0
        || read as usize > buffer.len()
        || len as usize != mem::size_of::<libc::sockaddr_nl>()
        || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || sender.nl_pid != 0
        || sender.nl_groups != 0
    {
        return Err(invalid());
    }
    Ok(read as usize)
}
fn configure(fd: RawFd, queue: u16, seq: u32, attrs: &[u8], buffer: &mut [u8]) -> io::Result<()> {
    send(fd, &message(CONFIG, REQUEST | ACK, seq, queue, attrs))?;
    let n = receive(fd, buffer)?;
    let (kind, received_seq, body) = checked_header(&buffer[..n])?;
    if kind != ERROR || received_seq != seq || body.len() < 4 + HEADER {
        return Err(invalid());
    }
    let errno = i32::from_ne_bytes(body[..4].try_into().map_err(|_| invalid())?);
    match errno {
        0 => Ok(()),
        i32::MIN => Err(invalid()),
        n if n < 0 => Err(io::Error::from_raw_os_error(-n)),
        _ => Err(invalid()),
    }
}

/// A single exclusive kernel queue, configured without FAIL_OPEN or GSO.
/// The owner must use an external guarded rule transaction. This low-level
/// API does not activate or recover system firewall rules.
pub struct Queue {
    fd: Option<OwnedFd>,
    number: u16,
    namespace: (u64, u64),
    identity: [u8; 16],
    buffer: Vec<u8>,
}
impl Queue {
    pub fn bind(number: u16, max_pending: u32) -> io::Result<Self> {
        if !(1..=4096).contains(&max_pending) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let local = kernel_address();
        let result = unsafe {
            libc::bind(
                raw,
                (&local as *const libc::sockaddr_nl).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let result = unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut buffer = vec![0; MAX_MESSAGE];
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &[1, 0, 0, 0]); // NFQNL_CFG_CMD_BIND
        configure(raw, number, 1, &attrs, &mut buffer)?;
        attrs.clear();
        let mut copy = 65_531u32.to_be_bytes().to_vec();
        copy.push(2); // NFQNL_COPY_PACKET
        attr(&mut attrs, 2, &copy);
        attr(&mut attrs, 3, &max_pending.to_be_bytes());
        attr(&mut attrs, 4, &5u32.to_be_bytes()); // mask FAIL_OPEN | GSO
        attr(&mut attrs, 5, &0u32.to_be_bytes());
        configure(raw, number, 2, &attrs, &mut buffer)?;
        use ring::rand::{SecureRandom, SystemRandom};
        let mut identity = [0u8; 16];
        SystemRandom::new()
            .fill(&mut identity)
            .map_err(|_| invalid())?;
        Ok(Self {
            fd: Some(fd),
            number,
            namespace: Self::namespace()?,
            identity,
            buffer,
        })
    }

    fn namespace() -> io::Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata("/proc/thread-self/ns/net")?;
        Ok((meta.dev(), meta.ino()))
    }

    pub(super) fn number(&self) -> io::Result<u16> {
        self.descriptor()?;
        if self.namespace != Self::namespace()? {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(self.number)
    }

    pub(super) fn identity(&self) -> [u8; 16] {
        self.identity
    }

    fn descriptor(&self) -> io::Result<RawFd> {
        self.fd
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }

    fn verdict(&mut self, id: u32, accept: bool) -> io::Result<()> {
        self.verdict_payload(id,accept,None,None)
    }

    fn verdict_payload(&mut self,id:u32,accept:bool,payload:Option<&[u8]>,mark:Option<u32>)->io::Result<()> {
        if mark.is_some_and(|m|!accept || !super::linux_rules::reserved_mark(m)) ||
            payload.is_some_and(|p| !accept || p.len() > 65_531) {
            return Err(invalid());
        }
        let fd = self.descriptor()?;
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&u32::from(accept).to_be_bytes()); // NF_DROP=0, NF_ACCEPT=1
        data.extend_from_slice(&id.to_be_bytes());
        let mut attrs = Vec::with_capacity(12);
        attr(&mut attrs,2,&data);
        if let Some(mark)=mark {attr(&mut attrs,3,&mark.to_be_bytes());} // NFQA_MARK
        if let Some(payload) = payload {
            attr(&mut attrs, 10, payload);
        } // NFQA_PAYLOAD
        let result = send(fd, &message(VERDICT, REQUEST, 0, self.number, &attrs));
        if result.is_err() {
            drop(self.fd.take());
        }
        result
    }

    fn receive_captured(&mut self) -> io::Result<Captured> {
        let fd = self.descriptor()?;
        let result =
            receive(fd, &mut self.buffer).and_then(|n| decode(&self.buffer[..n], self.number));
        match result {
            Ok(captured) => Ok(captured),
            Err(error) => {
                if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) {
                    drop(self.fd.take());
                }
                Err(error)
            }
        }
    }

    /// Receives one bounded packet. Fatal errors close the queue.
    pub fn receive(&mut self) -> io::Result<Packet<'_>> {
        let captured = self.receive_captured()?;
        Ok(Packet {
            queue: self,
            captured,
            done: false,
        })
    }

    pub(crate) fn into_async(self) -> io::Result<AsyncQueue> {
        let fd = self.descriptor()?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Keep readiness registration independent of Queue's fatal-close
        // path. The whole AsyncQueue must be dropped on any fatal error.
        let duplicate = self.fd.as_ref().ok_or_else(invalid)?.try_clone()?;
        let ready = tokio::io::unix::AsyncFd::new(duplicate)?;
        Ok(AsyncQueue { ready, queue: self })
    }
}

pub(crate) struct AsyncQueue {
    ready: tokio::io::unix::AsyncFd<OwnedFd>,
    queue: Queue,
}
impl AsyncQueue {
    pub(crate) async fn next(&mut self) -> io::Result<Packet<'_>> {
        let captured = loop {
            let mut ready = self.ready.readable().await?;
            let queue = &mut self.queue;
            match ready.try_io(|_| queue.receive_captured()) {
                Ok(result) => break result?,
                Err(_) => continue,
            }
        };
        Ok(Packet {
            queue: &mut self.queue,
            captured,
            done: false,
        })
    }
}

/// Optional queue future for a single fair select over both capture
/// queues. Returning a packet borrows the actual queue, not the future.
pub(crate) async fn next_optional(queue:&mut Option<AsyncQueue>)->io::Result<Packet<'_>> {
    match queue.as_mut() {
        Some(queue)=>queue.next().await,
        None=>std::future::pending().await,
    }
}

/// A packet verdict is scoped to its exact queue and kernel packet ID.
pub struct Packet<'a> {
    queue: &'a mut Queue,
    captured: Captured,
    done: bool,
}
impl Packet<'_> {
    pub fn metadata(&self) -> Option<PacketMeta> {
        self.captured.meta
    }
    pub fn bytes(&self) -> &[u8] {
        &self.captured.bytes
    }
    pub fn checksum_pending(&self) -> bool {
        self.captured.checksum_pending
    }
    pub fn local_output(&self) -> bool {
        self.captured.local_output
    }
    pub(super) fn queue_identity(&self) -> [u8; 16] {
        self.queue.identity()
    }

    /// Only the checked laboratory strategy may provide a replacement.
    /// Reject inconsistent or unmodified output, rather than accepting the
    /// original bytes. The flow lease must already be committed to Modify.
    pub(crate) fn finish_stun_lab(mut self, changed: &[u8]) -> io::Result<PacketAction> {
        let expected =
            if self.local_output() && !self.checksum_pending() && self.metadata().is_some() {
                super::packet_modify::stun_fingerprint(self.bytes())
            } else {
                None
            };
        if expected.as_deref() != Some(changed) {
            return self.finish(PacketAction::Drop);
        }
        let result = self
            .queue
            .verdict_payload(self.captured.id,true,Some(changed),None);
        self.done = true;
        result.map(|()| PacketAction::Modify)
    }

    /// Only the managed policy consumer can stamp the kernel's held
    /// packet. The independent physical egress guard rejects Redirect
    /// marks unless the packet was actually rerouted onto loopback.
    pub(crate) fn finish_routed(mut self,action:PacketAction)->io::Result<PacketAction> {
        if !self.local_output() || self.metadata().is_none() {
            return self.finish(PacketAction::Drop);
        }
        let mark=match action {
            PacketAction::Pass=>super::linux_rules::PASS_MARK,
            PacketAction::Redirect=>super::linux_rules::REDIRECT_MARK,
            _=>return self.finish(PacketAction::Drop),
        };
        let result=self.queue.verdict_payload(self.captured.id,true,None,Some(mark));
        self.done=true;
        result.map(|()|action)
    }

    /// Pass only a complete supported packet. Until an actual redirect or
    /// modification adapter owns the payload, those actions are Drop.
    /// Returns the actual disposition, not the requested action.
    pub fn finish(mut self, action: PacketAction) -> io::Result<PacketAction> {
        let accept = action == PacketAction::Pass
            && self.captured.local_output
            && self.captured.meta.is_some();
        let result = self.queue.verdict(self.captured.id, accept);
        self.done = true;
        result.map(|()| {
            if accept {
                PacketAction::Pass
            } else {
                PacketAction::Drop
            }
        })
    }
}
impl Drop for Packet<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.queue.verdict(self.captured.id, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(payload: &[u8], skb: u32, cap_len: u32) -> Vec<u8> {
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &[0, 0, 0, 7, 8, 0, 3]);
        attr(&mut attrs, 6, &12u32.to_be_bytes());
        attr(&mut attrs, 10, payload);
        attr(&mut attrs, 13, &cap_len.to_be_bytes());
        attr(&mut attrs, 14, &skb.to_be_bytes());
        let mut data = message(PACKET, 0, 0, 9, &attrs);
        data[HEADER] = 2;
        data
    }
    fn udp4() -> Vec<u8> {
        let mut b = vec![0; 28];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&28u16.to_be_bytes());
        b[9] = 17;
        b[12..16].copy_from_slice(&[192, 0, 2, 1]);
        b[16..20].copy_from_slice(&[198, 51, 100, 2]);
        b[20..22].copy_from_slice(&1000u16.to_be_bytes());
        b[22..24].copy_from_slice(&53u16.to_be_bytes());
        b[24..26].copy_from_slice(&8u16.to_be_bytes());
        b
    }
    #[test]
    fn decode_preserves_id_interface_and_offload_status() {
        let data = packet(&udp4(), 1, 28);
        let p = decode(&data, 9).unwrap();
        assert_eq!(p.id, 7);
        assert_eq!(p.meta.unwrap().flow.interface, 12);
        assert!(p.checksum_pending);
        assert!(decode(&data, 10).is_err());
        assert!(decode(&packet(&udp4(), 2, 28), 9).unwrap().meta.is_none());
        assert!(decode(&packet(&udp4(), 0, 29), 9).unwrap().meta.is_none());
        for end in 0..data.len() {
            assert!(decode(&data[..end], 9).is_err());
        }
    }
    #[test]
    fn kernel_zerocopy_payload_without_terminal_padding() {
        let mut payload = udp4();
        payload.extend_from_slice(b"owned");
        payload[2..4].copy_from_slice(&33u16.to_be_bytes());
        payload[24..26].copy_from_slice(&13u16.to_be_bytes());
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &[0, 0, 0, 7, 8, 0, 3]);
        attr(&mut attrs, 6, &12u32.to_be_bytes());
        attr(&mut attrs, 14, &1u32.to_be_bytes());
        attr(&mut attrs, 10, &payload);
        // Model the kernel's skb_zerocopy output: last attribute has no pad.
        attrs.truncate(attrs.len() - 3);
        let mut data = message(PACKET, 0, 0, 9, &attrs);
        data[HEADER] = 2;
        assert_ne!(data.len() % 4, 0);
        let captured = decode(&data, 9).unwrap();
        assert_eq!(captured.bytes, payload);
        assert!(captured.meta.is_some());
        assert_eq!(captured.meta.unwrap().flow.interface, 12);
        assert!(captured.checksum_pending);
        assert!(decode(&data[..data.len() - 1], 9).is_err());
        let mut truncated = data[..data.len() - 1].to_vec();
        let len = truncated.len() as u32;
        truncated[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(decode(&truncated, 9).is_err());
    }

    #[test]
    fn duplicate_or_invalid_attributes_fail_closed() {
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &[0, 0, 0, 7, 8, 0, 3]);
        attr(&mut attrs, 1, &[0, 0, 0, 8, 8, 0, 3]);
        assert!(decode(&message(PACKET, 0, 0, 9, &attrs), 9).is_err());
        let mut bad = packet(&udp4(), 0, 28);
        bad[HEADER + NFGEN..HEADER + NFGEN + 2].copy_from_slice(&2u16.to_ne_bytes());
        assert!(decode(&bad, 9).is_err());
    }
}
