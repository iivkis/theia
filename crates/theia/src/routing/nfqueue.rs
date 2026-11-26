//! Linux NFQUEUE transport using the kernel NETLINK_NETFILTER UAPI.
//! No nftables rules are installed here. Opening a queue is not proof of
//! system ingress readiness; Redirect/Modify require a higher-layer adapter.
//! Dropping an undecided packet sends NF_DROP. Closing a failed queue leaves
//! externally owned non-bypass queue rules fail-closed.
use super::{packet::PacketMeta, PacketAction};
use std::{
    io,
    mem,
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
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    let len16 = u16::try_from(len).expect("fixed bounded command");
    out.extend_from_slice(&len16.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(align4(out.len()), 0);
}
fn message(kind: u16, flags: u16, sequence: u32, queue: u16, attrs: &[u8]) -> Vec<u8> {
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
fn checked_header(data: &[u8]) -> io::Result<(u16, u32, &[u8])> {
    let header = data.get(..HEADER).ok_or_else(invalid)?;
    let len = native32(&header[..4]) as usize;
    if len < HEADER || align4(len) != data.len() {
        return Err(invalid());
    }
    let body = data.get(HEADER..len).ok_or_else(invalid)?;
    Ok((native16(&header[4..6]), native32(&header[8..12]), body))
}
fn next_attr<'a>(rest: &mut &'a [u8]) -> io::Result<Option<(u16, &'a [u8])>> {
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
fn decode(data: &[u8], queue: u16) -> io::Result<Captured> {
    let (kind, _, body) = checked_header(data)?;
    let nfgen = body.get(..NFGEN).ok_or_else(invalid)?;
    if kind != PACKET || nfgen[1] != 0 || u16::from_be_bytes([nfgen[2], nfgen[3]]) != queue {
        return Err(invalid());
    }
    let mut rest = &body[NFGEN..];
    let (mut id, mut payload, mut captured_len, mut skb, mut input, mut output) = (None, None, None, None, None, None);
    let mut ethertype = 0;
    let mut local_output = false;
    while let Some((kind, value)) = next_attr(&mut rest)? {
        match kind {
            1 if id.is_none() && value.len() == 7 => {
                id = Some(be32(&value[..4]));
                ethertype = u16::from_be_bytes([value[4], value[5]]);
                local_output = value[6] == 3; // NF_INET_LOCAL_OUT
            }
            5 if input.is_none() && value.len() == 4 => input = Some(be32(value)),
            6 if output.is_none() && value.len() == 4 => output = Some(be32(value)),
            10 if payload.is_none() => payload = Some(value),
            13 if captured_len.is_none() && value.len() == 4 => captured_len = Some(be32(value) as usize),
            14 if skb.is_none() && value.len() == 4 => skb = Some(be32(value)),
            1 | 5 | 6 | 10 | 13 | 14 => return Err(invalid()),
            _ => {}
        }
    }
    let id = id.ok_or_else(invalid)?;
    let bytes = payload.unwrap_or_default();
    let skb = skb.unwrap_or(0);
    let family_ok = matches!((nfgen[0], ethertype, bytes.first().map(|b| b >> 4)),
        (2, 0x0800, Some(4)) | (10, 0x86dd, Some(6)));
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

fn kernel_address() -> libc::sockaddr_nl {
    // All padding and groups are zero; no multicast subscription.
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address
}
fn send(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let kernel = kernel_address();
    let sent = unsafe {
        libc::sendto(fd, bytes.as_ptr().cast(), bytes.len(), 0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t)
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != bytes.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}
fn receive(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let mut sender = kernel_address();
    let mut len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let read = unsafe {
        libc::recvfrom(fd, buffer.as_mut_ptr().cast(), buffer.len(), libc::MSG_TRUNC,
            (&mut sender as *mut libc::sockaddr_nl).cast(), &mut len)
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read == 0 || read as usize > buffer.len() || len as usize != mem::size_of::<libc::sockaddr_nl>()
        || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t || sender.nl_pid != 0 || sender.nl_groups != 0 {
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
    buffer: Vec<u8>,
}
impl Queue {
    pub fn bind(number: u16, max_pending: u32) -> io::Result<Self> {
        if !(1..=4096).contains(&max_pending) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let local = kernel_address();
        let result = unsafe {
            libc::bind(raw, (&local as *const libc::sockaddr_nl).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t)
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let timeout = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let result = unsafe {
                libc::setsockopt(raw, libc::SOL_SOCKET, option, (&timeout as *const libc::timeval).cast(),
                    mem::size_of::<libc::timeval>() as libc::socklen_t)
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
        Ok(Self { fd: Some(fd), number, buffer })
    }

    fn descriptor(&self) -> io::Result<RawFd> {
        self.fd.as_ref().map(AsRawFd::as_raw_fd).ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }

    fn verdict(&mut self, id: u32, accept: bool) -> io::Result<()> {
        let fd = self.descriptor()?;
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&u32::from(accept).to_be_bytes()); // NF_DROP=0, NF_ACCEPT=1
        data.extend_from_slice(&id.to_be_bytes());
        let mut attrs = Vec::with_capacity(12);
        attr(&mut attrs, 2, &data);
        let result = send(fd, &message(VERDICT, REQUEST, 0, self.number, &attrs));
        if result.is_err() {
            drop(self.fd.take());
        }
        result
    }

    /// Receives one bounded packet. A timeout is not a permission to pass;
    /// malformed kernel messages or lost netlink data close the queue.
    pub fn receive(&mut self) -> io::Result<Packet<'_>> {
        let fd = self.descriptor()?;
        let result = receive(fd, &mut self.buffer)
            .and_then(|n| decode(&self.buffer[..n], self.number));
        match result {
            Ok(captured) => Ok(Packet { queue: self, captured, done: false }),
            Err(error) => {
                if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) {
                    drop(self.fd.take());
                }
                Err(error)
            }
        }
    }
}

/// A packet verdict is scoped to its exact queue and kernel packet ID.
pub struct Packet<'a> {
    queue: &'a mut Queue,
    captured: Captured,
    done: bool,
}
impl Packet<'_> {
    pub fn metadata(&self) -> Option<PacketMeta> { self.captured.meta }
    pub fn bytes(&self) -> &[u8] { &self.captured.bytes }
    pub fn checksum_pending(&self) -> bool { self.captured.checksum_pending }
    pub fn local_output(&self) -> bool { self.captured.local_output }

    /// Pass only a complete supported packet. Until an actual redirect or
    /// modification adapter owns the payload, those actions are Drop.
    /// Returns the actual disposition, not the requested action.
    pub fn finish(mut self, action: PacketAction) -> io::Result<PacketAction> {
        let accept = action == PacketAction::Pass && self.captured.local_output && self.captured.meta.is_some();
        let result = self.queue.verdict(self.captured.id, accept);
        self.done = true;
        result.map(|()| if accept { PacketAction::Pass } else { PacketAction::Drop })
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
