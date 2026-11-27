//! Explicit laboratory-only nftables installation/recovery. The caller must
//! supply a reference to the host net namespace: this module refuses to
//! operate in that namespace. No product activation or carrier exemption.
//! A dedicated inet table queues LOCAL_OUT without bypass. If the owner
//! dies, the kernel queue closes and the table remains fail closed.
//! Recovery deletes ONLY our table, using the kernel ruleset generation CAS.
//! Any unrelated ruleset change after installation requires manual review.
use super::nfqueue::{align4, attr, checked_header, kernel_address, message, next_attr, receive, send, Queue};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io,
    mem,
    os::{fd::{AsRawFd, FromRawFd, OwnedFd}, linux::net::SocketAddrExt, unix::{fs::MetadataExt, net::UnixDatagram}},
    path::Path,
};

const NFT: u16 = 10 << 8;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const CREATE_EXCLUSIVE: u16 = 0x600;
const NESTED: u16 = 0x8000;
const FAMILY_INET: u8 = 1;
const NEW_TABLE: u16 = NFT;
const GET_TABLE: u16 = NFT | 1;
const DEL_TABLE: u16 = NFT | 2;
const NEW_CHAIN: u16 = NFT | 3;
const NEW_RULE: u16 = NFT | 6;
const NEW_GEN: u16 = NFT | 15;
const GET_GEN: u16 = NFT | 16;

fn refused() -> io::Error { io::Error::from(io::ErrorKind::PermissionDenied) }
fn invalid() -> io::Error { io::Error::from(io::ErrorKind::InvalidData) }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    boot: String,
    dev: u64,
    ino: u64,
}
impl Scope {
    fn current(host_namespace: &File) -> io::Result<Self> {
        let own = fs::metadata("/proc/thread-self/ns/net")?;
        let host = host_namespace.metadata()?;
        let mut stat: libc::statfs = unsafe { mem::zeroed() };
        if unsafe { libc::fstatfs(host_namespace.as_raw_fd(), &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
        if stat.f_type as u64 != 0x6e736673 { return Err(refused()); } // NSFS_MAGIC
        // NS_GET_NSTYPE rejects a mount/PID namespace presented as a host
        // network-namespace handle.
        if unsafe { libc::ioctl(host_namespace.as_raw_fd(), 0xb703 as libc::c_ulong) } != libc::CLONE_NEWNET { return Err(refused()); }
        if own.dev() == host.dev() && own.ino() == host.ino() { return Err(refused()); }
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().to_owned();
        if boot.len() != 36 || !boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') { return Err(invalid()); }
        Ok(Self { boot, dev: own.dev(), ino: own.ino() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    scope: Scope,
    nonce: [u8; 16],
    before: u32,
    installed: u32,
    restored: bool,
}
impl Journal {
    fn name(&self) -> String {
        let suffix: String = self.nonce.iter().map(|n| format!("{n:02x}")).collect();
        format!("theia_lab_{suffix}")
    }
    fn validate(&self, scope: &Scope) -> io::Result<()> {
        if self.version != 1 || &self.scope != scope || self.nonce == [0;16]
            || self.before == 0 || self.before.checked_add(1) != Some(self.installed) {
            return Err(refused());
        }
        Ok(())
    }
}

fn journal_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.uid() == unsafe { libc::geteuid() } && meta.nlink() == 1 => {
            crate::bounded_input::read(path, 4096, true, true).map(|b| Some(b.to_vec()))
        }
        Ok(_) => Err(refused()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn check_parent(path: &Path) -> io::Result<()> {
    if !crate::bounded_input::explicit_file_path(path) { return Err(refused()); }
    let parent = path.parent().ok_or_else(refused)?;
    // A trusted owner-only real directory is required. Reject symlinked
    // ancestors; the owner is responsible for a stable mount namespace.
    if fs::canonicalize(parent)? != parent { return Err(refused()); }
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 { return Err(refused()); }
    Ok(())
}
fn store(path: &Path, journal: &Journal, expected: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let encoded = toml::to_string(journal).map_err(|_| invalid())?;
    crate::config::guarded_trust_write(path, &encoded, expected).map_err(|_| refused())?;
    let bytes = journal_bytes(path)?.ok_or_else(refused)?;
    if bytes != encoded.as_bytes() { return Err(refused()); }
    Ok(bytes)
}
fn scope_lock() -> io::Result<UnixDatagram> {
    let address = std::os::unix::net::SocketAddr::from_abstract_name(b"theia-lab-nft-rules-v1")?;
    UnixDatagram::bind_addr(&address)
}

struct Netlink(OwnedFd);
impl Netlink {
    fn open() -> io::Result<Self> {
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let local = kernel_address();
        let rc = unsafe {
            libc::bind(raw, (&local as *const libc::sockaddr_nl).cast(), mem::size_of_val(&local) as libc::socklen_t)
        };
        if rc != 0 { return Err(io::Error::last_os_error()); }
        let wait = libc::timeval { tv_sec: 1, tv_usec: 0 };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let rc = unsafe { libc::setsockopt(raw, libc::SOL_SOCKET, option, (&wait as *const libc::timeval).cast(), mem::size_of_val(&wait) as libc::socklen_t) };
            if rc != 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(Self(fd))
    }
    fn request(&self, kind: u16, attrs: &[u8]) -> io::Result<Vec<u8>> {
        send(self.0.as_raw_fd(), &nft_message(kind, REQUEST, 1, attrs))?;
        let mut b = vec![0u8; 65536];
        let n = receive(self.0.as_raw_fd(), &mut b)?;
        b.truncate(n);
        Ok(b)
    }
    fn generation(&self) -> io::Result<u32> {
        let b = self.request(GET_GEN, &[])?;
        let (kind, seq, body) = checked_header(&b)?;
        if kind == 2 { return Err(ack_error(body)?.unwrap_or_else(invalid)); }
        if kind != NEW_GEN || seq != 1 || body.len() < 4 || body[1] != 0 { return Err(invalid()); }
        let mut rest = &body[4..];
        let mut generation = None;
        while let Some((kind, value)) = next_attr(&mut rest)? {
            if kind == 1 {
                if generation.is_some() || value.len() != 4 { return Err(invalid()); }
                generation = Some(u32::from_be_bytes(value.try_into().map_err(|_| invalid())?));
            }
        }
        generation.filter(|n| *n != 0).ok_or_else(invalid)
    }
    fn table(&self, journal: &Journal) -> io::Result<bool> {
        let mut attrs = Vec::new();
        name_attr(&mut attrs, 1, &journal.name());
        let b = self.request(GET_TABLE, &attrs)?;
        let (kind, seq, body) = checked_header(&b)?;
        if seq != 1 { return Err(invalid()); }
        if kind == 2 {
            let error = ack_error(body)?.ok_or_else(invalid)?;
            return if error.raw_os_error() == Some(libc::ENOENT) { Ok(false) } else { Err(error) };
        }
        if kind != NEW_TABLE || body.len() < 4 || body[0] != FAMILY_INET || body[1] != 0 { return Err(invalid()); }
        let mut rest = &body[4..];
        let (mut name, mut nonce, mut use_count) = (None, None, None);
        while let Some((kind, value)) = next_attr(&mut rest)? {
            match kind {
                1 if name.is_none() => name = Some(value),
                6 if nonce.is_none() => nonce = Some(value),
                3 if use_count.is_none() && value.len() == 4 => use_count = Some(u32::from_be_bytes(value.try_into().map_err(|_| invalid())?)),
                1 | 3 | 6 => return Err(invalid()),
                _ => {}
            }
        }
        let expected = journal.name() + "\0";
        if name != Some(expected.as_bytes()) || nonce != Some(journal.nonce.as_slice()) || use_count != Some(1) {
            return Err(refused());
        }
        Ok(true)
    }
    fn batch(&self, generation: u32, operations: &[Vec<u8>]) -> io::Result<()> {
        if generation == 0 || operations.is_empty() || operations.len() > 3 { return Err(invalid()); }
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &generation.to_be_bytes());
        let mut bytes = message(16, REQUEST, 1, 10, &attrs);
        for operation in operations { bytes.extend_from_slice(operation); }
        bytes.extend_from_slice(&message(17, REQUEST, operations.len() as u32 + 2, 10, &[]));
        send(self.0.as_raw_fd(), &bytes)?;
        let mut received = 0u8;
        let expected = (1u8 << operations.len()) - 1;
        let mut buffer = vec![0u8; 65536];
        for _ in 0..8 {
            let n = receive(self.0.as_raw_fd(), &mut buffer)?;
            let mut rest = &buffer[..n];
            while !rest.is_empty() {
                let header = rest.get(..16).ok_or_else(invalid)?;
                let len = u32::from_ne_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
                if len < 16 || align4(len) > rest.len() { return Err(invalid()); }
                let (kind, seq, body) = checked_header(&rest[..align4(len)])?;
                if kind != 2 { return Err(invalid()); }
                if let Some(error) = ack_error(body)? { return Err(error); }
                if seq < 2 || seq > operations.len() as u32 + 1 { return Err(invalid()); }
                let bit = 1u8 << (seq - 2);
                if received & bit != 0 { return Err(invalid()); }
                received |= bit;
                rest = &rest[align4(len)..];
            }
            if received == expected { return Ok(()); }
        }
        Err(invalid())
    }
}
fn ack_error(body: &[u8]) -> io::Result<Option<io::Error>> {
    if body.len() < 20 { return Err(invalid()); }
    let code = i32::from_ne_bytes(body[..4].try_into().map_err(|_| invalid())?);
    match code {
        0 => Ok(None),
        i32::MIN => Err(invalid()),
        n if n < 0 => Ok(Some(io::Error::from_raw_os_error(-n))),
        _ => Err(invalid()),
    }
}
fn name_attr(out: &mut Vec<u8>, kind: u16, name: &str) {
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    attr(out, kind, &name);
}
fn nft_message(kind: u16, flags: u16, sequence: u32, attrs: &[u8]) -> Vec<u8> {
    let mut msg = message(kind, flags, sequence, 0, attrs);
    // GETGEN is family-independent, all object operations are inet.
    if kind != GET_GEN { msg[16] = FAMILY_INET; }
    msg
}
fn install_messages(journal: &Journal, queue: u16) -> Vec<Vec<u8>> {
    let name = journal.name();
    let mut table = Vec::new();
    name_attr(&mut table, 1, &name);
    attr(&mut table, 6, &journal.nonce);

    let mut chain = Vec::new();
    name_attr(&mut chain, 1, &name);
    name_attr(&mut chain, 3, "output");
    name_attr(&mut chain, 7, "filter");
    let mut hook = Vec::new();
    attr(&mut hook, 1, &3u32.to_be_bytes()); // LOCAL_OUT
    attr(&mut hook, 2, &0i32.to_be_bytes());
    attr(&mut chain, 4 | NESTED, &hook);
    attr(&mut chain, 5, &0u32.to_be_bytes()); // NF_DROP policy

    let mut rule = Vec::new();
    name_attr(&mut rule, 1, &name);
    name_attr(&mut rule, 2, "output");
    let mut data = Vec::new();
    attr(&mut data, 1, &queue.to_be_bytes());
    attr(&mut data, 2, &1u16.to_be_bytes());
    attr(&mut data, 3, &0u16.to_be_bytes()); // no bypass
    let mut expression = Vec::new();
    name_attr(&mut expression, 1, "queue");
    attr(&mut expression, 2 | NESTED, &data);
    let mut expressions = Vec::new();
    attr(&mut expressions, 1 | NESTED, &expression);
    attr(&mut rule, 4 | NESTED, &expressions);
    let flags = REQUEST | ACK | CREATE_EXCLUSIVE;
    vec![nft_message(NEW_TABLE, flags, 2, &table), nft_message(NEW_CHAIN, flags, 3, &chain), nft_message(NEW_RULE, flags, 4, &rule)]
}

fn parse_journal(bytes: &[u8], scope: &Scope) -> io::Result<Journal> {
    let journal: Journal = toml::from_str(std::str::from_utf8(bytes).map_err(|_| invalid())?).map_err(|_| invalid())?;
    journal.validate(scope)?;
    Ok(journal)
}

/// A lab rule lease keeps the namespace ownership lock. Drop never deletes
/// rules or restores open networking. Explicit reviewed recovery is needed.
pub struct LabRules {
    _lock: UnixDatagram,
    journal: Journal,
    queue_identity: [u8; 16],
}
impl LabRules {
    pub(crate) fn owns_packet(&self, packet: &super::nfqueue::Packet<'_>) -> io::Result<bool> {
        let meta = fs::metadata("/proc/thread-self/ns/net")?;
        if (meta.dev(), meta.ino()) != (self.journal.scope.dev, self.journal.scope.ino)
            || packet.queue_identity() != self.queue_identity { return Ok(false); }
        let net = Netlink::open()?;
        Ok(net.generation()? == self.journal.installed && net.table(&self.journal)? && net.generation()? == self.journal.installed)
    }

    /// Blocking operation; run on a dedicated namespace worker, not a Tokio
    /// executor that can change namespaces between tasks. The provided
    /// host_namespace handle must genuinely be the trusted host namespace.
    /// The caller must own an isolated lab and a running NFQUEUE consumer.
    /// All its output will be queued; this is NOT production activation.
    pub fn install(queue: &Queue, host_namespace: &File, path: &Path) -> io::Result<Self> {
        let lock = scope_lock()?;
        let scope = Scope::current(host_namespace)?;
        check_parent(path)?;
        let old = journal_bytes(path)?;
        if let Some(bytes) = &old {
            if !parse_journal(bytes, &scope)?.restored { return Err(refused()); }
        }
        let net = Netlink::open()?;
        let before = net.generation()?;
        let installed = before.checked_add(1).ok_or_else(refused)?;
        let mut nonce = [0; 16];
        SystemRandom::new().fill(&mut nonce).map_err(|_| refused())?;
        let journal = Journal { version: 1, scope, nonce, before, installed, restored: false };
        if net.table(&journal)? { return Err(refused()); }
        let operations = install_messages(&journal, queue.number()?);
        // Durable intent before changing any OS state, with create-only/CAS
        // publication. All uncertain failures leave the journal intact.
        store(path, &journal, old.as_deref())?;
        net.batch(before, &operations)?;
        if net.generation()? != installed || !net.table(&journal)? || net.generation()? != installed {
            return Err(refused());
        }
        Ok(Self { _lock: lock, journal, queue_identity: queue.identity() })
    }
}

/// Explicit recovery, after the previous LabRules lease is dropped. A
/// foreign change anywhere in this namespace makes deletion fail closed.
/// No forced flush, no whole-ruleset restoration, no table-name guessing.
pub fn recover(host_namespace: &File, path: &Path) -> io::Result<()> {
    let _lock = scope_lock()?;
    let scope = Scope::current(host_namespace)?;
    check_parent(path)?;
    let raw = journal_bytes(path)?.ok_or_else(refused)?;
    let mut journal = parse_journal(&raw, &scope)?;
    if journal.restored { return Ok(()); }
    let net = Netlink::open()?;
    let generation = net.generation()?;
    if net.table(&journal)? {
        if generation != journal.installed || net.generation()? != generation { return Err(refused()); }
        crate::config::guarded_trust_assert(path, &raw).map_err(|_| refused())?;
        let mut attrs = Vec::new();
        name_attr(&mut attrs, 1, &journal.name());
        net.batch(generation, &[nft_message(DEL_TABLE, REQUEST | ACK, 2, &attrs)])?;
    }
    if net.table(&journal)? { return Err(refused()); }
    journal.restored = true;
    store(path, &journal, Some(&raw))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn journal() -> Journal {
        Journal { version: 1, scope: Scope { boot: "test".into(), dev: 1, ino: 2 }, nonce: [7;16], before: 12, installed: 13, restored: false }
    }
    #[test]
    fn exact_generation_and_scope_required() {
        let j = journal();
        assert!(j.validate(&j.scope).is_ok());
        let mut changed = j.clone();
        changed.installed += 1;
        assert!(changed.validate(&j.scope).is_err());
        let mut changed = j.scope.clone();
        changed.ino += 1;
        assert!(j.validate(&changed).is_err());
        assert_eq!(parse_journal(toml::to_string(&j).unwrap().as_bytes(), &j.scope).unwrap(), j);
    }
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and CAP_NET_ADMIN; isolated network namespace only"]
    fn kernel_install_and_recovery_in_new_namespace() {
        std::thread::spawn(|| {
            use std::os::unix::fs::DirBuilderExt;
            let host = File::open("/proc/thread-self/ns/net").unwrap();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            let mut random = [0;16];
            SystemRandom::new().fill(&mut random).unwrap();
            let suffix: String = random.iter().map(|n| format!("{n:02x}")).collect();
            let dir = std::env::temp_dir().join(format!("theia-nft-lab-{suffix}"));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            let path = dir.join("journal.toml");
            let queue = Queue::bind(49000, 64).unwrap();
            let lease = LabRules::install(&queue, &host, &path).unwrap();
            let scope = Scope::current(&host).unwrap();
            let journal = parse_journal(&journal_bytes(&path).unwrap().unwrap(), &scope).unwrap();
            assert!(Netlink::open().unwrap().table(&journal).unwrap());
            assert!(recover(&host, &path).is_err()); // live owner
            drop(lease);
            recover(&host, &path).unwrap();
            assert!(!Netlink::open().unwrap().table(&journal).unwrap());
            recover(&host, &path).unwrap();
            fs::remove_dir_all(dir).unwrap();
        }).join().unwrap();
    }

    #[test]
    fn batch_objects_have_exclusive_creation_and_no_queue_bypass() {
        let j = journal();
        let messages = install_messages(&j, 42);
        for (i, bytes) in messages.iter().enumerate() {
            let (kind, seq, body) = checked_header(bytes).unwrap();
            assert_eq!(kind, [NEW_TABLE, NEW_CHAIN, NEW_RULE][i]);
            assert_eq!(seq, i as u32 + 2);
            assert_eq!(body[0], FAMILY_INET);
            assert_eq!(u16::from_ne_bytes(bytes[6..8].try_into().unwrap()), REQUEST | ACK | CREATE_EXCLUSIVE);
        }
        let (_, _, body) = checked_header(&messages[2]).unwrap();
        let mut attrs = &body[4..];
        assert_eq!(next_attr(&mut attrs).unwrap().unwrap().0, 1);
        assert_eq!(next_attr(&mut attrs).unwrap().unwrap().0, 2);
        let (_, mut expressions) = next_attr(&mut attrs).unwrap().unwrap();
        let (_, mut expression) = next_attr(&mut expressions).unwrap().unwrap();
        assert_eq!(next_attr(&mut expression).unwrap().unwrap().1, b"queue\0");
        let (_, mut data) = next_attr(&mut expression).unwrap().unwrap();
        assert_eq!(next_attr(&mut data).unwrap().unwrap().1, &42u16.to_be_bytes());
        assert_eq!(next_attr(&mut data).unwrap().unwrap().1, &1u16.to_be_bytes());
        assert_eq!(next_attr(&mut data).unwrap().unwrap().1, &0u16.to_be_bytes());
    }
}
