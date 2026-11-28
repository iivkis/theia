//! Owned policy routing for the isolated native redirect. RTNL does not
//! expose nftables' generation CAS. Exclusive create and complete readback
//! are used instead; recovery refuses every uncertain or foreign object.
//! Requires a single trusted network administrator in this namespace.
use super::{
    check_parent, invalid, journal_bytes, loopback_index, refused, scope_lock, Scope, REDIRECT_MARK,
};
use crate::routing::nfqueue::{
    align4, attr, checked_header, kernel_address, next_attr, receive, send,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
};

const TABLE: u32 = 21577;
const PRIORITY: u32 = 21577;
const METRIC: u32 = 42760;
const PROTOCOL: u8 = 242;
const FAMILIES: [u8; 2] = [libc::AF_INET as u8, libc::AF_INET6 as u8];
const NEW_ROUTE: u16 = 24;
const DEL_ROUTE: u16 = 25;
const GET_ROUTE: u16 = 26;
const NEW_RULE: u16 = 32;
const DEL_RULE: u16 = 33;
const GET_RULE: u16 = 34;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    kind: u16,
    body: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    scope: Scope,
    loopback: u32,
    // Only read-back objects confirmed after successful exclusive create
    // are deletable. A crash in the create/readback gap is manual recovery.
    confirmed: Vec<Object>,
    restored: bool,
}
fn path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".routes");
    PathBuf::from(name)
}
fn lock() -> io::Result<UnixDatagram> {
    use std::os::linux::net::SocketAddrExt;
    UnixDatagram::bind_addr(&std::os::unix::net::SocketAddr::from_abstract_name(
        b"theia-owned-policy-routes-v1",
    )?)
}
fn read_intent_mode(
    path: &Path,
    scope: &Scope,
    old_boot: bool,
) -> io::Result<Option<(Intent, Vec<u8>)>> {
    let Some(raw) = journal_bytes(path)? else {
        return Ok(None);
    };
    let intent: Intent =
        toml::from_str(std::str::from_utf8(&raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
    let same = &intent.scope == scope;
    let previous_boot = old_boot
        && scope.machine.is_some()
        && scope.machine == intent.scope.machine
        && scope.boot != intent.scope.boot
        && super::valid_boot_id(&intent.scope.boot);
    if intent.version != 1
        || (!same && !previous_boot)
        || intent.loopback == 0
        || intent.confirmed.len() > 4
        || intent
            .confirmed
            .iter()
            .any(|o| o.body.len() > 256 || !exact(o, intent.loopback))
        || intent.confirmed.iter().enumerate().any(|(i, o)| {
            intent.confirmed[..i]
                .iter()
                .any(|a| a.kind == o.kind && a.body[0] == o.body[0])
        })
    {
        return Err(refused());
    }
    Ok(Some((intent, raw)))
}
fn read_intent(path: &Path, scope: &Scope) -> io::Result<Option<(Intent, Vec<u8>)>> {
    read_intent_mode(path, scope, false)
}
fn write_intent(path: &Path, intent: &Intent, expected: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let value = toml::to_string(intent).map_err(|_| invalid())?;
    if value.len() > 4096 {
        return Err(invalid());
    }
    crate::config::guarded_trust_write(path, &value, expected).map_err(|_| refused())?;
    let raw = journal_bytes(path)?.ok_or_else(refused)?;
    if raw != value.as_bytes() {
        return Err(refused());
    }
    Ok(raw)
}
struct Rtnl(OwnedFd);
impl Rtnl {
    fn open() -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let local = kernel_address();
        if unsafe {
            libc::bind(
                raw,
                (&local as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&local) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            if unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    mem::size_of_val(&timeout) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(fd))
    }
    fn request(&self, kind: u16, flags: u16, body: &[u8]) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(16 + body.len());
        bytes.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&1u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        send(self.0.as_raw_fd(), &bytes)
    }
    fn mutate(kind: u16, body: &[u8], create: bool) -> io::Result<()> {
        let net = Self::open()?;
        net.request(kind, if create { 0x605 } else { 5 }, body)?;
        let mut bytes = [0u8; 8192];
        let n = receive(net.0.as_raw_fd(), &mut bytes)?;
        let (typ, seq, body) = checked_header(&bytes[..n])?;
        if typ != 2 || seq != 1 || body.len() < 20 {
            return Err(invalid());
        }
        let errno = i32::from_ne_bytes(body[..4].try_into().map_err(|_| invalid())?);
        match errno {
            0 => Ok(()),
            n if n < 0 && n != i32::MIN => Err(io::Error::from_raw_os_error(-n)),
            _ => Err(invalid()),
        }
    }
    fn dump(kind: u16, family: u8) -> io::Result<Vec<Object>> {
        let net = Self::open()?;
        let mut request = [0u8; 12];
        request[0] = family;
        net.request(kind, 0x301, &request)?;
        let mut bytes = vec![0u8; 65536];
        let mut objects = Vec::new();
        for _ in 0..128 {
            let n = receive(net.0.as_raw_fd(), &mut bytes)?;
            if decode_dump(&bytes[..n], kind, family, &mut objects)? {
                return Ok(objects);
            }
        }
        Err(invalid())
    }
}
// Parse a complete received datagram; preserve the kernel's multipart
// completion and interruption rules independently of the socket transport.
fn decode_dump(bytes: &[u8], kind: u16, family: u8, objects: &mut Vec<Object>) -> io::Result<bool> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let header = rest.get(..16).ok_or_else(invalid)?;
        let len =
            u32::from_ne_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
        if len < 16
            || align4(len) > rest.len()
            || u16::from_ne_bytes([header[6], header[7]]) & 0x10 != 0
        {
            return Err(invalid()); // interrupted dump
        }
        let (typ, seq, body) = checked_header(&rest[..align4(len)])?;
        if seq != 1 {
            return Err(invalid());
        }
        if typ == 3 {
            if rest.len() != align4(len)
                || (!body.is_empty() && (body.len() < 4 || body[..4] != [0; 4]))
            {
                return Err(invalid());
            }
            return Ok(true);
        }
        if typ
            != (if kind == GET_ROUTE {
                NEW_ROUTE
            } else {
                NEW_RULE
            })
            || body.len() < 12
            || body[0] != family
            || objects.len() >= 4096
        {
            return Err(invalid());
        }
        let object = Object {
            kind: typ,
            body: body.to_vec(),
        };
        if relevant(&object)? {
            objects.push(object);
        }
        rest = &rest[align4(len)..];
    }
    Ok(false)
}
fn attrs(body: &[u8]) -> io::Result<std::collections::BTreeMap<u16, &[u8]>> {
    let mut rest = body.get(12..).ok_or_else(invalid)?;
    let mut map = std::collections::BTreeMap::new();
    while let Some((kind, value)) = next_attr(&mut rest)? {
        if map.insert(kind, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(map)
}
fn number(value: Option<&&[u8]>) -> io::Result<Option<u32>> {
    value
        .map(|v| Ok(u32::from_ne_bytes((*v).try_into().map_err(|_| invalid())?)))
        .transpose()
}
fn relevant(object: &Object) -> io::Result<bool> {
    let a = attrs(&object.body)?;
    let table = number(a.get(&15))?.unwrap_or(u32::from(object.body[4]));
    if table == TABLE {
        return Ok(true);
    }
    if object.kind == NEW_RULE {
        if number(a.get(&6))? == Some(PRIORITY) {
            return Ok(true);
        }
        if let Some(mark) = number(a.get(&10))? {
            let mask = number(a.get(&16))?.unwrap_or(u32::MAX);
            if mark & mask == REDIRECT_MARK & mask || mark & mask == super::PASS_MARK & mask {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn expected(kind: u16, family: u8, lo: u32) -> Object {
    let mut body = vec![0u8; 12];
    body[0] = family;
    if kind == NEW_ROUTE {
        body[5] = PROTOCOL;
        body[6] = if family == FAMILIES[0] { 254 } else { 0 };
        body[7] = 2; // local
        attr(&mut body, 4, &lo.to_ne_bytes());
        attr(&mut body, 6, &METRIC.to_ne_bytes());
    } else {
        body[7] = 1; // FR_ACT_TO_TBL
        attr(&mut body, 6, &PRIORITY.to_ne_bytes());
        attr(&mut body, 10, &REDIRECT_MARK.to_ne_bytes());
        attr(&mut body, 16, &u32::MAX.to_ne_bytes());
        attr(&mut body, 21, &[PROTOCOL]);
    }
    attr(&mut body, 15, &TABLE.to_ne_bytes());
    Object { kind, body }
}
fn exact(object: &Object, lo: u32) -> bool {
    let Some(&family) = object.body.first() else {
        return false;
    };
    if !FAMILIES.contains(&family)
        || ![NEW_ROUTE, NEW_RULE].contains(&object.kind)
        || object.body.len() < 12
    {
        return false;
    }
    let wanted = expected(object.kind, family, lo);
    // Kernel dumps may materialize unspecified route table (0) or
    // RT_TABLE_COMPAT (252), suppress-prefix default and IPv6 preference.
    if ![0, 252].contains(&object.body[4])
        || object.body[..4] != wanted.body[..4]
        || object.body[5..12] != wanted.body[5..12]
    {
        return false;
    }
    let Ok(a) = attrs(&object.body) else {
        return false;
    };
    let Ok(b) = attrs(&wanted.body) else {
        return false;
    };
    if b.iter().any(|(key, value)| a.get(key) != Some(value)) {
        return false;
    }
    a.iter().all(|(key, value)| {
        b.contains_key(key)
            || (object.kind == NEW_RULE && *key == 14 && *value == u32::MAX.to_ne_bytes())
            || (object.kind == NEW_ROUTE
                && family == FAMILIES[1]
                && ((*key == 20 && *value == [0]) || (*key == 12 && *value == [0; 32])))
    })
}
fn snapshot() -> io::Result<Vec<Object>> {
    let mut result = Vec::new();
    for family in FAMILIES {
        result.extend(Rtnl::dump(GET_ROUTE, family)?);
        result.extend(Rtnl::dump(GET_RULE, family)?);
    }
    if result.len() > 16 {
        return Err(refused());
    }
    result.sort_by_key(|o| (o.kind, o.body[0]));
    Ok(result)
}
fn same(actual: &[Object], expected: &[Object]) -> bool {
    actual.len() == expected.len() && actual.iter().all(|o| expected.contains(o))
}
pub(crate) struct PolicyRoutes {
    intent: Intent,
    path: PathBuf,
    _lock: UnixDatagram,
}
impl PolicyRoutes {
    pub(crate) fn install(host: &File, guard: &Path, host_mode: bool) -> io::Result<Self> {
        let scope = Scope::current_mode(host, host_mode)?;
        if host_mode {
            super::host_path(guard)?;
        }
        // Serialize against any existing nftables owner before making
        // changes. The route lock then survives the entire capture epoch.
        let _guard_lock = scope_lock()?;
        let owner = lock()?;
        let path = path_for(guard);
        check_parent(&path)?;
        let intent = install_transaction(&path, scope, host_mode, snapshot, Rtnl::mutate, loopback_index)?;
        let result = Self {
            intent,
            path,
            _lock: owner,
        };
        if !result.current()? {
            return Err(refused());
        }
        Ok(result)
    }
    pub(crate) fn current(&self) -> io::Result<bool> {
        let meta = std::fs::metadata("/proc/thread-self/ns/net")?;
        use std::os::unix::fs::MetadataExt;
        Ok(
            (meta.dev(), meta.ino()) == (self.intent.scope.dev, self.intent.scope.ino)
                && self.intent.confirmed.len() == 4
                && loopback_index()? == self.intent.loopback
                && read_intent(&self.path, &self.intent.scope)?
                    .is_some_and(|(i, _)| i == self.intent)
                && same(&snapshot()?, &self.intent.confirmed),
        )
    }
}
// Called only while the nftables ownership lock is held. Remove the
// routes while the external egress guard is still present. No Drop
// rollback and no deletion based only on a reserved table number.
pub(super) fn recover_if_present(host: &File, guard: &Path, host_mode: bool) -> io::Result<()> {
    let path = path_for(guard);
    check_parent(&path)?;
    let _owner = lock()?;
    let scope = Scope::current_mode(host, host_mode)?;
    recover_transaction(&path, scope, host_mode, snapshot, Rtnl::mutate)
}

// Keep the durable state machine shared between the real kernel adapter
// and deterministic fault-injection tests. No alternate admission policy.
fn install_transaction(
    path: &Path,
    scope: Scope,
    host_mode: bool,
    mut read: impl FnMut() -> io::Result<Vec<Object>>,
    mut mutate: impl FnMut(u16, &[u8], bool) -> io::Result<()>,
    get_loopback: impl FnOnce() -> io::Result<u32>,
) -> io::Result<Intent> {
    let old = read_intent_mode(path, &scope, host_mode)?;
    if old
        .as_ref()
        .is_some_and(|(i, _)| i.scope == scope && !i.restored)
        || !read()?.is_empty()
    {
        return Err(refused());
    }
    // Old-boot records have no deletion authority. Stable absence of
    // all reserved objects is required before a new exclusive create.
    let lo = get_loopback()?;
    let mut intent = Intent {
        version: 1,
        scope,
        loopback: lo,
        confirmed: Vec::new(),
        restored: false,
    };
    let mut raw = write_intent(path, &intent, old.as_ref().map(|(_, b)| b.as_slice()))?;
    for kind in [NEW_ROUTE, NEW_RULE] {
        for family in FAMILIES {
            if !same(&read()?, &intent.confirmed) {
                return Err(refused());
            }
            let object = expected(kind, family, lo);
            mutate(kind, &object.body, true)?;
            let current = read()?;
            if current.len() != intent.confirmed.len() + 1
                || !intent.confirmed.iter().all(|o| current.contains(o))
            {
                return Err(refused());
            }
            let added = current
                .iter()
                .find(|o| !intent.confirmed.contains(o))
                .ok_or_else(refused)?;
            if added.kind != kind || added.body[0] != family || !exact(added, lo) {
                return Err(refused());
            }
            intent.confirmed.push(added.clone());
            raw = write_intent(path, &intent, Some(&raw))?;
        }
    }
    Ok(intent)
}

fn recover_transaction(
    path: &Path,
    scope: Scope,
    host_mode: bool,
    mut read: impl FnMut() -> io::Result<Vec<Object>>,
    mut mutate: impl FnMut(u16, &[u8], bool) -> io::Result<()>,
) -> io::Result<()> {
    let Some((mut intent, mut raw)) = read_intent_mode(path, &scope, host_mode)? else {
        return Ok(());
    };
    if intent.scope != scope {
        if !read()?.is_empty() {
            return Err(refused());
        }
        intent.scope = scope;
        intent.confirmed.clear();
        intent.restored = true;
        write_intent(path, &intent, Some(&raw))?;
        return Ok(());
    }
    if intent.restored {
        return if read()?.is_empty() {
            Ok(())
        } else {
            Err(refused())
        };
    }
    let mut current = read()?;
    if !current.iter().all(|o| intent.confirmed.contains(o)) {
        return Err(refused());
    }
    // An absent confirmed object can mean a prior interrupted removal.
    // Unknown or changed objects cannot be overwritten or deleted.
    for object in intent.confirmed.iter().rev() {
        if !current.contains(object) {
            continue;
        }
        crate::config::guarded_trust_assert(path, &raw).map_err(|_| refused())?;
        if !same(&read()?, &current) {
            return Err(refused());
        }
        let body = expected(object.kind, object.body[0], intent.loopback).body;
        mutate(
            if object.kind == NEW_RULE {
                DEL_RULE
            } else {
                DEL_ROUTE
            },
            &body,
            false,
        )?;
        current.retain(|o| o != object);
        if !same(&read()?, &current) {
            return Err(refused());
        }
    }
    intent.restored = true;
    raw = write_intent(path, &intent, Some(&raw))?;
    if raw.is_empty() {
        return Err(refused());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_journal_cas_boot_scope_and_object_validation() {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).unwrap();
        let name: String = random.iter().map(|n| format!("{n:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("theia-route-journal-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let guard = dir.join("guard.toml");
        let path = path_for(&guard);
        assert_eq!(path, dir.join("guard.toml.routes"));
        check_parent(&path).unwrap();
        let scope = Scope {
            boot: "00000000-0000-0000-0000-000000000001".into(),
            dev: 1,
            ino: 2,
            machine: Some("a".repeat(32)),
        };
        let mut intent = Intent {
            version: 1,
            scope: scope.clone(),
            loopback: 1,
            confirmed: vec![expected(NEW_ROUTE, FAMILIES[0], 1)],
            restored: false,
        };
        assert!(read_intent(&path, &scope).unwrap().is_none());
        let initial = write_intent(&path, &intent, None).unwrap();
        assert_eq!(
            read_intent(&path, &scope).unwrap(),
            Some((intent.clone(), initial.clone()))
        );
        intent.confirmed.push(expected(NEW_RULE, FAMILIES[1], 1));
        assert!(write_intent(&path, &intent, None).is_err());
        let second = write_intent(&path, &intent, Some(&initial)).unwrap();
        assert!(write_intent(&path, &intent, Some(&initial)).is_err());
        let mut reboot = scope.clone();
        reboot.boot = "00000000-0000-0000-0000-000000000002".into();
        assert!(read_intent(&path, &reboot).is_err());
        assert_eq!(
            read_intent_mode(&path, &reboot, true).unwrap(),
            Some((intent.clone(), second.clone()))
        );
        reboot.machine = Some("b".repeat(32));
        assert!(read_intent_mode(&path, &reboot, true).is_err());
        reboot.machine = None;
        assert!(read_intent_mode(&path, &reboot, true).is_err());
        let mut raw = second;
        for variant in 0..6 {
            let mut bad = intent.clone();
            match variant {
                0 => bad.version = 2,
                1 => bad.loopback = 0,
                2 => bad.confirmed.push(bad.confirmed[0].clone()),
                3 => bad.confirmed[0].body.clear(),
                4 => bad.confirmed[0].body.resize(257, 0),
                _ => bad.confirmed = vec![bad.confirmed[0].clone(); 5],
            }
            raw = write_intent(&path, &bad, Some(&raw)).unwrap();
            assert!(read_intent(&path, &scope).is_err());
        }
        let raw = write_intent(&path, &intent, Some(&raw)).unwrap();
        assert_eq!(read_intent(&path, &scope).unwrap(), Some((intent, raw)));
    }

    #[test]
    fn route_inventory_rejects_foreign_marks_and_malformed_attributes() {
        let foreign = Object {
            kind: NEW_RULE,
            body: vec![0; 12],
        };
        assert!(!relevant(&foreign).unwrap());
        for (key, value) in [
            (6, PRIORITY),
            (10, REDIRECT_MARK),
            (10, super::super::PASS_MARK),
            (15, TABLE),
        ] {
            let mut object = foreign.clone();
            attr(&mut object.body, key, &value.to_ne_bytes());
            assert!(relevant(&object).unwrap());
        }
        let mut masked = foreign.clone();
        attr(&mut masked.body, 10, &0u32.to_ne_bytes());
        attr(&mut masked.body, 16, &0u32.to_ne_bytes());
        assert!(relevant(&masked).unwrap());
        let mut duplicate = foreign.clone();
        attr(&mut duplicate.body, 6, &1u32.to_ne_bytes());
        attr(&mut duplicate.body, 6, &2u32.to_ne_bytes());
        assert!(relevant(&duplicate).is_err());
        let mut malformed = foreign.clone();
        attr(&mut malformed.body, 15, &[1, 2]);
        assert!(relevant(&malformed).is_err());
        assert!(attrs(&[0; 11]).is_err());
        assert!(!exact(
            &Object {
                kind: NEW_ROUTE,
                body: vec![]
            },
            1
        ));
        assert!(!exact(
            &Object {
                kind: 255,
                body: vec![FAMILIES[0]; 12]
            },
            1
        ));
        let mut rule = expected(NEW_RULE, FAMILIES[0], 1);
        attr(&mut rule.body, 14, &u32::MAX.to_ne_bytes());
        assert!(exact(&rule, 1));
        let mut route = expected(NEW_ROUTE, FAMILIES[1], 1);
        attr(&mut route.body, 20, &[0]);
        attr(&mut route.body, 12, &[0; 32]);
        assert!(exact(&route, 1));
        assert!(same(
            &[route.clone(), rule.clone()],
            &[rule.clone(), route.clone()]
        ));
        assert!(!same(&[route], &[rule]));
    }

    #[test]
    fn exact_route_and_rule_reject_changes() {
        for family in FAMILIES {
            for kind in [NEW_ROUTE, NEW_RULE] {
                let a = expected(kind, family, 1);
                assert!(exact(&a, 1));
                assert!(relevant(&a).unwrap());
                let mut changed = a.clone();
                changed.body[1] = 1;
                assert!(!exact(&changed, 1));
                let mut changed = a.clone();
                attr(&mut changed.body, 99, &[1]);
                assert!(!exact(&changed, 1));
            }
        }
    }
    #[test]
    fn multipart_route_dump_rejects_interrupted_truncated_foreign_sequence_and_invalid_completion() {
        fn frame(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            frame.extend_from_slice(&kind.to_ne_bytes());
            frame.extend_from_slice(&flags.to_ne_bytes());
            frame.extend_from_slice(&seq.to_ne_bytes());
            frame.extend_from_slice(&0u32.to_ne_bytes());
            frame.extend_from_slice(body);
            frame.resize(align4(frame.len()), 0);
            frame
        }
        for family in FAMILIES {
            for (get, new) in [(GET_ROUTE, NEW_ROUTE), (GET_RULE, NEW_RULE)] {
                let object = expected(new, family, 1);
                let mut foreign = vec![0; 12];
                foreign[0] = family;
                let first = frame(new, 2, 1, &foreign);
                let second = frame(new, 2, 1, &object.body);
                let done = frame(3, 2, 1, &[0; 4]);
                let mut seen = Vec::new();
                assert!(!decode_dump(&first, get, family, &mut seen).unwrap());
                assert!(seen.is_empty());
                assert!(!decode_dump(&second, get, family, &mut seen).unwrap());
                assert_eq!(seen, vec![object.clone()]);
                assert!(decode_dump(&done, get, family, &mut seen).unwrap());
                let combined = [first.as_slice(), second.as_slice(), done.as_slice()].concat();
                let mut seen = Vec::new();
                assert!(decode_dump(&combined, get, family, &mut seen).unwrap());
                assert_eq!(seen, vec![object.clone()]);
                for malformed in [
                    second[..15].to_vec(),
                    second[..second.len()-1].to_vec(),
                    frame(new, 0x10, 1, &object.body),
                    frame(new, 2, 2, &object.body),
                    frame(255, 2, 1, &object.body),
                    frame(new, 2, 1, &[family; 11]),
                    frame(new, 2, 1, &[0; 12]),
                    frame(3, 2, 1, &[1, 0, 0, 0]),
                    frame(3, 2, 1, &[0]),
                    [done.as_slice(), second.as_slice()].concat(),
                ] {
                    assert!(decode_dump(&malformed, get, family, &mut Vec::new()).is_err());
                }
                let mut capacity = vec![object.clone(); 4096];
                assert!(decode_dump(&second, get, family, &mut capacity).is_err());
            }
        }
    }

    #[test]
    fn kernel_route_inventory_is_read_only_and_bounded() {
        // RTM_GETROUTE/GETRULE only: no route installation, no elevation.
        for family in FAMILIES {
            for (get, new) in [(GET_ROUTE, NEW_ROUTE), (GET_RULE, NEW_RULE)] {
                let records = Rtnl::dump(get, family).unwrap();
                assert!(records.len() <= 4096);
                for record in records {
                    assert_eq!(record.kind, new);
                    assert_eq!(record.body[0], family);
                    assert!(relevant(&record).unwrap());
                }
            }
        }
    }

    #[test]
    fn transaction_requires_exact_readback_and_recovers_only_confirmed_objects() {
        use std::{cell::{Cell, RefCell}, os::unix::fs::DirBuilderExt};
        let mut random = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).unwrap();
        let name: String = random.iter().map(|n| format!("{n:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("theia-route-transaction-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        let _cleanup = Cleanup(dir.clone());
        let scope = Scope {
            boot: "00000000-0000-0000-0000-000000000001".into(),
            dev: 1, ino: 2, machine: Some("a".repeat(32)),
        };
        // At every possible mutation boundary simulate an interrupted
        // acknowledgement, including an object created but not confirmed.
        for fail_at in 0..=4 {
            for uncertain in [false, true] {
                let path = dir.join(format!("install-{fail_at}-{uncertain}"));
                let objects = RefCell::new(Vec::<Object>::new());
                let operations = Cell::new(0);
                let read = || Ok(objects.borrow().clone());
                let mutate = |kind, body: &[u8], create| {
                    assert!(create);
                    let n = operations.get();
                    operations.set(n + 1);
                    if n == fail_at {
                        if uncertain {
                            objects.borrow_mut().push(Object { kind, body: body.to_vec() });
                        }
                        return Err(refused());
                    }
                    objects.borrow_mut().push(Object { kind, body: body.to_vec() });
                    Ok(())
                };
                let result = install_transaction(&path, scope.clone(), false, read, mutate, || Ok(1));
                let (intent, _) = read_intent(&path, &scope).unwrap().unwrap();
                assert_eq!(intent.confirmed.len(), fail_at);
                assert!(!intent.restored);
                assert_eq!(result.is_ok(), fail_at == 4);
                let deletes = Cell::new(0);
                let recover = || recover_transaction(&path, scope.clone(), false, read, |kind, body, create| {
                    assert!(!create);
                    let kind = if kind == DEL_RULE { NEW_RULE } else { assert_eq!(kind, DEL_ROUTE); NEW_ROUTE };
                    let mut objects = objects.borrow_mut();
                    let position = objects.iter().position(|o| o.kind == kind && o.body == body).unwrap();
                    objects.remove(position);
                    deletes.set(deletes.get() + 1);
                    Ok(())
                });
                if uncertain && fail_at < 4 {
                    assert!(recover().is_err());
                    assert_eq!(deletes.get(), 0);
                    assert_eq!(objects.borrow().len(), fail_at + 1);
                } else {
                    recover().unwrap();
                    assert!(objects.borrow().is_empty());
                    assert_eq!(deletes.get(), fail_at);
                    assert!(read_intent(&path, &scope).unwrap().unwrap().0.restored);
                    recover().unwrap();
                    assert_eq!(deletes.get(), fail_at);
                }
            }
        }
        // A successful ACK alone is not enough: missing exact readback
        // must never become a confirmed object in the durable journal.
        let path = dir.join("missing-readback");
        let result = install_transaction(&path, scope.clone(), false, || Ok(vec![]), |_, _, _| Ok(()), || Ok(1));
        assert!(result.is_err());
        assert!(read_intent(&path, &scope).unwrap().unwrap().0.confirmed.is_empty());
        // Recovery across a reboot must not delete any route on the new boot.
        let path = dir.join("reboot");
        let old = Intent { version: 1, scope: scope.clone(), loopback: 1,
            confirmed: vec![expected(NEW_ROUTE, FAMILIES[0], 1)], restored: false };
        let raw = write_intent(&path, &old, None).unwrap();
        let mut reboot = scope.clone();
        reboot.boot = "00000000-0000-0000-0000-000000000002".into();
        assert!(recover_transaction(&path, reboot.clone(), true, || Ok(old.confirmed.clone()), |_,_,_| panic!("foreign object deletion")).is_err());
        assert_eq!(journal_bytes(&path).unwrap().unwrap(), raw);
        recover_transaction(&path, reboot.clone(), true, || Ok(vec![]), |_,_,_| panic!("old boot deletion")).unwrap();
        let new = read_intent(&path, &reboot).unwrap().unwrap().0;
        assert!(new.restored && new.confirmed.is_empty());
    }

}
