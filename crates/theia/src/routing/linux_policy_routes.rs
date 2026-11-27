//! Owned policy routing for the isolated native redirect. RTNL does not
//! expose nftables' generation CAS. Exclusive create and complete readback
//! are used instead; recovery refuses every uncertain or foreign object.
//! Requires a single trusted network administrator in this namespace.
use super::{Scope,REDIRECT_MARK,check_parent,journal_bytes,scope_lock,loopback_index,refused,invalid};
use crate::routing::nfqueue::{align4,attr,checked_header,kernel_address,next_attr,receive,send};
use serde::{Serialize,Deserialize};
use std::{fs::File,io,mem,os::fd::{AsRawFd,FromRawFd,OwnedFd},os::unix::net::UnixDatagram,path::{Path,PathBuf}};

const TABLE:u32=21577;
const PRIORITY:u32=21577;
const METRIC:u32=42760;
const PROTOCOL:u8=242;
const FAMILIES:[u8;2]=[libc::AF_INET as u8,libc::AF_INET6 as u8];
const NEW_ROUTE:u16=24;
const DEL_ROUTE:u16=25;
const GET_ROUTE:u16=26;
const NEW_RULE:u16=32;
const DEL_RULE:u16=33;
const GET_RULE:u16=34;

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Object { kind:u16, body:Vec<u8> }
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version:u8,
    scope:Scope,
    loopback:u32,
    // Only read-back objects confirmed after successful exclusive create
    // are deletable. A crash in the create/readback gap is manual recovery.
    confirmed:Vec<Object>,
    restored:bool,
}
fn path_for(path:&Path)->PathBuf {
    let mut name=path.as_os_str().to_os_string();
    name.push(".routes");
    PathBuf::from(name)
}
fn lock()->io::Result<UnixDatagram> {
    use std::os::linux::net::SocketAddrExt;
    UnixDatagram::bind_addr(&std::os::unix::net::SocketAddr::from_abstract_name(b"theia-owned-policy-routes-v1")?)
}
fn read_intent_mode(path:&Path,scope:&Scope,old_boot:bool)->io::Result<Option<(Intent,Vec<u8>)>> {
    let Some(raw)=journal_bytes(path)? else {return Ok(None);};
    let intent:Intent=toml::from_str(std::str::from_utf8(&raw).map_err(|_|invalid())?).map_err(|_|invalid())?;
    let same=&intent.scope==scope;
    let previous_boot=old_boot && scope.machine.is_some() && scope.machine==intent.scope.machine &&
        scope.boot!=intent.scope.boot && super::valid_boot_id(&intent.scope.boot);
    if intent.version!=1 || (!same && !previous_boot) || intent.loopback==0 ||
        intent.confirmed.len()>4 || intent.confirmed.iter().any(|o|o.body.len()>256 || !exact(o,intent.loopback)) ||
        intent.confirmed.iter().enumerate().any(|(i,o)|intent.confirmed[..i].iter().any(|a|a.kind==o.kind && a.body[0]==o.body[0])) {
        return Err(refused());
    }
    Ok(Some((intent,raw)))
}
fn read_intent(path:&Path,scope:&Scope)->io::Result<Option<(Intent,Vec<u8>)>> {
    read_intent_mode(path,scope,false)
}
fn write_intent(path:&Path,intent:&Intent,expected:Option<&[u8]>)->io::Result<Vec<u8>> {
    let value=toml::to_string(intent).map_err(|_|invalid())?;
    if value.len()>4096 {return Err(invalid());}
    crate::config::guarded_trust_write(path,&value,expected).map_err(|_|refused())?;
    let raw=journal_bytes(path)?.ok_or_else(refused)?;
    if raw!=value.as_bytes() {return Err(refused());}
    Ok(raw)
}
struct Rtnl(OwnedFd);
impl Rtnl {
    fn open()->io::Result<Self> {
        let raw=unsafe {libc::socket(libc::AF_NETLINK,libc::SOCK_RAW|libc::SOCK_CLOEXEC,libc::NETLINK_ROUTE)};
        if raw<0 {return Err(io::Error::last_os_error());}
        let fd=unsafe {OwnedFd::from_raw_fd(raw)};
        let local=kernel_address();
        if unsafe {libc::bind(raw,(&local as *const libc::sockaddr_nl).cast(),mem::size_of_val(&local) as libc::socklen_t)}!=0 {
            return Err(io::Error::last_os_error());
        }
        let timeout=libc::timeval{tv_sec:1,tv_usec:0};
        for option in [libc::SO_RCVTIMEO,libc::SO_SNDTIMEO] {
            if unsafe {libc::setsockopt(raw,libc::SOL_SOCKET,option,(&timeout as *const libc::timeval).cast(),mem::size_of_val(&timeout) as libc::socklen_t)}!=0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(fd))
    }
    fn request(&self,kind:u16,flags:u16,body:&[u8])->io::Result<()> {
        let mut bytes=Vec::with_capacity(16+body.len());
        bytes.extend_from_slice(&((16+body.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&1u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        send(self.0.as_raw_fd(),&bytes)
    }
    fn mutate(kind:u16,body:&[u8],create:bool)->io::Result<()> {
        let net=Self::open()?;
        net.request(kind,if create {0x605}else{5},body)?;
        let mut bytes=[0u8;8192];
        let n=receive(net.0.as_raw_fd(),&mut bytes)?;
        let (typ,seq,body)=checked_header(&bytes[..n])?;
        if typ!=2 || seq!=1 || body.len()<20 {return Err(invalid());}
        let errno=i32::from_ne_bytes(body[..4].try_into().map_err(|_|invalid())?);
        match errno {0=>Ok(()),n if n<0 && n!=i32::MIN=>Err(io::Error::from_raw_os_error(-n)),_=>Err(invalid())}
    }
    fn dump(kind:u16,family:u8)->io::Result<Vec<Object>> {
        let net=Self::open()?;
        let mut request=[0u8;12];request[0]=family;
        net.request(kind,0x301,&request)?;
        let mut bytes=vec![0u8;65536];
        let mut objects=Vec::new();
        for _ in 0..128 {
            let n=receive(net.0.as_raw_fd(),&mut bytes)?;
            let mut rest=&bytes[..n];
            while !rest.is_empty() {
                let header=rest.get(..16).ok_or_else(invalid)?;
                let len=u32::from_ne_bytes(header[..4].try_into().map_err(|_|invalid())?) as usize;
                if len<16 || align4(len)>rest.len() || u16::from_ne_bytes([header[6],header[7]])&0x10!=0 {
                    return Err(invalid()); // interrupted dump
                }
                let (typ,seq,body)=checked_header(&rest[..align4(len)])?;
                if seq!=1 {return Err(invalid());}
                if typ==3 {
                    if rest.len()!=align4(len) || (!body.is_empty() && (body.len()<4 || body[..4]!=[0;4])) {return Err(invalid());}
                    return Ok(objects);
                }
                if typ!=if kind==GET_ROUTE {NEW_ROUTE}else{NEW_RULE} || body.len()<12 || body[0]!=family || objects.len()>=4096 {
                    return Err(invalid());
                }
                let object=Object{kind:typ,body:body.to_vec()};
                if relevant(&object)? {objects.push(object);}
                rest=&rest[align4(len)..];
            }
        }
        Err(invalid())
    }
}
fn attrs(body:&[u8])->io::Result<std::collections::BTreeMap<u16,&[u8]>> {
    let mut rest=body.get(12..).ok_or_else(invalid)?;
    let mut map=std::collections::BTreeMap::new();
    while let Some((kind,value))=next_attr(&mut rest)? {
        if map.insert(kind,value).is_some() {return Err(invalid());}
    }
    Ok(map)
}
fn number(value:Option<&&[u8]>)->io::Result<Option<u32>> {
    value.map(|v|Ok(u32::from_ne_bytes((*v).try_into().map_err(|_|invalid())?))).transpose()
}
fn relevant(object:&Object)->io::Result<bool> {
    let a=attrs(&object.body)?;
    let table=number(a.get(&15))?.unwrap_or(u32::from(object.body[4]));
    if table==TABLE {return Ok(true);}
    if object.kind==NEW_RULE {
        if number(a.get(&6))?==Some(PRIORITY) {return Ok(true);}
        if let Some(mark)=number(a.get(&10))? {
            let mask=number(a.get(&16))?.unwrap_or(u32::MAX);
            if mark&mask==REDIRECT_MARK&mask || mark&mask==super::PASS_MARK&mask {return Ok(true);}
        }
    }
    Ok(false)
}
fn expected(kind:u16,family:u8,lo:u32)->Object {
    let mut body=vec![0u8;12];body[0]=family;
    if kind==NEW_ROUTE {
        body[5]=PROTOCOL;
        body[6]=if family==FAMILIES[0] {254}else{0};
        body[7]=2; // local
        attr(&mut body,4,&lo.to_ne_bytes());
        attr(&mut body,6,&METRIC.to_ne_bytes());
    } else {
        body[7]=1; // FR_ACT_TO_TBL
        attr(&mut body,6,&PRIORITY.to_ne_bytes());
        attr(&mut body,10,&REDIRECT_MARK.to_ne_bytes());
        attr(&mut body,16,&u32::MAX.to_ne_bytes());
        attr(&mut body,21,&[PROTOCOL]);
    }
    attr(&mut body,15,&TABLE.to_ne_bytes());
    Object{kind,body}
}
fn exact(object:&Object,lo:u32)->bool {
    let Some(&family)=object.body.first() else {return false;};
    if !FAMILIES.contains(&family) || ![NEW_ROUTE,NEW_RULE].contains(&object.kind) || object.body.len()<12 {return false;}
    let wanted=expected(object.kind,family,lo);
    // Kernel dumps may materialize unspecified route table (0) or
    // RT_TABLE_COMPAT (252), suppress-prefix default and IPv6 preference.
    if ![0,252].contains(&object.body[4]) || object.body[..4]!=wanted.body[..4] ||
        object.body[5..12]!=wanted.body[5..12] {return false;}
    let Ok(a)=attrs(&object.body) else {return false;};
    let Ok(b)=attrs(&wanted.body) else {return false;};
    if b.iter().any(|(key,value)|a.get(key)!=Some(value)) {return false;}
    a.iter().all(|(key,value)|b.contains_key(key) ||
        (object.kind==NEW_RULE && *key==14 && *value==u32::MAX.to_ne_bytes()) ||
        (object.kind==NEW_ROUTE && family==FAMILIES[1] &&
            ((*key==20 && *value==[0]) || (*key==12 && *value==[0;32]))))
}
fn snapshot()->io::Result<Vec<Object>> {
    let mut result=Vec::new();
    for family in FAMILIES {
        result.extend(Rtnl::dump(GET_ROUTE,family)?);
        result.extend(Rtnl::dump(GET_RULE,family)?);
    }
    if result.len()>16 {return Err(refused());}
    result.sort_by_key(|o|(o.kind,o.body[0]));
    Ok(result)
}
fn same(actual:&[Object],expected:&[Object])->bool {
    actual.len()==expected.len() && actual.iter().all(|o|expected.contains(o))
}
pub(crate) struct PolicyRoutes {
    intent:Intent,
    path:PathBuf,
    _lock:UnixDatagram,
}
impl PolicyRoutes {
    pub(crate) fn install(host:&File,guard:&Path,host_mode:bool)->io::Result<Self> {
        let scope=Scope::current_mode(host,host_mode)?;
        if host_mode {super::host_path(guard)?;}
        // Serialize against any existing nftables owner before making
        // changes. The route lock then survives the entire capture epoch.
        let _guard_lock=scope_lock()?;
        let owner=lock()?;
        let path=path_for(guard);
        check_parent(&path)?;
        let old=read_intent_mode(&path,&scope,host_mode)?;
        if old.as_ref().is_some_and(|(i,_)|i.scope==scope && !i.restored) || !snapshot()?.is_empty() {return Err(refused());}
        // Old-boot records have no deletion authority. Stable absence of
        // all reserved objects is required before a new exclusive create.
        let lo=loopback_index()?;
        let mut intent=Intent{version:1,scope,loopback:lo,confirmed:Vec::new(),restored:false};
        let mut raw=write_intent(&path,&intent,old.as_ref().map(|(_,b)|b.as_slice()))?;
        for kind in [NEW_ROUTE,NEW_RULE] {
            for family in FAMILIES {
                if !same(&snapshot()?,&intent.confirmed) {return Err(refused());}
                let object=expected(kind,family,lo);
                Rtnl::mutate(kind,&object.body,true)?;
                let current=snapshot()?;
                if current.len()!=intent.confirmed.len()+1 ||
                    !intent.confirmed.iter().all(|o|current.contains(o)) {return Err(refused());}
                let added=current.iter().find(|o|!intent.confirmed.contains(o)).ok_or_else(refused)?;
                if added.kind!=kind || added.body[0]!=family || !exact(added,lo) {return Err(refused());}
                intent.confirmed.push(added.clone());
                raw=write_intent(&path,&intent,Some(&raw))?;
            }
        }
        let result=Self{intent,path,_lock:owner};
        if !result.current()? {return Err(refused());}
        Ok(result)
    }
    pub(crate) fn current(&self)->io::Result<bool> {
        let meta=std::fs::metadata("/proc/thread-self/ns/net")?;
        use std::os::unix::fs::MetadataExt;
        Ok((meta.dev(),meta.ino())==(self.intent.scope.dev,self.intent.scope.ino) &&
            self.intent.confirmed.len()==4 && loopback_index()?==self.intent.loopback &&
            read_intent(&self.path,&self.intent.scope)?.is_some_and(|(i,_)|i==self.intent) &&
            same(&snapshot()?,&self.intent.confirmed))
    }
}
// Called only while the nftables ownership lock is held. Remove the
// routes while the external egress guard is still present. No Drop
// rollback and no deletion based only on a reserved table number.
pub(super) fn recover_if_present(host:&File,guard:&Path,host_mode:bool)->io::Result<()> {
    let path=path_for(guard);
    check_parent(&path)?;
    let _owner=lock()?;
    let scope=Scope::current_mode(host,host_mode)?;
    let Some((mut intent,mut raw))=read_intent_mode(&path,&scope,host_mode)? else {return Ok(());};
    if intent.scope!=scope {
        if !snapshot()?.is_empty() {return Err(refused());}
        intent.scope=scope;intent.confirmed.clear();intent.restored=true;
        write_intent(&path,&intent,Some(&raw))?;
        return Ok(());
    }
    if intent.restored {return if snapshot()?.is_empty(){Ok(())}else{Err(refused())};}
    let mut current=snapshot()?;
    if !current.iter().all(|o|intent.confirmed.contains(o)) {return Err(refused());}
    // An absent confirmed object can mean a prior interrupted removal.
    // Unknown or changed objects cannot be overwritten or deleted.
    for object in intent.confirmed.iter().rev() {
        if !current.contains(object) {continue;}
        crate::config::guarded_trust_assert(&path,&raw).map_err(|_|refused())?;
        if !same(&snapshot()?,&current) {return Err(refused());}
        let body=expected(object.kind,object.body[0],intent.loopback).body;
        Rtnl::mutate(if object.kind==NEW_RULE {DEL_RULE}else{DEL_ROUTE},&body,false)?;
        current.retain(|o|o!=object);
        if !same(&snapshot()?,&current) {return Err(refused());}
    }
    intent.restored=true;
    raw=write_intent(&path,&intent,Some(&raw))?;
    if raw.is_empty() {return Err(refused());}
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_route_and_rule_reject_changes() {
        for family in FAMILIES {
            for kind in [NEW_ROUTE,NEW_RULE] {
                let a=expected(kind,family,1);
                assert!(exact(&a,1));
                assert!(relevant(&a).unwrap());
                let mut changed=a.clone();
                changed.body[1]=1;
                assert!(!exact(&changed,1));
                let mut changed=a.clone();
                attr(&mut changed.body,99,&[1]);
                assert!(!exact(&changed,1));
            }
        }
    }
}
