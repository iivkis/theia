//! Bounded UDP ingress for the native QUIC development backend.
//! Retry validates a physical address, not TLS identity or Theia admission.
//! Existing CID routing is also untrusted until the connection authenticates
//! the packet. The socket harness remains loopback-only until the full
//! connection driver and its security/interop gates are integrated.
use super::{
    datagram::{self, Demux, PacketKind, CID_LEN},
    negotiation::{self, Binding, Tokens, VersionPolicy, TOKEN_TTL},
    wire::Version,
};
use crate::reality_quic_wire::{long, retry_integrity_tag};
use ring::{hmac, rand::{SecureRandom, SystemRandom}};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    time::Instant,
};
use tokio::net::UdpSocket;

const MAX_DATAGRAM: usize = 65527;
const MAX_OWNER_CIDS: usize = 8;
type Cid = [u8; CID_LEN];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Drop,
    Reply(Vec<u8>),
    Existing(u64),
    Accepted { owner: u64, binding: Binding },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Owner,
    Clock,
    Random,
}

pub struct Ingress {
    routes: Demux,
    owners: BTreeMap<u64, BTreeSet<Cid>>,
    retired: BTreeMap<Cid, u64>,
    tokens: Tokens,
    reset_key: hmac::Key,
    resettable: BTreeSet<Cid>,
    next_owner: u64,
    limit: usize,
    occupied: usize,
    now: u64,
    versions: VersionPolicy,
}

impl Ingress {
    pub fn new(limit: usize) -> Result<Self, Error> {
        Self::with_versions(limit, VersionPolicy::both())
    }

    pub fn with_versions(limit: usize, versions: VersionPolicy) -> Result<Self, Error> {
        Ok(Self {
            routes: Demux::new(limit).map_err(|_| Error::Limit)?,
            owners: BTreeMap::new(),
            retired: BTreeMap::new(),
            tokens: Tokens::new().map_err(|_| Error::Random)?,
            reset_key: hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).map_err(|_| Error::Random)?,
            resettable: BTreeSet::new(),
            next_owner: 1,
            limit,
            occupied: 0,
            now: 0,
            versions,
        })
    }

    fn tick(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Clock);
        }
        self.now = now;
        let before = self.retired.len();
        self.retired.retain(|_, until| now <= *until);
        self.occupied -= before - self.retired.len();
        self.resettable.retain(|cid| self.retired.contains_key(cid) || self.routes.owner(*cid).is_some());
        Ok(())
    }

    fn available(&self, cid: Cid) -> bool {
        self.routes.owner(cid).is_none() && !self.retired.contains_key(&cid)
    }

    fn fresh_cid(&self, avoid: &[u8]) -> Result<Cid, Error> {
        for _ in 0..8 {
            let cid = negotiation::random_cid().map_err(|_| Error::Random)?;
            if cid != [0; CID_LEN] && cid.as_slice() != avoid && self.available(cid) {
                return Ok(cid);
            }
        }
        Err(Error::Limit)
    }

    /// The caller must only issue additional CIDs for its own live
    /// connection and send NEW_CONNECTION_ID in authenticated packets.
    pub fn issue_local_cid(&mut self, owner: u64, now: u64) -> Result<Cid, Error> {
        self.tick(now)?;
        let ids = self.owners.get(&owner).ok_or(Error::Owner)?;
        if ids.len() >= MAX_OWNER_CIDS || self.occupied >= self.limit {
            return Err(Error::Limit);
        }
        let cid = self.fresh_cid(&[])?;
        self.routes.register(cid, owner).map_err(|_| Error::Limit)?;
        self.owners.get_mut(&owner).ok_or(Error::Owner)?.insert(cid);
        self.occupied += 1;
        self.resettable.insert(cid);
        Ok(cid)
    }

    pub(crate) fn reset_token(&self, cid: Cid) -> [u8; 16] {
        let tag = hmac::sign(&self.reset_key, &cid);
        let mut token = [0; 16];
        token.copy_from_slice(&tag.as_ref()[..16]);
        token
    }

    /// Reply only for previously issued, retired aliases, never unknown
    /// CIDs. A strictly smaller response prevents reset loops/amplification.
    fn retired_reset(&self, cid: Cid, received: usize) -> Result<Action, Error> {
        if received <= 21 || !self.retired.contains_key(&cid) || !self.resettable.contains(&cid) {
            return Ok(Action::Drop);
        }
        let mut packet = vec![0; (received - 1).min(43)];
        SystemRandom::new().fill(&mut packet).map_err(|_| Error::Random)?;
        packet[0] = (packet[0] & 0x3f) | 0x40;
        let at = packet.len() - 16;
        packet[at..].copy_from_slice(&self.reset_token(cid));
        Ok(Action::Reply(packet))
    }

    /// Do not retire the last CID separately from connection teardown.
    pub fn retire_local_cid(&mut self, owner: u64, cid: Cid, now: u64) -> Result<(), Error> {
        self.tick(now)?;
        let until = now.checked_add(TOKEN_TTL).ok_or(Error::Clock)?;
        let ids = self.owners.get_mut(&owner).ok_or(Error::Owner)?;
        if ids.len() <= 1 || !ids.contains(&cid) {
            return Err(Error::Owner);
        }
        self.routes.retire(cid, owner).map_err(|_| Error::Owner)?;
        ids.remove(&cid);
        self.retired.insert(cid, until);
        Ok(())
    }

    /// The connection driver invokes this only after its draining deadline.
    /// Keep a bounded tombstone through the entire Retry replay window.
    pub fn close(&mut self, owner: u64, now: u64) -> Result<(), Error> {
        self.tick(now)?;
        let until = now.checked_add(TOKEN_TTL).ok_or(Error::Clock)?;
        let ids = self.owners.remove(&owner).ok_or(Error::Owner)?;
        self.routes.remove_owner(owner);
        for cid in ids {
            self.retired.insert(cid, until);
        }
        Ok(())
    }

    pub fn process(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
        now: u64,
    ) -> Result<Action, Error> {
        self.tick(now)?;
        if peer.port() == 0 || datagram.is_empty() || datagram.len() > MAX_DATAGRAM {
            return Ok(Action::Drop);
        }
        if let Some((version, dcid, scid)) = invariant_header(datagram) {
            if version != 0
                && Version::from_wire(version).is_none_or(|v| !self.versions.supports(v))
                && <Cid>::try_from(dcid)
                    .ok()
                    .is_none_or(|cid| self.available(cid))
            {
                let mut reply = vec![0x80];
                reply.extend([0; 4]);
                reply.push(scid.len() as u8);
                reply.extend_from_slice(scid);
                reply.push(dcid.len() as u8);
                reply.extend_from_slice(dcid);
                for v in self.versions.versions() {
                    reply.extend(v.wire().to_be_bytes());
                }
                return Ok(Action::Reply(reply));
            }
        }
        let Ok(packets) = datagram::split(datagram) else {
            return Ok(Action::Drop);
        };
        let Some(head) = packets.first() else {
            return Ok(Action::Drop);
        };
        if matches!(
            head.kind,
            PacketKind::Retry | PacketKind::VersionNegotiation
        ) {
            return Ok(Action::Drop);
        }
        let cid = <Cid>::try_from(head.destination).ok();
        if let Some(owner) = cid.and_then(|id| self.routes.owner(id)) {
            return Ok(Action::Existing(owner));
        }
        if head.kind == PacketKind::Application {
            return match cid { Some(cid) => self.retired_reset(cid, datagram.len()), None => Ok(Action::Drop) };
        }
        if head.kind != PacketKind::Initial || self.occupied >= self.limit {
            return Ok(Action::Drop);
        }
        if cid.is_some_and(|id| self.retired.contains_key(&id)) {
            return Ok(Action::Drop);
        }
        let Some(header) = long(head.bytes) else {
            return Ok(Action::Drop);
        };
        let Some(version) = head.version.filter(|v| self.versions.supports(*v)) else {
            return Ok(Action::Drop);
        };
        if header.token.is_empty() {
            let retry = self.fresh_cid(header.dcid)?;
            let binding = Binding {
                version,
                original: header.dcid.to_vec(),
                retry,
                client: header.scid.to_vec(),
            };
            let token = self
                .tokens
                .issue(peer, &binding, now)
                .map_err(|_| Error::Random)?;
            return Ok(Action::Reply(
                make_retry(&binding, &token).ok_or(Error::Limit)?,
            ));
        }
        let Some(cid) = cid else {
            return Ok(Action::Drop);
        };
        let Ok(binding) = self
            .tokens
            .verify(header.token, peer, version, cid, header.scid, now)
        else {
            return Ok(Action::Drop);
        };
        if !self.available(cid) {
            return Ok(Action::Drop);
        }
        let owner = self.next_owner;
        let next = owner.checked_add(1).ok_or(Error::Limit)?;
        self.routes.register(cid, owner).map_err(|_| Error::Limit)?;
        self.owners.insert(owner, BTreeSet::from([cid]));
        self.next_owner = next;
        self.occupied += 1;
        Ok(Action::Accepted { owner, binding })
    }
}

/// QUIC invariant header only. No type interpretation for unknown
/// versions. Bounded by the native endpoint's supported CID lengths.
fn invariant_header(bytes: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if bytes.len() < 1200 || bytes.first()? & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?);
    if version == 0 {
        return None;
    }
    let dlen = usize::from(*bytes.get(5)?);
    if !(8..=20).contains(&dlen) {
        return None;
    }
    let dcid = bytes.get(6..6 + dlen)?;
    let slen = usize::from(*bytes.get(6 + dlen)?);
    if slen > 20 {
        return None;
    }
    let scid = bytes.get(7 + dlen..7 + dlen + slen)?;
    Some((version, dcid, scid))
}

fn make_retry(binding: &Binding, token: &[u8]) -> Option<Vec<u8>> {
    let first = match binding.version {
        Version::V1 => 0xf0,
        Version::V2 => 0xc0,
    };
    let mut packet = vec![first];
    packet.extend(binding.version.wire().to_be_bytes());
    packet.push(binding.client.len() as u8);
    packet.extend_from_slice(&binding.client);
    packet.push(CID_LEN as u8);
    packet.extend(binding.retry);
    packet.extend_from_slice(token);
    let tag = retry_integrity_tag(binding.version.wire(), &packet, &binding.original)?;
    packet.extend(tag);
    Some(packet)
}

#[derive(Debug)]
pub enum UdpError {
    Io(io::Error),
    Ingress(Error),
    Scope,
}
#[derive(Debug)]
pub enum Event {
    Dropped,
    Replied,
    Datagram {
        peer: SocketAddr,
        bytes: Vec<u8>,
        action: Action,
    },
}

/// One real UDP socket and one serialized owner of the CID routing table.
/// No unbounded tasks or per-packet channels. The consumer must dispatch
/// authenticated connection processing; address validation is not admission.
pub struct UdpIngress {
    socket: UdpSocket,
    ingress: Ingress,
    clock: Instant,
    buffer: Vec<u8>,
}

impl UdpIngress {
    pub fn new(socket: UdpSocket, limit: usize) -> Result<Self, UdpError> {
        if !socket
            .local_addr()
            .map_err(UdpError::Io)?
            .ip()
            .is_loopback()
        {
            return Err(UdpError::Scope);
        }
        Ok(Self {
            socket,
            ingress: Ingress::new(limit).map_err(UdpError::Ingress)?,
            clock: Instant::now(),
            buffer: vec![0; MAX_DATAGRAM + 1],
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, UdpError> {
        self.socket.local_addr().map_err(UdpError::Io)
    }

    pub fn close(&mut self, owner: u64) -> Result<(), UdpError> {
        self.ingress
            .close(owner, self.clock.elapsed().as_secs())
            .map_err(UdpError::Ingress)
    }

    pub async fn receive(&mut self) -> Result<Event, UdpError> {
        let (n, peer) = self
            .socket
            .recv_from(&mut self.buffer)
            .await
            .map_err(UdpError::Io)?;
        if !peer.ip().is_loopback() {
            return Ok(Event::Dropped);
        }
        let action = self
            .ingress
            .process(peer, &self.buffer[..n], self.clock.elapsed().as_secs())
            .map_err(UdpError::Ingress)?;
        match action {
            Action::Drop => Ok(Event::Dropped),
            Action::Reply(bytes) => {
                // Both stateless responses are smaller than the triggering
                // datagram. Never amplify unvalidated traffic.
                if bytes.len() > n {
                    return Ok(Event::Dropped);
                }
                if self
                    .socket
                    .send_to(&bytes, peer)
                    .await
                    .map_err(UdpError::Io)?
                    != bytes.len()
                {
                    return Err(UdpError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short UDP send",
                    )));
                }
                Ok(Event::Replied)
            }
            action => Ok(Event::Datagram {
                peer,
                bytes: self.buffer[..n].to_vec(),
                action,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::initial::Writer;
    use rustls::Side;
    use std::time::Duration;

    fn initial(version: Version, dst: &[u8], src: &[u8], token: &[u8]) -> Vec<u8> {
        Writer::new(version, dst, Side::Client)
            .unwrap()
            .seal(dst, src, token, &[1])
            .unwrap()
    }
    fn short(cid: Cid) -> Vec<u8> {
        let mut bytes = vec![0x43];
        bytes.extend(cid);
        bytes.extend([0; 20]);
        bytes
    }

    #[test]
    fn retry_binding_cid_demux_and_replay_tombstones() {
        for version in [Version::V1, Version::V2] {
            let mut ingress = Ingress::new(2).unwrap();
            let peer = "127.0.0.1:1000".parse().unwrap();
            let other = "127.0.0.1:1001".parse().unwrap();
            let original = [1; 12];
            let client = [2; 8];
            let Action::Reply(retry) = ingress
                .process(peer, &initial(version, &original, &client, &[]), 0)
                .unwrap()
            else {
                panic!("Retry required")
            };
            let (new, token) =
                negotiation::retry_token(&retry, version, &client, &original, false, false)
                    .unwrap();
            let cid: Cid = new.try_into().unwrap();
            let packet = initial(version, &cid, &client, token);
            assert_eq!(ingress.process(other, &packet, 1), Ok(Action::Drop));
            assert_eq!(
                ingress.process(peer, &initial(version, &cid, &[3; 8], token), 1),
                Ok(Action::Drop)
            );
            let Action::Accepted { owner, binding } = ingress.process(peer, &packet, 1).unwrap()
            else {
                panic!("valid address token")
            };
            assert_eq!(binding.original, original);
            let mut joined = packet.clone();
            joined.extend(short(cid));
            assert_eq!(
                ingress.process(peer, &joined, 1),
                Ok(Action::Existing(owner))
            );
            let alias = ingress.issue_local_cid(owner, 1).unwrap();
            assert_eq!(ingress.issue_local_cid(owner, 1), Err(Error::Limit));
            // Routing new tuple does not validate migration.
            assert_eq!(
                ingress.process(other, &short(alias), 1),
                Ok(Action::Existing(owner))
            );
            assert_eq!(
                ingress.retire_local_cid(owner + 1, alias, 1),
                Err(Error::Owner)
            );
            ingress.retire_local_cid(owner, alias, 1).unwrap();
            let probe = short(alias);
            let Action::Reply(reset) = ingress.process(peer, &probe, 1).unwrap() else { panic!("retired alias reset") };
            assert!(reset.len() >= 21 && reset.len() < probe.len());
            assert_eq!(reset[0] & 0xc0, 0x40);
            assert_eq!(&reset[reset.len()-16..], &ingress.reset_token(alias));
            assert_eq!(ingress.process(peer, &short([0; 8]), 1), Ok(Action::Drop));
            assert_eq!(ingress.issue_local_cid(owner, 1), Err(Error::Limit));
            ingress.close(owner, 2).unwrap();
            assert_eq!(ingress.process(peer, &packet, 2), Ok(Action::Drop));
            assert_eq!(ingress.process(peer, &packet, 33), Ok(Action::Drop));
            assert_eq!(ingress.process(peer, &packet, 32), Err(Error::Clock));
        }
    }

    #[test]
    fn unknown_version_gets_bounded_vn_with_swapped_ids() {
        let mut ingress = Ingress::new(1).unwrap();
        let peer = "127.0.0.1:1000".parse().unwrap();
        let mut packet = initial(Version::V1, &[1; 8], &[2; 8], &[]);
        packet[1..5].copy_from_slice(&0x11223344u32.to_be_bytes());
        let Action::Reply(vn) = ingress.process(peer, &packet, 0).unwrap() else {
            panic!("VN required")
        };
        let h = long(&vn).unwrap();
        assert_eq!(h.version, 0);
        assert_eq!(h.dcid, &[2; 8]);
        assert_eq!(h.scid, &[1; 8]);
        assert_eq!(&vn[vn.len() - 8..], &[0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf]);
        assert_eq!(ingress.process(peer, &packet[..1199], 0), Ok(Action::Drop));
        assert_eq!(ingress.process(peer, &vn, 0), Ok(Action::Drop));
    }

    #[tokio::test]
    async fn actual_udp_retry_and_existing_route() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ingress = UdpIngress::new(server, 2).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = ingress.local_addr().unwrap();
        let version = Version::V2;
        let original = [7; 8];
        let client = [8; 8];
        tokio::time::timeout(Duration::from_secs(2), async {
            peer.send_to(&initial(version, &original, &client, &[]), dst).await.unwrap();
            assert!(matches!(ingress.receive().await.unwrap(), Event::Replied));
            let mut buffer = [0; 256];
            let (n, addr) = peer.recv_from(&mut buffer).await.unwrap();
            assert_eq!(addr, dst);
            let (cid, token) = negotiation::retry_token(&buffer[..n], version, &client, &original, false, false).unwrap();
            peer.send_to(&initial(version, cid, &client, token), dst).await.unwrap();
            let Event::Datagram { action: Action::Accepted { owner, .. }, .. } = ingress.receive().await.unwrap()
                else { panic!("expected candidate") };
            peer.send_to(&short(cid.try_into().unwrap()), dst).await.unwrap();
            assert!(matches!(ingress.receive().await.unwrap(), Event::Datagram { action: Action::Existing(id), .. } if id == owner));
            ingress.close(owner).unwrap();
            peer.send_to(&short(cid.try_into().unwrap()), dst).await.unwrap();
            assert!(matches!(ingress.receive().await.unwrap(), Event::Dropped));
        }).await.unwrap();
    }
}
