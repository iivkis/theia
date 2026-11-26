//! Bounded UDP datagram routing for a future native listener. Header
//! inspection is not authentication; the connection owner must authenticate
//! packets and validate new paths before applying any state changes.
use super::wire::Version;
use crate::reality_quic_wire::{long, Kind};
use std::collections::BTreeMap;

const MAX_DATAGRAM: usize = 65527;
const MAX_PACKETS: usize = 64;
const MAX_ROUTES: usize = 16384;
pub const CID_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Malformed, MixedCid, Limit, Collision, Owner, Unsupported }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind { Initial, Handshake, Application, Retry, VersionNegotiation }

#[derive(Debug)]
pub struct Packet<'a> {
    pub kind: PacketKind,
    pub version: Option<Version>,
    pub destination: &'a [u8],
    pub source: Option<&'a [u8]>,
    pub bytes: &'a [u8],
}

/// Parse complete boundaries before dispatch. A short packet and Retry/VN
/// consume the remainder. No 0-RTT or fixed-bit greasing in this stage.
/// An Initial's 1200-byte minimum applies to the whole UDP datagram,
/// not each individual packet.
pub fn split(datagram: &[u8]) -> Result<Vec<Packet<'_>>, Error> {
    if datagram.is_empty() || datagram.len() > MAX_DATAGRAM { return Err(Error::Limit); }
    let mut out: Vec<Packet<'_>> = Vec::new();
    let mut remaining = datagram;
    while !remaining.is_empty() {
        if out.len() == MAX_PACKETS { return Err(Error::Limit); }
        let first = remaining[0];
        let packet = if first & 0x80 == 0 {
            if first & 0x40 == 0 || remaining.len() < 1 + CID_LEN + 4 + 16 { return Err(Error::Malformed); }
            Packet { kind: PacketKind::Application, version: None, destination: &remaining[1..1 + CID_LEN],
                source: None, bytes: remaining }
        } else {
            let h = long(remaining).ok_or(Error::Malformed)?;
            let kind = match h.kind {
                Kind::Initial => PacketKind::Initial,
                Kind::Handshake => PacketKind::Handshake,
                Kind::Retry => PacketKind::Retry,
                Kind::VersionNegotiation => PacketKind::VersionNegotiation,
                Kind::ZeroRtt => return Err(Error::Unsupported),
            };
            if h.dcid.len() != CID_LEN || h.scid.len() > 20 { return Err(Error::Malformed); }
            if kind != PacketKind::VersionNegotiation && first & 0x40 == 0 { return Err(Error::Malformed); }
            if kind == PacketKind::Initial && datagram.len() < 1200 { return Err(Error::Malformed); }
            if matches!(kind, PacketKind::Retry | PacketKind::VersionNegotiation) && !out.is_empty() {
                return Err(Error::Malformed);
            }
            Packet { kind, version: Version::from_wire(h.version), destination: h.dcid,
                source: Some(h.scid), bytes: &remaining[..h.end] }
        };
        if let Some(head) = out.first() {
            if packet.destination != head.destination
                || (packet.version.is_some() && packet.version != head.version) {
                return Err(Error::MixedCid);
            }
        }
        remaining = &remaining[packet.bytes.len()..];
        out.push(packet);
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route { Existing(u64), NewInitial, Drop }

/// The owner is a non-reused connection handle supplied by the listener.
/// A CID collision cannot overwrite an existing connection, and retirement
/// checks the owner to prevent stale teardown from deleting another route.
pub struct Demux {
    limit: usize,
    routes: BTreeMap<[u8; CID_LEN], u64>,
}

impl Demux {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 || limit > MAX_ROUTES { return Err(Error::Limit); }
        Ok(Self { limit, routes: BTreeMap::new() })
    }

    pub fn register(&mut self, cid: [u8; CID_LEN], owner: u64) -> Result<(), Error> {
        if let Some(old) = self.routes.get(&cid) {
            return if *old == owner { Ok(()) } else { Err(Error::Collision) };
        }
        if self.routes.len() >= self.limit { return Err(Error::Limit); }
        self.routes.insert(cid, owner);
        Ok(())
    }

    pub fn retire(&mut self, cid: [u8; CID_LEN], owner: u64) -> Result<(), Error> {
        if self.routes.get(&cid) != Some(&owner) { return Err(Error::Owner); }
        self.routes.remove(&cid);
        Ok(())
    }

    pub fn remove_owner(&mut self, owner: u64) {
        self.routes.retain(|_, value| *value != owner);
    }

    /// Unknown Initial is only a candidate, never an allocated connection.
    /// The caller applies Retry, admission and resource gates separately.
    pub fn classify(&self, datagram: &[u8]) -> Result<Route, Error> {
        let packets = split(datagram)?;
        let head = packets.first().ok_or(Error::Malformed)?;
        let cid: [u8; CID_LEN] = head.destination.try_into().map_err(|_| Error::Malformed)?;
        Ok(if let Some(owner) = self.routes.get(&cid) {
            Route::Existing(*owner)
        } else if head.kind == PacketKind::Initial {
            Route::NewInitial
        } else {
            Route::Drop
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::initial::Writer;
    use rustls::Side;

    fn short(cid: [u8; CID_LEN]) -> Vec<u8> {
        let mut bytes = vec![0x43];
        bytes.extend(cid);
        bytes.extend([0; 20]);
        bytes
    }

    #[test]
    fn coalescing_and_cid_ownership() {
        for version in [Version::V1, Version::V2] {
            let cid = [1; CID_LEN];
            let mut writer = Writer::new(version, &cid, Side::Client).unwrap();
            let initial = writer.seal(&cid, &[2; CID_LEN], &[], &[1]).unwrap();
            let mut mixed = initial.clone();
            mixed.extend(short([3; CID_LEN]));
            assert!(matches!(split(&mixed), Err(Error::MixedCid)));
            let mut joined = initial.clone();
            joined.extend(short(cid));
            let packets = split(&joined).unwrap();
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].kind, PacketKind::Initial);
            assert_eq!(packets[1].kind, PacketKind::Application);
            assert_eq!(packets[0].bytes, initial);
            let mut routes = Demux::new(1).unwrap();
            assert_eq!(routes.classify(&joined), Ok(Route::NewInitial));
            assert_eq!(routes.classify(&short(cid)), Ok(Route::Drop));
            routes.register(cid, 7).unwrap();
            assert_eq!(routes.register(cid, 8), Err(Error::Collision));
            assert_eq!(routes.register([2; CID_LEN], 7), Err(Error::Limit));
            assert_eq!(routes.classify(&joined), Ok(Route::Existing(7)));
            assert_eq!(routes.retire(cid, 8), Err(Error::Owner));
            routes.remove_owner(7);
            assert_eq!(routes.classify(&short(cid)), Ok(Route::Drop));
            routes.register(cid, 8).unwrap();
            assert_eq!(routes.retire(cid, 7), Err(Error::Owner));
            assert_eq!(routes.classify(&short(cid)), Ok(Route::Existing(8)));
        }
    }

    #[test]
    fn rejects_truncated_and_unnegotiated_zero_rtt() {
        assert!(split(&[0x43; 10]).is_err());
        let cid = [1; CID_LEN];
        let mut writer = Writer::new(Version::V1, &cid, Side::Client).unwrap();
        let mut packet = writer.seal(&cid, &[2; CID_LEN], &[], &[1]).unwrap();
        assert!(split(&packet[..100]).is_err());
        // Construct a structural 0-RTT header by removing the Initial token
        // length (zero) and changing only the unprotected packet type.
        packet.remove(23);
        packet[0] = 0xd0;
        assert!(matches!(split(&packet), Err(Error::Unsupported)));
    }
}
