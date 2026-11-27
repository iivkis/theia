//! Shared, bounded L3 packet metadata for the native ingress adapters.
//! This does not infer a hostname or application identity from an IP address.
use super::{ApplicationId, Classification, Evidence, Policy, RoutingError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    Invalid,
    Fragment,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: Transport,
    /// Kernel interface/compartment identity, supplied by the backend.
    pub interface: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub flow: FlowKey,
    pub payload_len: usize,
    pub tcp_flags: Option<u16>,
}

impl PacketMeta {
    /// Complete non-GSO L3 packet only. No fragment reassembly, IPv4 source
    /// routing, IPv6 routing headers or jumbograms are silently accepted.
    pub fn parse(bytes: &[u8], interface: u32) -> Result<Self, ParseError> {
        let version = bytes.first().ok_or(ParseError::Truncated)? >> 4;
        let (source, destination, mut next, mut offset) = match version {
            4 => {
                let header = bytes.get(..20).ok_or(ParseError::Truncated)?;
                let ihl = usize::from(header[0] & 15) * 4;
                let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
                if ihl < 20 || len < ihl || len != bytes.len() {
                    return Err(ParseError::Invalid);
                }
                let fragment = u16::from_be_bytes([header[6], header[7]]);
                if fragment & 0x8000 != 0 {
                    return Err(ParseError::Invalid);
                }
                if fragment & 0x3fff != 0 {
                    return Err(ParseError::Fragment);
                }
                if ihl != 20 {
                    return Err(ParseError::Unsupported);
                }
                (
                    IpAddr::V4(Ipv4Addr::new(
                        header[12], header[13], header[14], header[15],
                    )),
                    IpAddr::V4(Ipv4Addr::new(
                        header[16], header[17], header[18], header[19],
                    )),
                    header[9],
                    ihl,
                )
            }
            6 => {
                let header = bytes.get(..40).ok_or(ParseError::Truncated)?;
                let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
                if len == 0 || 40 + len != bytes.len() {
                    return Err(ParseError::Invalid);
                }
                let source =
                    <[u8; 16]>::try_from(&header[8..24]).map_err(|_| ParseError::Invalid)?;
                let destination =
                    <[u8; 16]>::try_from(&header[24..40]).map_err(|_| ParseError::Invalid)?;
                (
                    IpAddr::V6(Ipv6Addr::from(source)),
                    IpAddr::V6(Ipv6Addr::from(destination)),
                    header[6],
                    40,
                )
            }
            _ => return Err(ParseError::Unsupported),
        };
        if version == 6 {
            let mut extension_count = 0;
            while matches!(next, 0 | 60) {
                if extension_count == 8 || (next == 0 && offset != 40) {
                    return Err(ParseError::Unsupported);
                }
                let header = bytes.get(offset..offset + 2).ok_or(ParseError::Truncated)?;
                let len = (usize::from(header[1]) + 1) * 8;
                if bytes.get(offset..offset + len).is_none() {
                    return Err(ParseError::Truncated);
                }
                next = header[0];
                offset += len;
                extension_count += 1;
            }
            if next == 44 {
                return Err(ParseError::Fragment);
            }
        }
        let transport = bytes.get(offset..).ok_or(ParseError::Truncated)?;
        let ports = transport.get(..4).ok_or(ParseError::Truncated)?;
        let source_port = u16::from_be_bytes([ports[0], ports[1]]);
        let destination_port = u16::from_be_bytes([ports[2], ports[3]]);
        if source_port == 0 || destination_port == 0 {
            return Err(ParseError::Invalid);
        }
        let (kind, header_len, tcp_flags) = match next {
            6 => {
                let header = transport.get(..20).ok_or(ParseError::Truncated)?;
                let len = usize::from(header[12] >> 4) * 4;
                if len < 20 || len > transport.len() || header[12] & 0x0e != 0 {
                    return Err(ParseError::Invalid);
                }
                (
                    Transport::Tcp,
                    len,
                    Some((u16::from(header[12] & 1) << 8) | u16::from(header[13])),
                )
            }
            17 => {
                let header = transport.get(..8).ok_or(ParseError::Truncated)?;
                let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
                if len != transport.len() || len < 8 {
                    return Err(ParseError::Invalid);
                }
                (Transport::Udp, 8, None)
            }
            _ => return Err(ParseError::Unsupported),
        };
        Ok(Self {
            flow: FlowKey {
                source: SocketAddr::new(source, source_port),
                destination: SocketAddr::new(destination, destination_port),
                transport: kind,
                interface,
            },
            payload_len: transport.len() - header_len,
            tcp_flags,
        })
    }

    /// The caller must supply independently verified domain/application
    /// attribution. Missing attribution is Unknown, never guessed from SNI,
    /// reverse DNS, PID or the destination IP.
    pub fn classify(
        &self,
        policy: &Policy,
        domain: Evidence<&str>,
        application: Evidence<ApplicationId>,
    ) -> Result<Classification, RoutingError> {
        policy.classify_with_application(
            domain,
            Evidence::Known(self.flow.destination.ip()),
            application,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{Action, Rule};

    fn tcp4() -> Vec<u8> {
        let mut b = vec![0u8; 43];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&43u16.to_be_bytes());
        b[9] = 6;
        b[12..16].copy_from_slice(&[192, 0, 2, 1]);
        b[16..20].copy_from_slice(&[198, 51, 100, 2]);
        b[20..22].copy_from_slice(&1234u16.to_be_bytes());
        b[22..24].copy_from_slice(&443u16.to_be_bytes());
        b[32] = 0x50;
        b[33] = 0x02; // SYN carrying three bytes: first payload is not delayed.
        b
    }

    #[test]
    fn exact_tuple_and_syn_payload() {
        let p = PacketMeta::parse(&tcp4(), 7).unwrap();
        assert_eq!(p.flow.source, "192.0.2.1:1234".parse().unwrap());
        assert_eq!(p.flow.destination, "198.51.100.2:443".parse().unwrap());
        assert_eq!(p.flow.transport, Transport::Tcp);
        assert_eq!(p.flow.interface, 7);
        assert_eq!(p.payload_len, 3);
        assert_eq!(p.tcp_flags, Some(2));
        let policy = Policy::compile(
            &[
                Rule {
                    name: "blocked".into(),
                    action: Action::Blocked,
                    domains: vec!["blocked.example".into()],
                    ips: vec![],
                    applications: vec![],
                },
                Rule {
                    name: "ip".into(),
                    action: Action::Direct,
                    domains: vec![],
                    ips: vec!["198.51.100.0/24".into()],
                    applications: vec![],
                },
            ],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            p.classify(&policy, Evidence::Unknown, Evidence::Unknown)
                .unwrap(),
            Classification::Unresolved
        );
        assert_eq!(
            p.classify(&policy, Evidence::Absent, Evidence::Unknown)
                .unwrap(),
            Classification::Matched(Action::Direct)
        );
    }

    #[test]
    fn ipv6_udp_extension_and_fragment_refusal() {
        let mut b = vec![0u8; 59];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&19u16.to_be_bytes());
        b[6] = 60;
        b[8] = 0x20;
        b[24] = 0x20;
        b[39] = 1;
        b[40] = 17;
        b[48..50].copy_from_slice(&1234u16.to_be_bytes());
        b[50..52].copy_from_slice(&443u16.to_be_bytes());
        b[52..54].copy_from_slice(&11u16.to_be_bytes());
        let meta = PacketMeta::parse(&b, 4).unwrap();
        assert_eq!(meta.flow.transport, Transport::Udp);
        assert_eq!(meta.payload_len, 3);
        b[6] = 44;
        assert_eq!(PacketMeta::parse(&b, 4), Err(ParseError::Fragment));
        b[6] = 43;
        assert!(PacketMeta::parse(&b, 4).is_err());
    }

    #[test]
    fn truncated_and_malformed_packets_fail_closed() {
        let b = tcp4();
        for end in 0..b.len() {
            assert!(PacketMeta::parse(&b[..end], 1).is_err());
        }
        let mut fragment = b.clone();
        fragment[6] = 0x20;
        assert_eq!(PacketMeta::parse(&fragment, 1), Err(ParseError::Fragment));
        let mut malformed = b;
        malformed[32] = 0x40;
        assert_eq!(PacketMeta::parse(&malformed, 1), Err(ParseError::Invalid));
    }
}
