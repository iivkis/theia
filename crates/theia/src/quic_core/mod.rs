//! Native QUIC foundation. Not a selectable endpoint until interoperability,
//! security and performance gates pass. Existing H3 remains on Quinn.
#![forbid(unsafe_code)]

pub mod ack;
pub mod ack_tx;
pub mod bbr;
pub mod congestion;
pub mod datagram;
pub mod endpoint;
pub mod ecn;
pub mod flow;
pub mod frames;
pub mod h3_adapter;
pub mod handshake;
pub mod handshake_udp;
pub mod ingress;
pub mod initial;
pub mod key_update;
pub mod lifecycle;
pub mod listener;
pub mod loss;
pub mod negotiation;
pub mod packet;
pub mod parameters;
pub mod path;
pub mod recovery;
pub mod scheduler;
pub mod send_flow;
pub mod spaces;
pub mod stream;
pub mod tls;
pub mod wire;

#[cfg(test)]
mod mutation_tests;

/// The experimental native transport must never become an externally reachable
/// carrier before independent admission and interoperability acceptance.
pub(crate) fn loopback_pair(local: std::net::SocketAddr, peer: std::net::SocketAddr) -> bool {
    local.ip().is_loopback() && peer.ip().is_loopback() && peer.port() != 0 && local != peer
}

#[cfg(test)]
mod scope_tests {
    use super::loopback_pair;
    #[test]
    fn laboratory_scope_rejects_external_and_invalid_peers() {
        let local = "127.0.0.1:1234".parse().unwrap();
        let peer = "127.0.0.1:4321".parse().unwrap();
        assert!(loopback_pair(local, peer));
        assert!(!loopback_pair(local, local));
        assert!(!loopback_pair(local, "127.0.0.1:0".parse().unwrap()));
        assert!(!loopback_pair(local, "192.0.2.1:443".parse().unwrap()));
        assert!(!loopback_pair("0.0.0.0:1234".parse().unwrap(), peer));
        assert!(loopback_pair(
            "[::1]:1234".parse().unwrap(),
            "[::1]:4321".parse().unwrap()
        ));
    }
}
