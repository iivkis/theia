//! Reserve both native sockets on the exact same loopback port.
//! Windows can exclude a different range for TCP and UDP. Try both native
//! ephemeral allocators, then sample the dynamic range in a random order.
use std::net::{TcpListener, UdpSocket};

pub fn reserve_shared_port() -> (TcpListener, UdpSocket) {
    let mut rejected_udp = Vec::new();
    let mut rejected_tcp = Vec::new();
    for _ in 0..64 {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("reserve ephemeral UDP loopback socket");
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
            return (tcp, udp);
        }
        rejected_udp.push(udp);
        let tcp = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral TCP loopback socket");
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()) {
            return (tcp, udp);
        }
        rejected_tcp.push(tcp);
    }
    drop(rejected_tcp);
    drop(rejected_udp);
    // The OS allocators can be restricted to disjoint pools. Walk all ports
    // in the IANA dynamic range in a randomized permutation, not fixed ports.
    let mut random = [0u8; 4];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .expect("randomize shared port search");
    let start = u16::from_ne_bytes([random[0], random[1]]) & 0x3fff;
    let stride = (u16::from_ne_bytes([random[2], random[3]]) & 0x3fff) | 1;
    let mut last_error = None;
    for step in 0u16..16384 {
        let port = 49152 + (start.wrapping_add(step.wrapping_mul(stride)) & 0x3fff);
        let address = ("127.0.0.1", port);
        let tcp = match TcpListener::bind(address) {
            Ok(tcp) => tcp,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match UdpSocket::bind(address) {
            Ok(udp) => return (tcp, udp),
            Err(error) => last_error = Some(error),
        }
    }
    panic!("reserve common native TCP/UDP loopback port: {last_error:?}");
}
