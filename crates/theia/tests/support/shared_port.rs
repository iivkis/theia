//! Real native shared TCP/UDP fixture allocation. UDP and TCP ephemeral
//! ranges can differ on Windows; choosing TCP first can repeatedly hit
//! excluded UDP ports. No fixed ports or fallback to different port numbers.
use std::net::{TcpListener, UdpSocket};

pub fn reserve_shared_port() -> (TcpListener, UdpSocket) {
    let mut last_error = None;
    // Hold rejected UDP reservations until selection finishes so the OS
    // cannot immediately hand the same unusable port back to this fixture.
    let mut rejected = Vec::new();
    for _ in 0..64 {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("reserve ephemeral UDP loopback socket");
        let address = udp.local_addr().unwrap();
        match TcpListener::bind(address) {
            Ok(tcp) => return (tcp, udp),
            Err(error) => {
                last_error = Some(error);
                rejected.push(udp);
            }
        }
    }
    panic!("reserve common native TCP/UDP loopback port: {last_error:?}");
}
