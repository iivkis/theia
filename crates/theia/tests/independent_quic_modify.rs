//! Independent actual loopback UDP and HTTP/3 on both QUIC versions.
//! The aioquic fixture originates genuine Initial/0-RTT packets, then only
//! the Rust transformation result is emitted by the independent client.
//! Does not prove production capture, physical networks or DPI effectiveness.
#[path = "support/private_pem.rs"]
mod private_pem;

use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use theia::routing::packet_modify::quic_initial_datagrams;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_field(reader: &mut impl Read) -> Vec<u8> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).unwrap();
    let size = u32::from_be_bytes(size) as usize;
    assert!((1..=65527).contains(&size));
    let mut packet = vec![0; size];
    reader.read_exact(&mut packet).unwrap();
    packet
}

#[test]
#[ignore = "requires pinned aioquic from browser-e2e CI"]
fn independent_aioquic_live_modify_v1_v2() {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "theia-live-modify-{}", std::process::id()
    )));
    fs::create_dir(&scratch.0).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(scratch.0.join("cert.pem"), cert.cert.pem()).unwrap();
    private_pem::write_new_key(&scratch.0.join("key.pem"), cert.key_pair.serialize_pem());
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/e2e/independent_quic_live_modify.py");
    for version in [1u32, 0x6b33_43cf] {
        let mut peer = Peer(Command::new("python").arg(&script).arg(&scratch.0)
            .arg(version.to_string()).stdin(Stdio::piped()).stdout(Stdio::piped())
            .spawn().unwrap());
        let mut stdout = peer.0.stdout.take().unwrap();
        let input = read_field(&mut stdout);
        let outputs = quic_initial_datagrams(&input, "localhost").expect("genuine coalesced flight");
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs.concat(), input);
        assert!(outputs[0].len() >= 1200);
        assert!(quic_initial_datagrams(&input, "wrong.example").is_none());
        let mut corrupted = input.clone();
        corrupted[100] ^= 1;
        assert!(quic_initial_datagrams(&corrupted, "localhost").is_none());
        {
            let mut stdin = peer.0.stdin.take().unwrap();
            stdin.write_all(&[2]).unwrap();
            for packet in &outputs {
                stdin.write_all(&(packet.len() as u32).to_be_bytes()).unwrap();
                stdin.write_all(packet).unwrap();
            }
        }
        let mut trailing = Vec::new();
        stdout.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty(), "unexpected independent fixture output");
        assert!(peer.0.wait().unwrap().success(), "live QUIC v1/v2 Modify failed");
    }
}
