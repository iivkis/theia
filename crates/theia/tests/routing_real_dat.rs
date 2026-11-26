//! Explicit online acceptance and local snapshot CPU/size measurements.
//! This is not a physical-host test or a measurement of H2/H3 network RTT.
use std::time::Instant;
use theia::routing::{geodata::Store, snapshot::Snapshot, Action, Rule};

#[tokio::test]
#[ignore = "explicit online diagnostic: downloads real XTLS release"]
async fn real_xtls_pair_and_snapshot_cost() {
    let mut random = [0u8; 16];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new().fill(&mut random).unwrap();
    let suffix = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let directory = std::env::temp_dir().join(format!("theia-routing-dat-{suffix}"));
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let store = Store::new(directory.canonicalize().unwrap()).unwrap();
    let rules = [
        Rule {
            name: "google".into(),
            action: Action::Direct,
            domains: vec!["geosite:google".into()],
            ips: vec![],
            applications: vec![],
        },
        Rule {
            name: "private".into(),
            action: Action::Blocked,
            domains: vec![],
            ips: vec!["geoip:private".into()],
            applications: vec![],
        },
    ];
    let start = Instant::now();
    let pair = store
        .refresh(&rules)
        .await
        .expect("real XTLS pair, verified by production loader");
    let refresh_ms = start.elapsed().as_millis();
    let manifest = pair.manifest();
    assert!(pair.geosite().len() <= 32 * 1024 * 1024);
    assert!(pair.geoip().len() <= 32 * 1024 * 1024);
    assert!(directory.join("active-standard-lite.toml").is_file());
    println!(
        "edition=standard-lite release={} raw_geosite_bytes={} raw_geoip_bytes={} refresh_ms={} geosite_sha256={:02x?} geoip_sha256={:02x?}",
        manifest.release, pair.geosite().len(), pair.geoip().len(), refresh_ms,
        manifest.geosite_sha256, manifest.geoip_sha256,
    );
    let pinned = store.load_pinned(manifest, &rules).unwrap();
    assert_eq!(pinned.geosite(), pair.geosite());
    assert_eq!(pinned.geoip(), pair.geoip());
    for sample in 1..=3 {
        let start = Instant::now();
        let (server, wire) =
            Snapshot::build("real-dat", 1, &rules, pair.geosite(), pair.geoip()).unwrap();
        let build_us = start.elapsed().as_micros();
        let start = Instant::now();
        let client = Snapshot::decode(&wire, "real-dat").unwrap();
        let decode_us = start.elapsed().as_micros();
        assert_eq!(server.digest(), client.digest());
        assert_eq!(
            client
                .policy()
                .matching_action(Some("google.com"), None)
                .unwrap(),
            Some(Action::Direct)
        );
        for address in ["127.0.0.1", "::1"] {
            assert_eq!(
                client
                    .policy()
                    .matching_action(None, Some(address.parse().unwrap()))
                    .unwrap(),
                Some(Action::Blocked)
            );
        }
        println!(
            "sample={sample} snapshot_bytes={} build_us={build_us} decode_us={decode_us}",
            wire.len()
        );
        let mut corrupt = wire;
        let last = corrupt.last_mut().unwrap();
        *last ^= 1;
        assert!(Snapshot::decode(&corrupt, "real-dat").is_err());
    }
}
