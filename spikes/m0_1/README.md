# M0.1 Rust transport API spike

**Not production Theia.** The isolated crate proves 1) `quinn::congestion::BbrConfig` is constructible and can be attached to client/server configs, 2) real in-memory HTTP/2 responds before request EOF and accepts later request chunks, and 3) the current HTTP/3 API exposes split send/receive halves.

```sh
cargo test --manifest-path spikes/m0_1/Cargo.toml --locked
```

**Missing (release blockers):** real TLS-backed HTTP/2, real QUIC-backed HTTP/3 streaming, BBR-on-wire telemetry/loss benchmarks, TLS/HTTP browser-like fingerprint, Windows x64 integration. Do not rename this spike to Theia core or merge it into the production binary prematurely.

The CI workflow generates the lockfile on the first run; the lockfile should subsequently be committed so later runs can use `--locked`. Use `docs/adr/0004-m0-1-feasibility.md` for the evidence ledger.
