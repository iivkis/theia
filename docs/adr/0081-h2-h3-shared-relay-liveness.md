# ADR-0081: Shared H2/H3 tunnel liveness and strict EOF

**State:** proposed; exact-head native CI required.

## Problem

The production client currently opens a new verified H2 TLS or H3 QUIC connection for each TCP tunnel. All four relay adapters had independent 30-second read timeouts; an active large upload/download or long half-close could fail because its other direction was silent. H2 also did not check HTTP trailers at EOF, unlike H3. Neither is consistent with byte-exact full duplex.

## Decision

After OPEN_OK share one monotonic 30-second inactivity deadline across the two directional futures. Refresh only after successful nonempty DATA forwarding (or the single valid FIN per direction); empty frames, partial headers, control traffic and mere socket readiness are not useful progress. Run both futures concurrently, with a watchdog that rechecks the extended deadline. Keep bounded destination writes, flow-credit/send, handshake, dial and absolute server session (300s) budgets. No unbounded buffering or background tasks. A write stalled beyond its own deadline can still fail even if the opposite direction has progress.

A received FIN shuts down only the target/local write half. Watch for trailing frames or transport reset until HTTP EOF; only once the opposite FIN is forwarded does the separate 2-second EOF budget begin. Poll the same tail future across the transition, avoiding cancellation/restart of an in-flight decode. Both H2 and H3 refuse trailers. H2 keeps its stream-reset policy when errors could leave a partially sent frame; shared idle is reported as timeout. No retry of an established tunnel. No wire/TOML/feature-flag migration, no TLS/auth/ACL/BBR or fallback changes. Connection pooling and configurable long-lived session budget remain separate future work.

## Acceptance

- Given active one-way upload or download with a silent other direction, both real H2 and H3 must forward exact bytes across the actual 30s idle boundary.
- Given a FIN in either direction first, the other direction continues past 30s and both FINs/HTTP EOF finish cleanly.
- Given both directions idle, relay terminates within the bounded timeout, not falsely as success.
- Given empty DATA or partial frames, no idle extension; given opposite FIN, tail may not outlive the close deadline. Paused Tokio clock verifies the watchdog and timeout transitions without real-time sleeps.
- Given H2 trailers after FIN, stream reset rather than clean EOF. Existing protocol/ACL/auth/cancellation/backpressure/native browser/cross-host cases remain mandatory.
- Ten real socket cases run concurrently in a single native test on each platform, with a 75-second outer guard. This is liveness evidence, not throughput/RSS/packet parity or release acceptance. No added CI job; no measured speedup claimed.

