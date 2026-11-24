# ADR-0082: exact evidence review before any F-18 Apply

**State:** proposed; native CI required.

The existing approved exact-IP and separately consented catalogue DNS paths share a read-only second stage. A completed batch remains an immutable worker result. The operator manually highlights a result (j/k) and opens a preview (a); y has no activation path, Esc/n returns. No extra DNS/HTTP/TCP/UDP, scan expansion, config/IPC mutation, key creation or invitation export. Keep the old explicit consent limits.

Require the report's entire address set to match the manually selected IPs at port 443, reject duplicates and inconsistent inner/outer address. H2 and H3 share strict independent TLS/PKI/ALPN evidence predicates; wrong or unknown evidence is not verified. A delayed UI poll cannot rejuvenate results: age starts conservatively before worker creation, valid for at most 60s, and the domain path additionally requires its original DNS pin to remain fresh. This is a local review boundary, not cryptographically authenticated evidence or authorization.

Apply remains unavailable until a real separately reviewed versioned security mode, independent identity and HTTP semantics exist. No modified handshake, anti-probing, browser parity, DPI-evasion or ready status is claimed. Tests cover malformed scope, stale/future/missing observation, delayed poll, no activation on review/confirmation and shared UI wiring. No new dependencies or CI jobs. Existing test-only identity experiments are not promoted to production.
