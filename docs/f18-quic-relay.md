# F-18: prepared external QUIC v1 backend

This development candidate is now connected to normal server startup for
registered REALITY configurations. It is not release-accepted; see
f18-runtime.md for the startup and management limitations.
It composes the registered immutable generation, QUIC Initial admission,
the native H3 application endpoint, and a byte-exact UDP reference relay.

* Initial packets: RFC 9001 public Initial keys (ring HKDF, AES-GCM, header
  protection), packet number reconstruction, bounded CRYPTO reassembly,
  exact first-flight datagram retention. Admission before any reference
  socket; a valid marker goes exclusively to Quinn, with physical peer
  addresses preserved. Independent TLS-bound admission guard rejects fresh
  handshakes on retired or guessed CIDs. No loopback listener bypass. Initial inspection
  timeout or memory exhaustion drops incomplete flights. Only QUIC v1 is
  supported by this candidate; unsupported versions are dropped.
* Reference: immutable approved plan and signed active reference; each
  physical path obtains a fresh DNS-revalidated RelayLease for the exact
  signer selected at session creation; overlap expiry cannot redirect a
  new path to a different reference. Connected UDP
  socket only; no arbitrary destination, no payload modification.
* CID: track visible server-issued long-header CIDs; Retry integrity and
  exact opaque token continuity on the original tuple. A known CID on a
  new tuple creates an independent upstream socket; old tuple remains
  intact. Retired visible server CIDs are quarantined across tuples for
  the bounded cooldown; ambiguous known Initials cannot create a duplicate
  session. Coalesced datagrams must agree on their destination CID before
  forwarding; malformed or mixed-CID long-header datagrams are dropped.
  Global CID-prefix collisions are rejected even when a tuple is known;
  overlap between native and relay candidates also fails closed. Short
  header candidates require a minimum protected payload and fixed bit
  (conservative; QUIC-bit greasing interoperability remains unverified).
  Unknown short CID can be forwarded only on a unique existing
  physical tuple, never learned or used to migrate to another tuple.
* Amplification: independent client payload accounting per physical path,
  output <= 3 * input, including Retry and migration. Neither a valid Retry
  tag nor an opaque token is proof of external path validation. The relay
  does not lift the cap because reference PATH_RESPONSE and authenticated
  Handshake/1-RTT processing cannot be verified by a passive intermediary.
  Quinn retains native validation for admitted traffic. Its local CIDs use
  a generation-specific HMAC namespace so encrypted CID issuance and NAT
  rebinding can route to Quinn without accepting unknown probe packets.
* Absolute 60s / idle 15s / 8 MiB aggregate per relay session; at most 64
  pending + relay sessions, four paths per session, eight visible server
  CIDs, bounded queues, a global 256-worker semaphore and first-flight storage. Cancelled dispatch drops
  workers and closes the local endpoint. No wire errors reveal admission.

## Open interoperability boundary

A transparent, non-cooperating reference does not disclose encrypted
NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE or PATH_RESPONSE.
When CID and client tuple both change to previously unseen values, the
relay cannot establish the association safely; it drops the datagram.
Likewise it cannot safely lift the 3x external-path cap, even if the
reference has validated the proxy's upstream UDP address. A cooperating
reference or separately reviewed protocol-level routing/validation design
is required for unrestricted simultaneous CID rotation and migration.
The boundary follows RFC 9000 sections 5.1 and 9.5 (CIDs must not enable an observer to correlate connections across address changes), RFC 9001 section 5 (packet protection), and RFC 9312 (on-path manageability). Two histories can expose the same new tuple and opaque short-header packet while assigning it to different existing connections. Therefore no deterministic or probabilistic routing rule can prove that association from the relay's observations alone. Fan-out, first-match heuristics, trial forwarding to previous references and resetting a session budget for an unknown CID are not valid fixes. A cooperative reference could supply authenticated CID-to-connection and path-validation evidence, but this would change the approved unchanged-third-party contract. The reference's validation of the upstream relay address is not validation of the physical client address. Do not infer validation from successful UDP send, observed CID, public
Initial integrity or Retry token echo. Zero-length CID migration is not
supported. Native admitted endpoint uses a generation-specific authenticated
CID namespace; only classified Initial retransmits may reach its TLS
boundary and it still delegates packet and path authentication to Quinn.

Written unit tests cover RFC 9001 Retry and header-protection vectors,
packet truncation, encrypted fragmented Initial reassembly, conflicting
CRYPTO overlap, routing ambiguity, generation-bound native CIDs,
per-path amplification, idle/absolute expiry and backpressure; a real
connected-loopback UDP fixture checks byte preservation, isolation of two
physical paths and rejection of a foreign source.
Independent real reference QUIC E2E (Retry, migration, CID rotation,
probe parity, quota exhaustion), admitted path lifetime/retirement,
live multi-inbound management/rotation and post-merge CI remain required.
No build, test, or coverage result is claimed for development commits.
