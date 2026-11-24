# F-18: prepared external QUIC v1 backend

This development candidate is not activated by normal production startup.
It composes the registered immutable generation, QUIC Initial admission,
the native H3 application endpoint, and a byte-exact UDP reference relay.

* Initial packets: RFC 9001 public Initial keys (ring HKDF, AES-GCM, header
  protection), packet number reconstruction, bounded CRYPTO reassembly,
  exact first-flight datagram retention. Admission before any reference
  socket; a valid marker goes exclusively to Quinn, with physical peer
  addresses preserved. No loopback listener bypass. Initial inspection
  timeout or memory exhaustion drops incomplete flights. Only QUIC v1 is
  supported by this candidate; unsupported versions are dropped.
* Reference: immutable approved plan and signed active reference; each
  physical path obtains a fresh DNS-revalidated RelayLease. Connected UDP
  socket only; no arbitrary destination, no payload modification.
* CID: track visible server-issued long-header CIDs; Retry integrity and
  exact opaque token continuity on the original tuple. A known CID on a
  new tuple creates an independent upstream socket; old tuple remains
  intact. Unknown short CID can be forwarded only on a unique existing
  physical tuple, never learned or used to migrate to another tuple.
* Amplification: independent client payload accounting per physical path,
  output <= 3 * input, including Retry and migration. Neither a valid Retry
  tag nor an opaque token is proof of external path validation. The relay
  does not lift the cap because reference PATH_RESPONSE and authenticated
  Handshake/1-RTT processing cannot be verified by a passive intermediary.
  Quinn retains native validation for admitted traffic.
* Absolute 60s / idle 15s / 8 MiB aggregate per relay session; at most 64
  pending + relay sessions, four paths per session, eight visible server
  CIDs, bounded queues and first-flight storage. Cancelled dispatch drops
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
Do not infer validation from successful UDP send, observed CID, public
Initial integrity or Retry token echo. Zero-length CID migration is not
supported. Native admitted endpoint routing is also limited to visible
server CIDs and unambiguous admitted tuples in this candidate.

Written unit tests cover RFC 9001 Retry and header-protection vectors,
packet truncation, conflicting CRYPTO overlap, routing ambiguity,
per-path amplification, idle/absolute expiry and backpressure.
Independent real reference QUIC E2E (Retry, migration, CID rotation,
probe parity, quota exhaustion), admitted path lifetime/retirement,
production multi-inbound activation and post-merge CI remain required.
No build, test, or coverage result is claimed for development commits.
