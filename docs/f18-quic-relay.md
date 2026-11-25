# F-18: native QUIC and bounded external reference relay

The approved v1 contract distinguishes a native authenticated QUIC endpoint
from a passive external UDP relay. The latter never terminates reference
TLS, modifies datagrams, requests third-party keys or requires reference
cooperation. This is a development candidate, not release acceptance.

## Native admitted H3

* Valid v1 admission is classified before Quinn; the original physical
  source address is preserved. The endpoint independently checks TLS-bound
  admission and identity before bearer; every OPEN has its own grant and quota.
* Native CID generation is authenticated and endpoint-scoped, including
  CIDs issued through encrypted NEW_CONNECTION_ID. Quinn authenticates
  packets, manages CID retirement, performs path validation and enforces
  amplification limits on unvalidated paths. A CID match only routes a packet
  to Quinn, not to an admitted HTTP request.
* Active migration is enabled for checked REALITY server configurations,
  including live generations. The same verified connection may migrate
  without a fresh admission handshake; a new connection must pass admission
  again. Existing connection and stream quotas are not reset by migration.
  Own-TLS migration policy is unchanged. This is transport support, not a
  guarantee that every operating-system network switch triggers client rebind.
* Native v1 only; a valid v2 admission marker is rejected, not downgraded
  or forwarded to the reference.

## External non-cooperating reference

* QUIC v1/v2 Initial parsing and public keys (RFC 9001/9369), bounded
  CRYPTO reassembly and exact first-flight datagram retention. Invalid
  admission selects only the approved pinned reference; incomplete flights
  that exceed bounds or the deadline are dropped. Unsupported versions and
  malformed or mixed-connection datagrams are not forwarded.
* Each physical path has a connected upstream socket with fresh DNS
  eligibility, exact signed signer/reference pin, no arbitrary destination.
  No reference switching for a live relay session.
* Retry integrity and opaque token continuity on the original tuple;
  no address-validation inference. Version negotiation is advisory.
  Compatible v1/v2 transition is tracked on the first server Initial.
* Known visible server Initial CID can route a new physical tuple; an
  unknown short-header CID can only use a unique existing physical tuple
  without an ambiguity or native/retired-tuple conflict. No guessing,
  learning unauthenticated opaque CIDs, fan-out or cross-session forwarding.
  Zero-length CID is tuple-bound; Retry CID is not a 1-RTT migration CID.
  Greased fixed bits are not interpreted as validation. Retired visible
  CIDs and tuples are quarantined during the bounded cooldown.
* Per physical path, output <= 3 * accepted input for the entire external
  session. No limit lift: upstream address validation concerns the relay,
  not the client; encrypted path validation is not visible to the relay.
* Bounds: 60 s absolute, 15 s idle, 8 MiB aggregate per relay session,
  64 pending + relay sessions, four paths/session, eight visible server
  CIDs, bounded queues and 256 path worker slots. First flight bounded by
  64 KiB, 16 datagrams and 3 s. Expired and exhausted paths fail closed.

## Approved interoperability boundary

RFC 9000 §§5.1,9.5, RFC 9001 §5 and RFC 9312 describe the observer's
limited visibility: a new opaque CID and new tuple are not sufficient
to prove connection association. The relay must drop such packets rather
than guess; external zero-CID migration is similarly unsupported.
External simultaneous unknown-CID/address migration, encrypted CID
retirement tracking, successful independent client address validation,
lifting the 3x cap and unrestricted session duration/throughput are
explicit non-goals of this passive relay. They are not implementation
blockers under the revised contract. No change to independent identity,
admission, DNS, reference eligibility, isolation or anti-amplification
requirements. The native endpoint has the full protocol context and
must support the normal authenticated lifecycle.

## Acceptance

Native: test full identity/admission handshake, actual CID issuance,
rebind of a verified connection with a live OPEN_OK tunnel, data in both
directions after rebind, invalid fresh admission, no quota reset and
bounded retirement. Verify transport-level address validation and
anti-amplification remain with Quinn.

External: independent controlled QUIC reference fixtures exercise
byte-exact ordinary handshakes and payload exchange within bounds,
Retry, v1/v2, greasing, supported known-CID paths and unique-tuple
rotation; ambiguous CID/new tuple, zero-CID migration, spoofed packets,
foreign upstream traffic, exhausted budgets and reference drift must
fail closed. Measure probing differences against the direct reference,
including the documented limits. Do not count a rejection as successful
migration; it is the expected result for an explicitly unsupported
external scenario. Authored loopback and RFC vector tests are not
independent acceptance or evidence of browser parity.

All build/test/coverage and independent acceptance are post-merge main
work. No successful run is claimed for development commits.
