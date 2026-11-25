# F-18 live identity, generation and approved-reference lifecycle

One enrolled inbound owns one TCP listener and, if H3 is signed, one UDP
socket and one Quinn endpoint. A complete prepared generation contains
per-signer TLS configs and HTTP authorization contexts (all share existing
inbound/global quotas). The generation is replaced under one lock for
both transport dispatchers. A failed root/health/storage/preparation
check suspends new admission without cancelling existing application
streams. Native H3 consumes an exact peer+original DCID admission ticket
once and calls Quinn accept_with; a second lifetime-stable replay guard
checks the TLS ClientHello. The UDP namespace and existing connections
remain attached to the endpoint. TCP uses the selected immutable
acceptor and context. Existing relay sessions pin the original generation
and remain bounded by their original lease; a new path cannot migrate an
existing relay to a different reference.

The old and next signer are served concurrently during signed overlap.
Old signer stops being selectable at expiry, even before explicit
retirement. Active authenticated tunnels retain their connection context;
new requests on an expired context fail, not hard-revoke active streams.
Clients fetch the signed announcement and successor over admitted,
bearer-authorized H2/H3, verify the announced key and compatible policy,
authenticate a fresh successor connection, and CAS the persisted trust
history. An expired/offline client that missed the signed overlap still
requires independent recovery/re-enrollment; compromise is not planned
rotation. Replay state is not reset on publication.

The owner-scoped server maintenance revalidates the registered manifest,
health and publication floors; advances the floor even when degraded;
probes only the original approved plan at the scheduled interval/jitter
and the bounded suspect follow-up; automatically publishes compatible
same-signer failover when the fresh two-cycle evidence and existing
cooldown select a reserve. Renewal preserves the signed policy. Startup
can perform the same bounded recovery of a persisted degraded reference.
There is no automatic failover while a dual-signer publication is pending:
the existing signed transition contract does not permit changing its
operational parameters; suspend new admissions and preserve existing
tunnels. No eligible reserve, stale trust, or unrooted materials fail
closed. If startup cannot recover a valid generation it refuses to bind.

Recovery decision: allow a valid admission for any reference SNI in the
unchanged signed approved inventory on the same independently pinned
endpoint; no arbitrary aliases and no alternate relay targets. This
lets a still-valid client with a pre-failover descriptor authenticate,
read the signed new active index, and replace its carrier pools. The
active reference must be healthy; a previous reference SNI need not be
healthy because the authenticated handshake is local. This is a bounded
bootstrap compatibility exception, not evidence of probe parity for a
stale SNI. It requires independent contract review. The external
unadmitted relay always uses the single current pinned reference;
passive CID/NAT/3x limitations remain.

Native registered loopback test holds H2 CONNECT and H3 SOCKS5 tunnels
open across planned rotation, authenticates new signer on each branch,
and exchanges bytes after promotion. Reference evidence is synthetic.
The production anti-replay startup window is preserved; only the explicit
unit-test ready path uses a test guard start time in the past. No build,
test, or coverage result is claimed. Live structural management/rollback,
overlap failover, independent public reference and offline/restart E2E
acceptance, and final main CI remain open.
