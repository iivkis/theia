# F-18 external runtime: development integration

The normal server run path now recognizes registered REALITY records and
prepares a single immutable generation per inbound before starting accept
tasks. H2 and H3 share the same authorization and quotas, including mixed
own-TLS inbounds. H3 is only constructed when the signed descriptor allows
it; otherwise reserve the UDP port and remain silent. The normal client
proxy prepares the independently pinned enrollment, resolves only its
configured endpoint, constructs native H2/H3 admission carriers, and uses
the existing SOCKS5/CONNECT relay and conservative auto transport. New
logical operations check the durable signed trust state and credential
digest; a changed signed revision gets a new carrier pool and fallback
cache. Authenticated descriptor refresh is bounded and tied to the running
proxy. Existing tunnels retain their carrier leases.

This is development code, not a release acceptance claim. REALITY
server startup supports a single immutable signer/generation, with
status-only IPC for any configuration containing REALITY; mixed inbounds
do not support the existing own-TLS live mutation operations in this
candidate. Dual identity, live reference/descriptor generation changes,
restart/rollback integration and audit remain open. No deployment should
be declared accepted before main CI and independent review.

External QUIC path lifecycle retains independent budgets and original
physical peers. Retired CIDs are held for a bounded cooldown, idle/closed
paths cannot recreate their budget, Retry token is bound to its original
path, and unverified routing information cannot lift 3x amplification.
The passive reference limitation from f18-quic-relay.md remains: encrypted
CID issuance and PATH_RESPONSE cannot be observed; an unknown CID on a
new tuple is dropped and the external cap is not lifted. Native Quinn
handles authenticated validation and CID retirement for admitted traffic.

Tests for Retry continuity, retirement, and closed paths are authored.
All build/test/coverage acceptance is deferred to the post-merge main CI.
