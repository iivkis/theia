# F-18 native management and TUI

Linux/Windows file-run uses the native unified supervisor for own-TLS and
REALITY. Management remains owner-protected local IPC, not a network API.

* Authorization Apply checks the saved TOML digest, expected runtime
  revision, registered REALITY roots and own-TLS material. Existing
  tunnels retain their permits. A one-shot REALITY authorization rollback
  restores only prior grants/user flags/digests, within 300 seconds and
  at the exact current revision, as a new revision.
* Quota-only Apply uses one shared ledger across transports and mixed
  inbounds. Reducing limits never discards existing occupancy.
* Structural Apply uses a read-only preview bound to the TOML digest,
  runtime revision and composite material fingerprint (PEM or exact
  registered manifest/publication/health stamp). Both transports must
  prepare before CAS. Fresh ports must be disjoint; roster and limits
  must match. Old generation drains for up to 20 seconds, then remaining
  tunnels can be closed. This is not seamless identity rotation.
* Structural rollback is explicit, one-shot, at unchanged runtime revision,
  after drain and within 300 seconds of cutover. Previous ports must be
  available, previous own-TLS fingerprints must match, and REALITY reloads
  the current rooted publication and health floor. A replacement of the
  root on the same logical endpoint disables the rollback slot. No rollback
  rewrites saved TOML, trust history, or health floors.
* Same-port structural REALITY changes require maintenance. The existing
  own-TLS-only same-port TLS rotation remains a separate path. Mixed
  same-port PEM mutation is not supported.
* TUI runtime screen: a authorization Apply, b authorization rollback,
  c quota Apply, s structural preview/Apply, z structural rollback;
  y confirms, n/Esc cancels a preview, r reads status. Lost ACK is
  indeterminate, never automatically retried.
* REALITY screen: V queries live inbound status separately from saved
  state; t previews identity rotation; p previews retirement. y commits,
  n/Esc cancels. Root and publication are rechecked at commit.
  Runtime status is not a proof of a successful external handshake.
* Client status is still based on the saved trust store, not live
  carrier/fallback telemetry. The setup and enrollment panels remain
  separate.

CLI: server reload --apply --expected-revision N --sha256 HEX --confirm;
server auth rollback --check / --apply --expected-revision N --confirm;
server restart rollback --check / --apply --expected-revision N --confirm.
Use existing server restart --apply with both configuration and material
fingerprints for structural cutover.

Tests are authored for overlap failover, generation stamp drift, auth
rollback CAS and TUI confirmation; no execution or release acceptance
is claimed. Independent E2E and main CI are required.
