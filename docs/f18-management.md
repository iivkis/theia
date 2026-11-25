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
* Same-port REALITY replacement supports exactly one independently
  provisioned fresh bundle on the existing inbound, same endpoint and H3
  capability, different root and admission key, unchanged grants, quotas
  and other configuration. Stage and commit retain listeners, Quinn
  endpoint and replay guards; old authenticated streams retain permits
  but old identity contexts cannot authorize new streams. No root rollback
  slot is created. Reusing roots already seen by the running supervisor
  is refused. Other same-port structural changes (including enabling H3)
  still require maintenance. Own-TLS-only TLS rotation is separate.
* TUI runtime screen: a authorization Apply, b authorization rollback,
  c quota Apply, s structural preview/Apply, z structural rollback;
  y confirms, n/Esc cancels a preview, r reads status. Lost ACK is
  indeterminate, never automatically retried.
* REALITY screen: V queries live inbound status separately from saved
  state; t previews identity rotation; p previews retirement. y commits,
  n/Esc cancels. Root and publication are rechecked at commit.
  Runtime status is not a proof of a successful external handshake.
* Client wizard (I) in an explicitly opened clean TOML: create enrollment,
  then g opens registration prefilled with the verified identity and
  enrollment path. The original TOML digest is retained. Registration is
  a second explicit preview/confirmation; neither action activates the
  profile. A canceled or rejected registration retains enrolled files.
* Client V: saved trust status; s/y starts the exact active saved REALITY
  profile with both loopback listeners, x/y stops it (closing tunnels).
  Live local report includes descriptor revision, current signed reference,
  transport policy, last successful OPEN transport, route-bound H3 negative
  cache and descriptor-refresh result. This is process-local telemetry,
  not remote proof. Windows WinINet panel exposes
  the same runtime report when it owns a REALITY client.
* Headless file-run on Linux/Windows exposes a distinct opt-in owner-only
  client IPC endpoint (THEIA_CLIENT_CONTROL_DIR or THEIA_CLIENT_CONTROL_PIPE;
  use a separate directory/pipe ID from server IPC). V reads runtime
  revision, saved digest match, descriptor revision, last OPEN carrier and
  route-bound H3 negative cache. h previews, y confirms Client Apply.
  CLI client status and client reload --check/--apply --expected-revision N
  --sha256 HEX (--confirm for apply) use the same CAS. New accepted sockets
  receive the new client view; existing tunnels are not cancelled. Listener,
  management and OS-proxy changes require restart. Changing an existing ID's
  independently pinned enrollment or switching security mode requires
  explicit re-enrollment/restart; switching between registered profiles of
  the same mode is supported. Preview validates local material, not remote
  handshake success. No automatic retry on lost acknowledgement.
* Server K previews independent bundle replacement; Y saves only TOML.
  Structural Apply remains separate. Server V/e previews expired-signer
  recovery and y confirms it with fresh healthy evidence and current root.
* Client V: o previews same-signer offline recovery; k previews a signed
  planned successor promotion. Both bind the saved TOML, signed file,
  current trust snapshot and expected revision; y explicitly commits
  trust only. Missed overlap/compromise remains independent re-enrollment.
  No action reveals bearer or changes OS proxy implicitly.

CLI: server reload --apply --expected-revision N --sha256 HEX --confirm;
server auth rollback --check / --apply --expected-revision N --confirm;
server restart rollback --check / --apply --expected-revision N --confirm.
Use existing server restart --apply with both configuration and material
fingerprints for structural cutover.

Tests are authored for overlap failover, generation stamp drift, auth
rollback CAS and TUI confirmation; no execution or release acceptance
is claimed. Independent E2E and main CI are required.
