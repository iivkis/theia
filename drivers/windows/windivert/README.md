# Windows Packet Interception: WinDivert

Target: unmodified upstream WinDivert 2.2.2, x64, dynamically loaded under
LGPL-3.0. No custom WFP driver build/signing/installation is required.
WinDivert is the only Windows packet interception backend.

## Approved package

Obtain the official release archive from
https://github.com/basil00/WinDivert/releases/tag/v2.2.2
and corresponding exact source archive. Independently review and pin their
SHA-256 values; the release API currently does not publish an asset digest.
Run stage.ps1 with -Archive, -ArchiveSha256, -CorrespondingSourceArchive,
-SourceSha256, -OutputDirectory in an authorized Windows developer shell with
SignTool. Do not extract an untrusted archive wholesale. Ship the original
license and exact corresponding source alongside the replaceable DLL/SYS.
Review LGPL obligations including reverse-engineering for debugging modifications.
Use administrator-controlled directories; never load a DLL from an untrusted
working directory. Do not re-sign, modify, disable Code Integrity or delete a
shared WinDivert service.

## Compatibility probe

theia client windivert --check --directory DIR --dll-sha256 HEX --sys-sha256 HEX

Use lowercase independently approved hashes from the staging evidence. Probe
opens match-none read-only NETWORK, FLOW and SOCKET handles using NO_INSTALL.
It verifies the ABI, not capture or the identity of an already loaded driver.
An authorized disposable x64 lab may add --install-lab --confirm after verifying
the package signature; upstream loads its signed driver on demand. No packets
are captured, forwarded or altered. Never use probe success as capture ready.

## Native loopback acceptance (not product Connect)

After the official driver is installed and the approved package is staged,
run an elevated x64 Windows shell on a disposable laboratory machine:

    theia client windivert --loopback-lab --directory DIR --dll-sha256 HEX --sys-sha256 HEX --confirm

NO_INSTALL is enforced. Only exact loopback tuples reserved by the test are
captured. The test exercises cancellable overlapped RecvEx/SendEx, IPv4/IPv6
UDP reinjection and reverse replies, TCP redirection between reserved
listeners and a client which retains the original peer, SOCKET/FLOW/NETWORK
agreement, endpoint handle verification and carrier lease revocation.
A lower-priority kernel DROP handle protects one exact UDP tuple while a
separate child holding the higher-priority capture handle is hard-killed.
The test requires no delivery after that death, followed by delivery after
explicit guard removal. This is not a system-wide kill switch: the parent
still owns the guard and no reboot guarantee is provided.

## Authenticated UDP relay acceptance

On an authorized disposable Windows machine with an independently controlled
UDP echo origin and a configured authenticated Theia server:

    theia client windivert --udp-relay-lab --config PATH --directory DIR --dll-sha256 HEX --sys-sha256 HEX --target IP:PORT --flows 4 --confirm

Use a concrete non-loopback echo target which the configured policy routes
via authenticated VPS Redirect (or its permitted pre-payload Modify fallback).
The configured carrier endpoint must be a literal socket address; native
carrier scope does not resolve an untrusted local hostname. The registry is
attached before carrier preparation and retained by H2/H3 socket leases.
Up to eight simultaneous flows share one runtime and policy generation; each sends three distinct datagrams (32, 33 and 1200 bytes), including to the same target. Responses may be reordered but never duplicated or mixed across flows. Each original application socket is created with SO_EXCLUSIVEADDRUSE and bound
to the observed source. Only its exact tuple is intercepted and guarded.
The captured nonce is relayed using NativeIngress, FlowLease and H2/H3 XHTTP;
only its exact authenticated echoed response is injected inbound while
the flow lease is held. A denial, route change, timeout or unknown outcome
fails the test without direct fallback. Independent server/egress captures
are still required. This is not general application capture or Connect.

## Offline UDP reverse candidate

The Rust backend builds complete IPv4/IPv6 reverse UDP packets from parsed,
outbound, non-sniffed NETWORK observations, with the original peer reversed
and checksums recomputed. It rejects loopback, impostor and ambiguous packet
formats. Unit tests cover empty, odd, and maximum datagrams. These bytes are
not an injection authorization: the live endpoint, committed policy lease
and inbound interface still need verified correlation.

## TCP reflection and application observations

The non-loopback reflection table reserves an exact local listener per
original SYN, validates the SYN/SYN-ACK pair, and never reuses a retired
tuple/listener within an epoch. It builds inbound packet candidates with
the original client/remote identity and checksum; no live arbitrary-app
capture consumes these candidates yet. The local process image diagnostic
holds a live process handle, creation timestamp and read-pinned executable
file across socket observations. This still does not prove that the loaded
image section matches the file, or that a NETWORK packet belongs to that
process. Do not treat it as trusted application evidence.

## Remaining production gates

- Production packet/event workers and exact socket/carrier ownership
  proof for arbitrary applications; the bounded candidate ledger and
  registrar are implemented, but are not an authorization to inject.
  NETWORK lacks PID/endpoint identity. PID reuse, shared sockets, event
  loss and ambiguous tuples must not authorize bypass.
- Live non-loopback TCP reflection and general TCP/UDP transparent relay,
  arbitrary application lifetimes and independent physical H2/H3 egress.
  Up to eight exact UDP echo flows use NativeIngress/FlowLease and XHTTP;
  this does not demonstrate arbitrary application acceptance.
- Persistent independent fail-closed guard across both process deaths,
  reboot, non-loopback traffic and explicit owner/CAS recovery. WinDivert
  alone is not a kill switch; the scoped guard test is only one proof case.
- Physical IPv4/IPv6, offload, fragment, DNS, policy, disconnect/reboot,
  actual H2/H3 UDP and TCP egress, interoperability and throughput evidence.
Until accepted, Connect remains inactive. No silent direct fallback.

## Persistent guard experiment

persistent-guard-lab.ps1 prepares one exact, independently authorized UDP
block rule in Windows Firewall PersistentStore and records a durable
create-only intent first. Use an existing administrator/SYSTEM-only journal
directory with protected ACL and trusted ancestry, a reviewed executable/hash
and literal local and controlled remote IP/ports. Prepare requires
-IsolatedTestMachine. Verify with the independently recorded -IntentSha256
after both WinDivert owners exit and with -RequireDifferentBoot after reboot;
use independent remote packet capture to prove no egress. The guard blocks
the chosen tuple, not general traffic, and is not integrated with the
WinDivert relay or production Connect. NetSecurity has no atomic compare-
and-delete; the script never removes a firewall rule. After explicit
administrator review/removal, ReconcileAbsent records an observation of
absence without mutating OS policy. A mismatch retains the journal. No
automatic global firewall or default-policy changes, and no claim of OS CAS.

### Scoped TCP carrier acceptance

The explicit `client windivert --tcp-relay-lab` command requires a configured authenticated profile, pinned official package and an authorized literal non-loopback TCP echo target reachable from the VPS. It owns an exclusive source socket and a dedicated local listener. The NETWORK consumer reflects only those exact tuples, derives the original destination from the captured SYN, validates the local accept, and hands the accepted stream to the same guarded XHTTP TCP adapter used on Linux. It checks a random echo and TCP half-close, retaining a lower DROP handle until the owned sockets are closed even after a capture error. This is a bounded laboratory implementation, not evidence of generic application attribution, production persistent scope protection, atomic OS CAS or physical acceptance. Never use an unrelated third-party endpoint as an echo fixture.

```powershell
theia client windivert --tcp-relay-lab --config $Config --directory $Dir --dll-sha256 $DllHash --sys-sha256 $SysHash --target $AuthorizedTcpEcho --confirm
```

### Native transactional persistent interface guard (isolated lab only)

`build-wfp-guard-lab.ps1` compiles the user-mode Windows SDK helper. No kernel driver, default firewall policy, or permit is installed. `wfp-guard-lab.ps1` requires an administrator, a local console on an explicitly disposable machine, and separately provisioned administrator/SYSTEM-only directories for the executable and journal. **The selected interface loses all outbound IPv4 and IPv6, including unrelated protocols and remote management.** Do not use on a production or remotely administered host.

Prepare pins the helper hash, machine, boot, interface GUID/LUID, random sublayer/filter keys and marker in a create-only flushed intent before BFE mutation. Record the emitted intent SHA-256 independently. BFE performs get-by-key/compare/add or get-by-key/compare/delete in one write transaction, including owner/group and protected administrator/SYSTEM DACL comparison. Recovery deletes only both exactly matching filters and their unique sublayer, or accepts complete absence; partial/foreign state fails closed. A referenced sublayer cannot be removed, so unexpected foreign references abort the entire transaction. Explicit recovery requires the original pinned intent and confirmation; no journal is deleted. This validates object state, not actual enforcement, boot-time continuity, or arbitration with WinDivert. Persistent filters are loaded by BFE, not a proof of pre-BFE boot coverage. The lab installs no carrier exemptions and cannot publish capture readiness. Interface changes or a different LUID prevent Verify; exact old-object recovery remains possible.

```powershell
./drivers/windows/windivert/build-wfp-guard-lab.ps1 -OutputDirectory $ProtectedHelperDir
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Prepare -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -InterfaceGuid $IsolatedInterfaceGuid -IsolatedTestMachine
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Verify -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -IntentSha256 $IntentHash -IsolatedTestMachine -RequireDifferentBoot
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Recover -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -IntentSha256 $IntentHash -IsolatedTestMachine -ConfirmRecovery
```

Physical acceptance requires a distinct management interface/local console, independent packet capture on the selected interface, TCP/UDP/non-TCP/UDP IPv4/IPv6, existing connections, simultaneous process termination, reboot, interface LUID change and conflicting WFP objects. Do not equate transactional object recovery with production CAS across an active capture/carrier epoch.

### Generic scoped capture/drop laboratory

With the official WinDivert package already installed and pinned, an explicitly authorized local-console operator on a disposable machine can run `theia client windivert --scope-drop-lab --directory DIR --dll-sha256 HEX --sys-sha256 HEX --interface-index N --seconds 1..30 --confirm-block`. This opens a bounded NETWORK consumer and an independent lower DROP handle on the exact interface, without process or target filtering. It discards all captured packets, including unsupported traffic; the only output is aggregate TCP/UDP v4/v6, unsupported and distinct-tuple counts. No app attribution, user payload export, redirect, carrier exemption or production readiness is asserted. The WinDivert handles are temporary; an independently installed and verified persistent WFP fixture is a separate experiment, not automatically combined with capture. Never run this on a remotely managed or production interface.

The Windows native prerequisite job now compiles the helper and requests an abort-only BFE transaction self-test: actual create/read/compare/remove, changed marker and LUID, partial-set rejection, then explicit abort and read-back of complete absence. It cannot certify packet enforcement or persistence because no test filter is committed. The interface guard matches the WFP local-interface LUID, not a proved physical next-hop interface; weak-host, forwarding, adapter reassignment and pre-BFE boot paths require separate acceptance. The helper is an engineering fixture, not a shipped production service.

### Scoped carrier filter fixture

The existing socket lab now checks actual WinDivert filter exclusion and revocation on two exclusively bound IPv4 loopback UDP sockets directed at the same owned receiver. The other socket is captured and dropped, the selected socket delivers its random nonce, and stricter capture/drop handles are installed before lease revocation; the formerly excluded socket must then be captured with no delivery. Only the two fixture tuples are in scope. This is not trusted NETWORK attribution or a production carrier exemption. Physical Windows execution remains required.

### Common TCP/UDP redirect for external applications (isolated lab)

The new bounded `--redirect-lab` fixture accepts up to eight explicit literal destinations (IPv4/IPv6, TCP and UDP), simultaneously, for 5–120 seconds. Use a disposable machine, local console and test-only destination IPs, not an ordinary network, public DNS or a carrier endpoint. Start external applications only after capture is installed; do not reuse/share source UDP sockets or run competing packet injectors. Stop applications before the epoch expires. The guard blocks **all ports/protocols** to and from each selected IP while active, including pre-existing connections; only the explicitly listed TCP/UDP targets can enter the adapter. The carrier registrar refuses connections to those IPs, even at different ports. Outside the listed IPs, the lab does not claim capture or protection.

```powershell
theia client windivert --redirect-lab --config client.toml --directory $PinnedWinDivert --dll-sha256 $DllHash --sys-sha256 $SysHash --targets '192.0.2.10:8443,[2001:db8::10]:8443' --seconds 120 --confirm-isolated
```

Replace the documentation addresses with controlled test servers. TCP dynamically allocates a separate exclusive listener per eligible captured SYN; the actual accepted stream is matched to the reflection generation, then handed to the existing XHTTP stream relay. UDP delivers captured payloads via the shared bounded dispatcher and authenticated XHTTP datagram relay; the sole capture worker injects a reply from the original destination only while its exact flow capability is live, and acknowledges the injection. No nonce/echo requirement or one-request/one-response restriction. No original packet is sent to the destination by the capture worker. Both protocols use the same NativeIngress, policy/FlowLease, existing carrier H2/H3 and first-send authorization. Unknown application/domain evidence is not promoted; unambiguously denied/non-Redirect rules refuse relay. Tuple tombstones, bounded queues and epoch limit restrict reuse but do not prove kernel socket ownership. Each target pins the OS-selected route source, interface index, GUID/LUID and network epoch, rechecked throughout the experiment. Reply operations are acknowledged by the packet worker and cancelled when their flow capability retires. The CLI emits a readiness line only after the actual scoped handles and isolated runtime are ready. Pre-existing TCP sessions and Fast Open are rejected.

The filter is deliberately destination-scoped, not a production carrier exemption or persistent kill switch. Original traffic can resume when handles are removed (including after a crash); this lab cannot guarantee fail-closed outside its active scope. It is not integrated with the separate persistent WFP fixture. Kernel attribution, live socket/UDP reuse handling, physical inbound delivery and arbitration, whole-scope guard, production activation and native acceptance remain open. A successful command exit indicates only that the fixture ran to completion, not that any external application was successfully relayed.

The independent `test-redirect-apps.py` fixture exercises four simultaneous TCP streams and four simultaneous UDP sockets per target from an external process. Each TCP stream sends four independently framed messages, verifies transformed responses, half-closes and receives a final transcript digest. Each UDP socket sends four datagrams (including empty), expects two different responses per request in any order and rejects missing, duplicate or wrong responses. The controlled server checks the peer IP against an explicit expected VPS egress allowlist. It must not be used as evidence of absent direct packets without an independent capture on the client-side network.

On the controlled target host (separate from the Windows client; substitute real authorized addresses):

```text
python test-redirect-apps.py server --listen TARGET_IP:PORT --expected-peer VPS_EGRESS_IP --seconds 180
```

Start the Theia redirect lab, wait for the scoped readiness line, then from a separate Windows process:

```text
python test-redirect-apps.py client --target TARGET_IP:PORT --target [TARGET_IPV6]:PORT
```

Repeat with distinct pinned H2-only and H3-only client profiles. Save exact source SHA, driver package hashes, the independent client's exit status, target-side peer observations and client-side packet capture showing no original target egress. Run policy-denial controls, concurrent unrelated destinations/ports, connection churn, packet loss, cancellation and carrier failure separately. A loopback-only self-test validates the external fixture itself; it must not be reported as a native capture or XHTTP E2E pass. CI runs only the fixture self-test without changing host capture rules.

### Carrier ownership and kernel attribution boundary

The native H2/H3 factories now prepare exclusive, non-inheritable Windows sockets before bind, verify the actual options and endpoint handle at admission, and retain the existing per-endpoint registry lease. Native QUIC sessions reject rebinding to an unregistered replacement socket. Runtime Stop explicitly retires the shared registrar, including outstanding clones. These are prerequisites for an exact kernel permit, not permission to reinject a NETWORK packet. WinDivert NETWORK still has no endpoint handle; FLOW/SOCKET candidate correlation and executable path/hash cannot authorize a production exception. WFP ALE and outbound transport can expose endpoint metadata to an appropriate callout, but that is not an authenticated attachment to an independent WinDivert NETWORK record. Do not introduce a PID-, executable-, address- or destination-wide permit. Any additional kernel component requires a reviewed interface, signing and independent physical acceptance. Production Connect remains disabled.

#### Capture-time attribution diagnostics

The shared redirect lab now opens private FLOW and SOCKET observers before NETWORK capture, using the QPC clock, a bounded 1024-record handoff and a 4096-endpoint epoch ledger. Capture-time correlation counts a candidate only when both event layers agree within the age bound. A close/delete, observed collision, endpoint reuse, known stream failure or queue saturation invalidates matching evidence. Driver-level silent event loss, cross-stream delivery races, shared sockets and absence of an endpoint/compartment in NETWORK remain unresolved. The output reports only aggregate counts, never PIDs, hashes, addresses or payload; the trusted application count is always zero. The result cannot generate an application selector or a carrier exception, even on a unique match. No new WFP callout or custom driver is introduced. Application-dependent routing still refuses unresolved policy under F-15.


### Multi-interface and boot-time guard objects

The existing Windows SDK helper remains a user-mode BFE API laboratory tool, not a custom WFP driver, callout, or second packet engine. Prepare accepts 1–8 explicit non-loopback interface GUIDs, each resolved to its exact LUID. The v2 protected intent pins the entire interface/object set, machine, boot and helper hash. The helper adds all persistent IPv4/IPv6 BLOCK filters atomically, rejects mixed/partial/foreign object sets, checks exact flags, conditions, owner marker and protected ACLs, and restores only the complete exact set in one transaction. Explicit recovery remains available for an old interface identity. Retain the original pinned helper for old v1 journals.

Optional -IncludeBootTime adds distinct BOOTTIME BLOCK objects for the same selected interface LUIDs, using a built-in sublayer; persistent and boot-time flags are never combined on one filter. An unsupported boot-time condition or partial transaction is a hard failure. The separate -TestBootTimeTransaction build option runs an abort-only BFE test, while the existing -TestBfeTransaction also exercises multi-interface all-or-conflict rollback. Boot-time object readback is not proof of actual pre-BFE enforcement, LUID stability, BFE handoff, external wire blocking or arbitration with WinDivert. Never install on a remote-access machine, never add carrier permits, and do not activate production capture from this helper.

No safe full-interface Windows carrier permit has been implemented: WinDivert NETWORK lacks authenticated packet-to-endpoint ownership. Guard integration and arbitrary-destination Windows Redirect remain blocked by the same F-15 requirement; a PID, server IP or tuple-only exception is not a substitute.
