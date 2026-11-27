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

Prepare pins the helper hash, machine, boot, interface GUID/LUID, random sublayer/filter keys and marker in a create-only flushed intent before BFE mutation. Record the emitted intent SHA-256 independently. BFE performs get-by-key/compare/add or get-by-key/compare/delete in one write transaction. Recovery deletes only both exactly matching filters and their unique sublayer, or accepts complete absence; partial/foreign state fails closed. A referenced sublayer cannot be removed, so unexpected foreign references abort the entire transaction. Explicit recovery requires the original pinned intent and confirmation; no journal is deleted. This validates object state, not actual enforcement, boot-time continuity, or arbitration with WinDivert. Persistent filters are loaded by BFE, not a proof of pre-BFE boot coverage. The lab installs no carrier exemptions and cannot publish capture readiness. Interface changes or a different LUID prevent Verify; exact old-object recovery remains possible.

```powershell
./drivers/windows/windivert/build-wfp-guard-lab.ps1 -OutputDirectory $ProtectedHelperDir
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Prepare -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -InterfaceGuid $IsolatedInterfaceGuid -IsolatedTestMachine
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Verify -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -IntentSha256 $IntentHash -IsolatedTestMachine -RequireDifferentBoot
./drivers/windows/windivert/wfp-guard-lab.ps1 -Mode Recover -JournalDirectory $ProtectedJournal -Helper $PinnedExe -HelperSha256 $HelperHash -IntentSha256 $IntentHash -IsolatedTestMachine -ConfirmRecovery
```

Physical acceptance requires a distinct management interface/local console, independent packet capture on the selected interface, TCP/UDP/non-TCP/UDP IPv4/IPv6, existing connections, simultaneous process termination, reboot, interface LUID change and conflicting WFP objects. Do not equate transactional object recovery with production CAS across an active capture/carrier epoch.
