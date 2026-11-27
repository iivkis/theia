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

    theia client windivert --udp-relay-lab --config PATH --directory DIR --dll-sha256 HEX --sys-sha256 HEX --target IP:PORT --confirm

Use a concrete non-loopback echo target which the configured policy routes
via authenticated VPS Redirect (or its permitted pre-payload Modify fallback).
The configured carrier endpoint must be a literal socket address; native
carrier scope does not resolve an untrusted local hostname. The registry is
attached before carrier preparation and retained by H2/H3 socket leases.
The original application socket is created with SO_EXCLUSIVEADDRUSE and bound
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

## Remaining production gates

- Production packet/event workers and exact socket/carrier ownership
  proof for arbitrary applications; the bounded candidate ledger and
  registrar are implemented, but are not an authorization to inject.
  NETWORK lacks PID/endpoint identity. PID reuse, shared sockets, event
  loss and ambiguous tuples must not authorize bypass.
- General TCP/UDP transparent relay, non-loopback TCP mapping, arbitrary
  application lifetimes and independent physical H2/H3 egress. The one
  exact UDP echo flow uses NativeIngress/FlowLease and XHTTP; this does not
  demonstrate arbitrary application acceptance.
- Persistent independent fail-closed guard across both process deaths,
  reboot, non-loopback traffic and explicit owner/CAS recovery. WinDivert
  alone is not a kill switch; the scoped guard test is only one proof case.
- Physical IPv4/IPv6, offload, fragment, DNS, policy, disconnect/reboot,
  actual H2/H3 UDP and TCP egress, interoperability and throughput evidence.
Until accepted, Connect remains inactive. No silent direct fallback.
