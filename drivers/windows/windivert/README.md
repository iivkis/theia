# Windows Packet Interception: WinDivert

Target: unmodified upstream WinDivert 2.2.2, x64, dynamically loaded under
LGPL-3.0. No custom WFP driver build/signing/installation is required.
The previous WFP laboratory code is retained only for reference and existing
explicit lab entry points; do not activate it in a WinDivert deployment.

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

## Remaining production gates

- Bound packet/event receive, exact socket/carrier ownership correlation;
  NETWORK has no PID or endpoint identity; FLOW/SOCKET events alone are
  ambiguous, including PID reuse, shared sockets and event loss.
- TCP/UDP transparent relay and reverse delivery on original socket,
  original destination, safe first-payload commitment, per-flow generation.
- Independent fail-closed guard across process death/handle closure and
  explicit owner/CAS recovery; WinDivert alone is not a kill switch.
- Physical IPv4/IPv6, offload, fragment, DNS, policy, disconnect/reboot,
  actual H2/H3 UDP and TCP egress, interoperability and throughput evidence.
Until accepted, Connect remains inactive. No silent fallback to custom WFP
or direct traffic.
