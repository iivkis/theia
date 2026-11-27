# WFP driver signing and isolated installation

The current driver is a non-PnP x64 laboratory driver. This procedure does not
activate Packet Interception on the host. Do not disable Secure Boot, code
integrity, HVCI, signature checks or driver signing. Do not install on a daily
use machine. Microsoft attestation signing is not HLK/WHQL certification.

## Prerequisites

- Exact reviewed commit, clean tracked checkout, Windows SDK/WDK, Visual
  Studio developer shell and pinned NuGet dependencies.
- Approved code signing certificate in the publisher's store or hardware
  token, with the publisher registered in Microsoft Partner Center and a
  valid associated EV certificate. Never upload the private key to GitHub.
- Disposable approved x64 Windows lab, admin access and an isolated
  non-default network compartment. Use a protected local directory.
- Record every SHA-256 from the trusted signing/build machine independently.
  A hash obtained solely from an untrusted download is not authorization.

## 1. Build unsigned

    nuget restore drivers/windows/packages.config -PackagesDirectory drivers/windows/packages -Source https://api.nuget.org/v3/index.json -NonInteractive
    ./drivers/windows/build-lab.ps1 -OutputDirectory C:\TheiaLab\unsigned

Retain build-evidence.json, SYS, PDB and BFE controller. Obtain the source SHA
and independently record the build-evidence SHA-256.

## 2. Prepare publisher-signed submission

    ./drivers/windows/prepare-attestation.ps1 -BuildDirectory C:\TheiaLab\unsigned -BuildEvidenceSha256 $BuildHash -SourceSha $SourceSha -OutputDirectory C:\TheiaLab\submission -CertificateThumbprint $Thumbprint -TimestampUrl $ApprovedTimestampUrl

The script validates the INF, generates the catalog, and signs the catalog
and CAB using the existing publisher key. Retain the submission evidence
and its hash. The CAB is NOT a Microsoft-signed driver.

Submit TheiaWfpLab.cab through the authorized Partner Center hardware
dashboard. Download the Microsoft-signed package after approval, verify its
provenance and record its SYS hash through a trusted channel. Do not extract
an untrusted ZIP over the build tree. No portal upload is automated here.

Microsoft guidance:
- https://learn.microsoft.com/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/windows-hardware/drivers/dashboard/code-signing-reqs

## 3. Accept the returned driver

    ./drivers/windows/accept-attestation.ps1 -MicrosoftSignedDriver C:\TheiaLab\returned\theia_wfp_lab.sys -MicrosoftDriverSha256 $ReturnedHash -SubmissionEvidence C:\TheiaLab\submission\submission-evidence.json -SubmissionEvidenceSha256 $SubmissionHash -SourceSha $SourceSha -BuildDirectory C:\TheiaLab\unsigned -OutputDirectory C:\TheiaLab\signed

Require an embedded Microsoft hardware publisher signature and SignTool /kp.
The returned PE must match the original executable bytes except signature
table, checksum and zero alignment. Catalog-only returns or any other image
change fail closed. Keep the newly issued build-evidence hash. This script
does not claim to verify the certification program or physical acceptance.

## 4. Install on the authorized lab machine

Copy the exact signed directory and approved scripts through a trusted
channel. Use an elevated Windows developer shell, verify the independently
recorded hashes, then run:

    ./drivers/windows/install-signed-lab.ps1 -Driver C:\TheiaLab\signed\theia_wfp_lab.sys -ExpectedSha256 $ReturnedHash -BuildEvidence C:\TheiaLab\signed\build-evidence.json -BuildEvidenceSha256 $SignedEvidenceHash -SourceSha $SourceSha -Compartment $Compartment -InstallEvidence C:\TheiaLab\install-evidence.json -IsolatedTestMachine

First use -WhatIf to inspect the proposed action. The script refuses
existing SCM service/files or any owned BFE objects, verifies the Microsoft
signature before and after copying, checks live code integrity, creates a
demand-start kernel service and requires SCM Running before emitting evidence.
If anything fails after copying or SCM creation, retain evidence and inspect
the machine; do not overwrite or automatically delete an uncertain service.

The install intentionally leaves BFE filters absent and CaptureReady=false.
UDP echo, STOP, crash and reboot acceptance remain separate tests on the
authorized isolated lab. Do not claim production readiness from a signature
or SCM state alone.
