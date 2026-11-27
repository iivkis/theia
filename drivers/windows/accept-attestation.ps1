[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MicrosoftSignedDriver,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$MicrosoftDriverSha256,
    [Parameter(Mandatory=$true)][string]$SubmissionEvidence,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$SubmissionEvidenceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'attestation-common.ps1')
$submission=Read-TheiaPinnedJson $SubmissionEvidence $SubmissionEvidenceSha256
if ($submission.Version -ne 1 -or $submission.SourceSha -cne $SourceSha.ToLowerInvariant() -or
    $submission.PublisherSignedCab -isnot [bool] -or !$submission.PublisherSignedCab) { throw 'Invalid publisher submission evidence.' }
$build=[IO.Path]::GetFullPath($BuildDirectory)
$proof=Read-TheiaPinnedJson (Join-Path $build 'build-evidence.json') $submission.UnsignedBuildEvidenceSha256
if ($proof.Version -ne 1 -or $proof.SourceSha -cne $submission.SourceSha -or
    $proof.DriverSha256 -ne $submission.UnsignedDriverSha256 -or $proof.ControllerSha256 -ne $submission.ControllerSha256 -or
    $proof.PdbSha256 -ne $submission.PdbSha256 -or $proof.KernelSignatureVerified -isnot [bool] -or $proof.KernelSignatureVerified) {
    throw 'Submission does not match the exact unsigned build.'
}
$unsigned=(Get-TheiaRegularFile (Join-Path $build 'theia_wfp_lab.sys')).FullName
$controller=(Get-TheiaRegularFile (Join-Path $build 'theia_bfe_lab.exe')).FullName
Assert-TheiaHash $unsigned $proof.DriverSha256
Assert-TheiaHash $controller $proof.ControllerSha256
$image=Get-TheiaImageIdentity $unsigned $false
if ($image -ne $submission.UnsignedImageIdentity) { throw 'Unsigned PE identity mismatch.' }
$signed=(Get-TheiaRegularFile $MicrosoftSignedDriver).FullName
Assert-TheiaHash $signed $MicrosoftDriverSha256
if ((Get-TheiaImageIdentity $signed $true) -ne $image) { throw 'Microsoft return is not the submitted executable image.' }
Assert-TheiaMicrosoftKernelSignature $signed
$output=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Output must be create-only.' }
New-Item -ItemType Directory -Path $output | Out-Null
$driver=Join-Path $output 'theia_wfp_lab.sys'
$exe=Join-Path $output 'theia_bfe_lab.exe'
[IO.File]::Copy($signed,$driver,$false)
[IO.File]::Copy($controller,$exe,$false)
Assert-TheiaHash $driver $MicrosoftDriverSha256
Assert-TheiaHash $exe $proof.ControllerSha256
if ((Get-TheiaImageIdentity $driver $true) -ne $image) { throw 'Copied PE identity mismatch.' }
Assert-TheiaMicrosoftKernelSignature $driver
$record=[pscustomobject]@{
    Version=1;SourceSha=$submission.SourceSha;DriverSha256=$MicrosoftDriverSha256.ToUpperInvariant()
    ControllerSha256=$proof.ControllerSha256;PdbSha256=$proof.PdbSha256
    UnsignedDriverSha256=$proof.DriverSha256;UnsignedImageIdentity=$image
    SubmissionEvidenceSha256=$SubmissionEvidenceSha256.ToUpperInvariant()
    KernelSignatureVerified=$true;MicrosoftKernelSignatureVerified=$true
    # Signature is verified; the script cannot identify which portal
    # certification program produced it without independent portal evidence.
    MicrosoftAttestationVerified=$false;PhysicalAcceptanceVerified=$false;CaptureReady=$false
}
$manifest=Join-Path $output 'build-evidence.json'
$record | ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding utf8
[pscustomobject]@{SourceSha=$record.SourceSha;DriverSha256=$record.DriverSha256;BuildEvidenceSha256=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash;MicrosoftKernelSignatureVerified=$true;Installed=$false} | ConvertTo-Json
