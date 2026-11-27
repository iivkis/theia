[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BuildEvidenceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][ValidatePattern('^https://[^\s]+$')][string]$TimestampUrl
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'attestation-common.ps1')
$build=[IO.Path]::GetFullPath($BuildDirectory)
$proof=Read-TheiaPinnedJson (Join-Path $build 'build-evidence.json') $BuildEvidenceSha256
if ($proof.Version -ne 1 -or $proof.SourceSha -cne $SourceSha.ToLowerInvariant() -or
    $proof.KernelSignatureVerified -isnot [bool] -or $proof.KernelSignatureVerified) {
    throw 'Expected exact unsigned build evidence.'
}
$source=(Get-TheiaRegularFile (Join-Path $build 'theia_wfp_lab.sys')).FullName
$pdb=(Get-TheiaRegularFile (Join-Path $build 'theia_wfp_lab.pdb') 268435456).FullName
$controller=(Get-TheiaRegularFile (Join-Path $build 'theia_bfe_lab.exe')).FullName
Assert-TheiaHash $source $proof.DriverSha256
Assert-TheiaHash $pdb $proof.PdbSha256
Assert-TheiaHash $controller $proof.ControllerSha256
$image=Get-TheiaImageIdentity $source $false
$output=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Output must be create-only.' }
New-Item -ItemType Directory -Path $output | Out-Null
$stage=Join-Path $output 'TheiaWfpLab'
New-Item -ItemType Directory -Path $stage | Out-Null
$driver=Join-Path $stage 'theia_wfp_lab.sys'
$symbols=Join-Path $stage 'theia_wfp_lab.pdb'
$inf=Join-Path $stage 'theia_wfp_lab.inf'
[IO.File]::Copy($source,$driver,$false)
[IO.File]::Copy($pdb,$symbols,$false)
[IO.File]::Copy((Join-Path $PSScriptRoot 'theia_wfp_lab.inf'),$inf,$false)
Assert-TheiaHash $driver $proof.DriverSha256
Assert-TheiaHash $symbols $proof.PdbSha256
$git=(Get-Command git.exe -ErrorAction Stop).Source
$revision=(& $git -C $PSScriptRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -cne $proof.SourceSha) { throw 'Packaging source does not match the build.' }
$changes=& $git -C $PSScriptRoot status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0 -or $changes) { throw 'Packaging requires clean tracked sources.' }
$infverif=(Get-Command infverif.exe -ErrorAction Stop).Source
& $infverif /v $inf
if ($LASTEXITCODE -ne 0) { throw 'INF validation failed.' }
$inf2cat=(Get-Command inf2cat.exe -ErrorAction Stop).Source
& $inf2cat "/driver:$stage" /os:10_X64
if ($LASTEXITCODE -ne 0) { throw 'Catalog generation failed.' }
$cat=(Get-TheiaRegularFile (Join-Path $stage 'theia_wfp_lab.cat')).FullName
$signtool=(Get-Command signtool.exe -ErrorAction Stop).Source
# The publisher key must already be in the approved Windows certificate
# store (including a supported hardware token). Do not export/import it.
& $signtool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $cat
if ($LASTEXITCODE -ne 0) { throw 'Publisher catalog signing failed.' }
& $signtool verify /pa /v $cat
if ($LASTEXITCODE -ne 0) { throw 'Publisher catalog signature invalid.' }
$cab=Join-Path $output 'TheiaWfpLab.cab'
$ddf=Join-Path $output 'submission.ddf'
@(
    '.OPTION EXPLICIT'
    '.Set CabinetNameTemplate=TheiaWfpLab.cab'
    ".Set DiskDirectoryTemplate=""$output"""
    ".Set InfFileName=""$(Join-Path $output 'makecab.inf')"""
    ".Set RptFileName=""$(Join-Path $output 'makecab.rpt')"""
    '.Set CompressionType=MSZIP'
    '.Set Cabinet=on'
    '.Set Compress=on'
    '.Set DestinationDir=TheiaWfpLab'
    """$driver"""
    """$symbols"""
    """$inf"""
    """$cat"""
) | Set-Content -LiteralPath $ddf -Encoding ascii
& (Get-Command makecab.exe -ErrorAction Stop).Source /F $ddf
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $cab -PathType Leaf)) { throw 'CAB creation failed.' }
& $signtool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $cab
if ($LASTEXITCODE -ne 0) { throw 'Publisher CAB signing failed.' }
& $signtool verify /pa /v $cab
if ($LASTEXITCODE -ne 0) { throw 'Publisher CAB signature invalid.' }
$record=[pscustomobject]@{
    Version=1;SourceSha=$proof.SourceSha;UnsignedBuildEvidenceSha256=$BuildEvidenceSha256.ToUpperInvariant()
    UnsignedDriverSha256=$proof.DriverSha256;UnsignedImageIdentity=$image
    PdbSha256=$proof.PdbSha256;ControllerSha256=$proof.ControllerSha256
    InfSha256=(Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash
    CabSha256=(Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash
    PublisherSignedCab=$true;MicrosoftKernelSignatureVerified=$false
    SubmittedToMicrosoft=$false;CaptureReady=$false
}
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'submission-evidence.json') -Encoding utf8
$record | ConvertTo-Json
