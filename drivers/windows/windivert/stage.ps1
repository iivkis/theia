[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$CorrespondingSourceArchive,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$SourceSha256,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Only official WinDivert 2.2.2 A/B/C artifacts with independently
# approved hashes. No network downloads or arbitrary ZIP extraction.
. (Join-Path $PSScriptRoot 'package.ps1')
$out=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Output must be create-only.' }
New-Item -ItemType Directory -Path $out | Out-Null
$release=Open-ApprovedArchive $Archive $ArchiveSha256
try {
    Copy-UniqueEntry $release.Zip 'x64/WinDivert.dll' (Join-Path $out 'WinDivert.dll') 16777216
    Copy-UniqueEntry $release.Zip 'x64/WinDivert64.sys' (Join-Path $out 'WinDivert64.sys') 16777216
    Copy-UniqueEntry $release.Zip 'LICENSE' (Join-Path $out 'LICENSE.WinDivert.txt') 1048576 -RootOnly
} finally { $release.Zip.Dispose(); $release.Stream.Dispose() }
$source=Open-ApprovedArchive $CorrespondingSourceArchive $SourceSha256
try {
    # Carry the exact corresponding source with the distribution, not just
    # a link. Its content must be independently reviewed for this release.
    if (!$source.Zip.Entries.Count) { throw 'Empty corresponding source archive.' }
    $source.Stream.Position=0
    $dst=[IO.File]::Open((Join-Path $out 'WinDivert-source.zip'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $source.Stream.CopyTo($dst) } finally { $dst.Dispose() }
} finally { $source.Zip.Dispose(); $source.Stream.Dispose() }
$driver=Join-Path $out 'WinDivert64.sys'
$sign=(Get-Command signtool.exe -ErrorAction Stop).Source
& $sign verify /kp /v $driver
if ($LASTEXITCODE -ne 0) { throw 'Official driver failed Windows kernel signature verification.' }
$record=[pscustomobject]@{
    Version=1;UpstreamVersion='2.2.2';Architecture='x64';License='LGPL-3.0'
    Upstream='https://github.com/basil00/WinDivert/releases/tag/v2.2.2'
    ArchiveSha256=$ArchiveSha256.ToLowerInvariant();SourceSha256=$SourceSha256.ToLowerInvariant()
    DllSha256=(Get-FileHash -LiteralPath (Join-Path $out 'WinDivert.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    SysSha256=(Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash.ToLowerInvariant()
    LicenseSha256=(Get-FileHash -LiteralPath (Join-Path $out 'LICENSE.WinDivert.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    KernelSignatureVerified=$true;Installed=$false;CaptureReady=$false
}
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'windivert-evidence.json') -Encoding utf8
$record | ConvertTo-Json
