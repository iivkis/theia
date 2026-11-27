[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$Driver,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][switch]$IsolatedTestMachine
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$IsolatedTestMachine) { throw 'A disposable, explicitly approved Windows test machine is required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required.'
}
$source = Get-Item -LiteralPath $Driver -Force
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $source.Length -gt 16777216 -or $source.Length -lt 4096) {
    throw 'Driver must be a bounded regular .sys file.'
}
if ($source.Extension -ne '.sys') { throw 'A signed .sys is required.' }
$expected = $ExpectedSha256.ToUpperInvariant()
$service = 'TheiaWfpLab'
$destination = Join-Path ([Environment]::SystemDirectory) 'drivers\TheiaWfpLab.sys'
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
if ((Test-Path -LiteralPath $serviceKey) -or (Test-Path -LiteralPath $destination)) {
    throw 'Existing service or driver file: refuse overwrite. Inspect and recover explicitly.'
}
$sign = (Get-Command signtool.exe -ErrorAction Stop).Source
function Assert-Driver {
    param([string]$Path)
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $expected) {
        throw 'Driver digest mismatch.'
    }
    & $sign verify /kp /v $Path
    if ($LASTEXITCODE -ne 0) { throw 'Kernel-mode signature verification failed.' }
}
Assert-Driver $source.FullName
if (!$PSCmdlet.ShouldProcess($destination, 'Install and start exact signed laboratory kernel driver; no BFE filters')) { return }
# Create-only in the OS-owned driver directory. Never replace an existing
# driver. Verify the copied bytes and signature again before SCM sees them.
[IO.File]::Copy($source.FullName, $destination, $false)
try {
    Assert-Driver $destination
} catch {
    # No service has been created. Remove only the new exact file, if it
    # still matches the expected digest; otherwise leave evidence.
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -eq $expected) {
        Remove-Item -LiteralPath $destination
    }
    throw
}
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
& $sc create $service type= kernel start= demand error= normal binPath= $destination
if ($LASTEXITCODE -ne 0) {
    throw 'SCM create failed or uncertain. File retained for inspection; no automatic deletion.'
}
# Verify the exact SCM record before start; no fallback to another binary.
$record = Get-ItemProperty -LiteralPath $serviceKey
if ($record.Type -ne 1 -or $record.Start -ne 3 -or $record.ImagePath.Trim('"') -ne $destination) {
    throw 'SCM record mismatch. Refuse start and retain evidence.'
}
Assert-Driver $destination
& $sc start $service
if ($LASTEXITCODE -ne 0) {
    throw 'Driver start failed. Inspect kernel code-integrity and SCM evidence. Do not disable signing.'
}
$driverRecord = Get-CimInstance Win32_SystemDriver -Filter "Name='$service'"
if (!$driverRecord -or $driverRecord.State -ne 'Running') {
    throw 'Driver running state not confirmed.'
}
[pscustomobject]@{
    Service = $service
    DriverSha256 = $expected
    State = 'Running'
    BfeFiltersInstalled = $false
    CaptureReady = $false
} | ConvertTo-Json
