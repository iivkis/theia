[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][ValidateSet('BeforeReboot','AfterReboot')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidateRange(2,4294967294)][uint32]$Compartment,
    [Parameter(Mandatory=$true)][string]$BfeController,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ControllerSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$DriverSha256,
    [Parameter(Mandatory=$true)][string]$Evidence,
    [Parameter(Mandatory=$true)][string]$BuildEvidence,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BuildEvidenceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][switch]$IsolatedTestMachine,
    [switch]$Recover
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$IsolatedTestMachine) { throw 'Disposable, explicitly approved Windows test machine required.' }
if ($Recover -and $Phase -ne 'AfterReboot') { throw 'Recovery must be a separate post-reboot action.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
$exe = Get-Item -LiteralPath $BfeController -Force
$driver = Join-Path ([Environment]::SystemDirectory) 'drivers\TheiaWfpLab.sys'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\TheiaWfpLab'
$expectedController = $ControllerSha256.ToUpperInvariant()
$expectedDriver = $DriverSha256.ToUpperInvariant()
. (Join-Path $PSScriptRoot 'build-evidence.ps1')
$proof = Read-TheiaBuildEvidence $BuildEvidence $BuildEvidenceSha256 $SourceSha $expectedDriver
if ($proof.ControllerSha256 -ne $expectedController) { throw 'Controller build evidence mismatch.' }
$sign = (Get-Command signtool.exe -ErrorAction Stop).Source
function Assert-Inputs {
    if ($exe.PSIsContainer -or ($exe.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash -ne $expectedController) {
        throw 'Controller digest or file type mismatch.'
    }
    if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne $expectedDriver) { throw 'Driver digest mismatch.' }
    & $sign verify /kp /v $driver
    if ($LASTEXITCODE -ne 0) { throw 'Kernel signature failed.' }
    $record = Get-ItemProperty -LiteralPath $serviceKey
    if ($record.Type -ne 1 -or $record.Start -ne 3 -or $record.ImagePath.Trim('"') -ne $driver) {
        throw 'Unexpected SCM driver record.'
    }
}
function Invoke-Bfe([string]$Action) {
    Assert-Inputs
    & $exe.FullName $Action $Compartment --isolated-lab-confirm
    if ($LASTEXITCODE -ne 0) { throw "BFE $Action failed or ownership uncertain." }
}
function Read-State {
    $os = Get-CimInstance Win32_OperatingSystem
    $state = Get-CimInstance Win32_SystemDriver -Filter "Name='TheiaWfpLab'"
    if (!$state) { throw 'Driver state missing.' }
    [pscustomobject]@{
        Version = 2
        SourceSha = $proof.SourceSha
        BuildEvidenceSha256 = $BuildEvidenceSha256.ToUpperInvariant()
        Machine = $env:COMPUTERNAME
        MachineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid)
        BootUtc = ([datetime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
        Compartment = $Compartment
        ControllerSha256 = $expectedController
        DriverSha256 = $expectedDriver
        DriverState = [string]$state.State
    }
}
Assert-Inputs
$evidencePath = [IO.Path]::GetFullPath($Evidence)
if ($Phase -eq 'BeforeReboot') {
    Invoke-Bfe 'inspect'
    $before = Read-State
    if ($before.DriverState -ne 'Running') { throw 'Pre-reboot driver must be running.' }
    # Create-only, no overwrite of evidence. Caller provides a protected
    # local administrator-owned directory on the disposable machine.
    $stream = [IO.File]::Open($evidencePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($before | ConvertTo-Json -Compress))
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    $before | ConvertTo-Json
    return
}
$item = Get-Item -LiteralPath $evidencePath -Force
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096) {
    throw 'Invalid pre-reboot evidence file.'
}
$before = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
$after = Read-State
if ($before.Version -ne 2 -or $before.SourceSha -cne $after.SourceSha -or
    $before.BuildEvidenceSha256 -ne $after.BuildEvidenceSha256 -or $before.Machine -ne $after.Machine -or
    !$before.MachineGuid -or $before.MachineGuid -ne $after.MachineGuid -or
    $before.Compartment -ne $after.Compartment -or $before.ControllerSha256 -ne $after.ControllerSha256 -or
    $before.DriverSha256 -ne $after.DriverSha256 -or $before.DriverState -ne 'Running' -or
    [datetimeoffset]::Parse($after.BootUtc) -le [datetimeoffset]::Parse($before.BootUtc)) {
    throw 'Same boot, wrong machine, wrong scope, or evidence mismatch.'
}
Invoke-Bfe 'inspect'
$recovered = $false
if ($Recover -and $PSCmdlet.ShouldProcess("compartment $Compartment", 'Delete only exact owned BFE objects after verified reboot')) {
    # Demand-start driver must be stopped before destructive recovery.
    # A running driver may have a live owner; do not infer owner death from reboot alone.
    if ((Read-State).DriverState -ne 'Stopped') { throw 'Refuse recovery while driver is running or state is uncertain.' }
    Invoke-Bfe 'recover'
    Invoke-Bfe 'inspect-absent'
    $recovered = $true
}
[pscustomobject]@{
    Before = $before
    After = $after
    RebootObserved = $true
    ExactOwnedFiltersVerified = $true
    ExactOwnedFiltersRecovered = $recovered
    TrafficFailClosedVerified = $false
    CaptureReady = $false
} | ConvertTo-Json -Depth 4
