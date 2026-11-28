#Requires -Version 7.0
# Run only in a disposable Windows desktop VM, as the same interactive user.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Native','PrepareReboot','RecoverAfterReboot')][string]$Phase,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSha,
    [Parameter(Mandatory)][string]$Evidence,
    [string]$Config,
    [switch]$ConfirmDisposable
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or -not $ConfirmDisposable) { throw 'Explicit disposable Windows VM consent required.' }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 10240 -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'Windows 10/11 x64 interactive workstation required; Server/session 0 does not qualify.'
}
$edition = if ([int]$os.BuildNumber -ge 22000) { 'Windows 11' } else { 'Windows 10' }
if ($os.Caption -notlike "*$edition*") { throw 'Unrecognized desktop edition.' }
$boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$userHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$env:COMPUTERNAME/$sid")))
$Evidence = [IO.Path]::GetFullPath($Evidence)
if ($Config) { $Config = (Resolve-Path -LiteralPath $Config).Path }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target = Join-Path $root 'target/windows-client-acceptance'
$exe = Join-Path $target 'debug/theia.exe'
function Write-Evidence($path, $value) {
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    try {
        $writer = [IO.StreamWriter]::new($stream)
        try { $writer.WriteLine(($value | ConvertTo-Json -Depth 6)); $writer.Flush(); $stream.Flush($true) }
        finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}
function Invoke-Theia([string[]]$Arguments) {
    $output = & $exe @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "theia failed: $output" }
    return $output
}
function Test-Status([string]$Expected) {
    $status = Invoke-Theia @('client','proxy','--status')
    if ($status -notmatch $Expected) { throw "Unexpected proxy state: $status" }
    return $status.Trim()
}
function Invoke-ExactTest([string]$Name,[string[]]$Selector,[switch]$Ignored) {
    $args = @('test','-p','theia','--locked') + $Selector + @('--',$Name,'--exact','--nocapture')
    if ($Ignored) { $args += '--ignored' }
    $output = & cargo @args 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $output
    if ($code -ne 0 -or $output -notmatch ('(?m)^test '+[regex]::Escape($Name)+' \.\.\. ok\s*$')) {
        throw "Exact test did not pass: $Name"
    }
}
$previousConsent = $env:THEIA_WINDOWS_PROXY_E2E_ALLOWED
$previousPipe = $env:THEIA_CLIENT_CONTROL_PIPE
Push-Location $root
try {
    if ((& git rev-parse HEAD).Trim() -ne $ExpectedSha -or $LASTEXITCODE -ne 0) { throw 'SHA mismatch.' }
    $dirty = & git status --porcelain --untracked-files=no
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Tracked working tree must be clean.' }
    $env:THEIA_WINDOWS_PROXY_E2E_ALLOWED = 'yes'
    $record = [ordered]@{ sha=$ExpectedSha; edition=$edition; build=$os.BuildNumber; boot=$boot; user_hash=$userHash; phase=$Phase }
    if ($Phase -eq 'Native') {
        if (Test-Path -LiteralPath $Evidence) { throw 'Evidence already exists.' }
        Invoke-ExactTest 'windows_system_proxy::tests::native_wininet_cas_recovery_and_foreign_override' @('--lib') -Ignored
        Invoke-ExactTest 'local_proxy::product_proxy_listener_is_exclusive_and_loopback_only' @('--lib')
        Invoke-ExactTest 'management::strict_wire_matrix_tests::lifecycle_ipc_requires_canonical_instance_and_never_treats_ack_as_restore' @('--lib')
        Invoke-ExactTest 'compiled_client_proxy_conpty_lifecycle' @('--test','tui_real_terminal') -Ignored
        $record.tests_passed = 4
        Write-Evidence $Evidence $record
    } elseif ($Phase -eq 'PrepareReboot') {
        if (-not $Config -or (Test-Path -LiteralPath $Evidence)) { throw 'Valid config and unused evidence path required.' }
        & cargo build -p theia --locked --bin theia --target-dir $target
        if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
        $record.binary_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        Test-Status '\bNoJournal\b' | Out-Null
        $env:THEIA_CLIENT_CONTROL_PIPE = 'acceptance-' + [guid]::NewGuid().ToString('N')
        $start = [Diagnostics.ProcessStartInfo]::new($exe)
        $start.UseShellExecute = $false
        foreach ($arg in @('client','run','--config',$Config,'--system-proxy','--confirm')) { $start.ArgumentList.Add($arg) }
        $child = [Diagnostics.Process]::Start($start)
        $connected = $false
        try {
            for ($i=0; $i -lt 120 -and -not $child.HasExited; $i++) {
                try {
                    $state = Invoke-Theia @('client','lifecycle')
                    if ($state -match 'lifecycle=connected;' -and $state -match 'listeners_ready=true;' -and $state -match 'proxy_settings_applied=yes;') {
                        $connected = $true; break
                    }
                } catch { }
                Start-Sleep -Milliseconds 500
            }
            if (-not $connected) { throw 'Connection not confirmed.' }
        } finally {
            # Kill only the exact child created by this harness, never by process name.
            if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
            $child.Dispose()
        }
        $record.pending_status = Test-Status '\bPendingOwned\b'
        Write-Evidence $Evidence $record
        Write-Host 'Hard-kill evidence saved. Reboot this disposable VM manually, then run RecoverAfterReboot as the same user. Do not use this VM for browsing meanwhile.'
    } else {
        $before = Get-Content -LiteralPath $Evidence -Raw | ConvertFrom-Json
        $afterPath = $Evidence + '.recovered.json'
        if ((Test-Path -LiteralPath $afterPath) -or $before.phase -ne 'PrepareReboot' -or
            $before.sha -ne $ExpectedSha -or $before.edition -ne $edition -or $before.build -ne $os.BuildNumber -or
            $before.user_hash -ne $userHash -or [datetime]$boot -le [datetime]$before.boot -or
            $before.binary_sha256 -ne (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash) {
            throw 'Reboot evidence, user, OS, or exact binary mismatch.'
        }
        $record.binary_sha256 = $before.binary_sha256
        $record.pending_status = Test-Status '\b(PendingOwned|PendingAlreadyRestored)\b'
        $record.recovery = (Invoke-Theia @('client','proxy','--recover','--confirm')).Trim()
        if ($record.recovery -notmatch '\b(Restored|AlreadyRestored)\b') { throw 'Recovery not confirmed.' }
        $record.final_status = Test-Status '\bNoJournal\b'
        Write-Evidence $afterPath $record
    }
} finally {
    $env:THEIA_WINDOWS_PROXY_E2E_ALLOWED = $previousConsent
    $env:THEIA_CLIENT_CONTROL_PIPE = $previousPipe
    Pop-Location
}
