#Requires -Version 7.0
# Explicitly run only on a disposable interactive Windows desktop VM.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSha,
    [Parameter(Mandatory)][string]$Evidence,
    [switch]$ConfirmDisposable
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or -not $ConfirmDisposable) { throw 'Explicit disposable Windows VM consent required.' }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 10240 -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Interactive Windows 10/11 x64 required.' }
$edition = if ([int]$os.BuildNumber -ge 22000) { 'Windows 11' } else { 'Windows 10' }
if ($os.Caption -notlike "*$edition*") { throw 'Unrecognized desktop edition.' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Evidence = [IO.Path]::GetFullPath($Evidence)
if (Test-Path -LiteralPath $Evidence) { throw 'Evidence already exists.' }
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('theia-f20-' + [guid]::NewGuid().ToString('N'))
$child = $null
Push-Location $root
try {
    if ((& git rev-parse HEAD).Trim() -ne $ExpectedSha -or $LASTEXITCODE -ne 0) { throw 'SHA mismatch.' }
    if (& git status --porcelain --untracked-files=no) { throw 'Tracked working tree must be clean.' }
    cargo build --locked -p theia --bin theia
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    $exe = Join-Path $root 'target/debug/theia.exe'
    function Run-Theia([string[]]$Arguments) {
        $result = & $exe @Arguments 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "theia failed: $result" }
        return $result.Trim()
    }
    function Digest([string]$Text) {
        $match = [regex]::Match($Text, 'Confirm policy SHA256=([0-9a-f]{64})')
        if (-not $match.Success) { throw 'Missing reviewed policy digest.' }
        return $match.Groups[1].Value
    }
    function StatusBinding([string]$Text) {
        $revision = [regex]::Match($Text, 'revision=([1-9][0-9]*)')
        $instance = [regex]::Match($Text, 'instance=([0-9a-f]{64})')
        $policy = [regex]::Match($Text, 'policy-sha256=([0-9a-f]{64})')
        if (-not ($revision.Success -and $instance.Success -and $policy.Success)) { throw 'Unbound IPC status.' }
        return @('--instance', $instance.Groups[1].Value, '--revision', $revision.Groups[1].Value, '--policy', $policy.Groups[1].Value)
    }
    $before = Run-Theia @('client','proxy','--status')
    if ($before -notmatch '\bNoJournal\b') { throw 'Existing proxy owner/recovery: do not modify this machine.' }
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $path = Join-Path $fixture 'anti-dpi.toml'
    $http = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $socks = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $http.Start(); $socks.Start()
        $httpPort = $http.LocalEndpoint.Port; $socksPort = $socks.LocalEndpoint.Port
    } finally { $http.Stop(); $socks.Stop() }
    $document = (Get-Content -LiteralPath (Join-Path $root 'examples/anti-dpi.toml') -Raw).
        Replace('127.0.0.1:8080', "127.0.0.1:$httpPort").
        Replace('127.0.0.1:1080', "127.0.0.1:$socksPort").
        Replace('direct_egress = false','direct_egress = true')
    $document += [Environment]::NewLine + (@('[anti_dpi.resolver]',"hostname='dns.example.com'","bootstrap=['1.1.1.1']",'') -join [Environment]::NewLine)
    [IO.File]::WriteAllText($path, $document)
    $digest = Digest (Run-Theia @('anti-dpi','enroll','--config',$path))
    Run-Theia @('anti-dpi','enroll','--config',$path,'--confirm',$digest) | Out-Null
    $info = [Diagnostics.ProcessStartInfo]::new($exe)
    $info.UseShellExecute = $false
    foreach ($arg in @('anti-dpi','connect','--config',$path,'--confirm',$digest)) { $info.ArgumentList.Add($arg) }
    $child = [Diagnostics.Process]::Start($info)
    $status = $null
    for ($i=0; $i -lt 100 -and -not $child.HasExited; $i++) {
        try {
            $observed = Run-Theia @('anti-dpi','status','--config',$path)
            if ($observed -match 'connected revision=1 admission=true') { $status = $observed; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if (-not $status) { throw 'Standalone owner/readback not confirmed.' }
    $binding = StatusBinding $status
    # Deliberately prohibited loopback destination: no external network use.
    $socket = [Net.Sockets.TcpClient]::new()
    try {
        $socket.Connect('127.0.0.1',$httpPort)
        $stream = $socket.GetStream(); $stream.ReadTimeout = 3000
        $crlf = [string][char]13 + [char]10
        $data = [Text.Encoding]::ASCII.GetBytes(('CONNECT 127.0.0.1:9 HTTP/1.1' + $crlf + 'Host: 127.0.0.1:9' + $crlf + $crlf))
        $stream.Write($data,0,$data.Length)
        $reader = [IO.StreamReader]::new($stream)
        if ($reader.ReadLine() -notmatch '^HTTP/1\.1 403') { throw 'Private destination was not denied.' }
    } finally { $socket.Dispose() }
    [IO.File]::WriteAllText($path,$document.Replace('revision = 1','revision = 2'))
    $next = Digest (Run-Theia @('anti-dpi','apply','--config',$path))
    Run-Theia (@('anti-dpi','live-apply','--config',$path) + $binding + @('--confirm',$next)) | Out-Null
    $after = Run-Theia @('anti-dpi','status','--config',$path)
    if ($after -notmatch 'connected revision=2 admission=true') { throw 'Live Apply was not observed.' }
    $newBinding = StatusBinding $after
    if ($newBinding[1] -ne $binding[1]) { throw 'Runtime was replaced rather than live-applied.' }
    $staleArgs = @('anti-dpi','disconnect','--config',$path) + $binding
    $null = & $exe @staleArgs 2>&1
    if ($LASTEXITCODE -eq 0) { throw 'Stale binding accepted.' }
    Run-Theia (@('anti-dpi','disconnect','--config',$path) + $newBinding) | Out-Null
    if (-not $child.WaitForExit(10000) -or $child.ExitCode -ne 0) { throw 'Disconnect/restore did not finish.' }
    $final = Run-Theia @('client','proxy','--status')
    if ($final -notmatch '\bNoJournal\b') { throw 'OS recovery journal remains.' }
    $record = [ordered]@{
        sha=$ExpectedSha; edition=$edition; build=$os.BuildNumber
        binary_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        standalone_connect_readback=$true; private_target_denied=$true
        live_apply_same_instance=$true; stale_disconnect_denied=$true; journal_cleared=$true
        external_network_tests=$false; modify_acceptance=$false
    }
    $file = [IO.File]::Open($Evidence,[IO.FileMode]::CreateNew)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 4))
        $file.Write($bytes,0,$bytes.Length); $file.Flush($true)
    } finally { $file.Dispose() }
} finally {
    if ($child) {
        if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit(); Write-Warning 'Forced stop: inspect client proxy --status and explicitly recover if required.' }
        $child.Dispose()
    }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
    Pop-Location
}
