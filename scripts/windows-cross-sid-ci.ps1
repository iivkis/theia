# Mandatory M4.2e test: ephemeral second local Windows SID on hosted runner.
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true') { throw 'Cross-SID security E2E is CI-only' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Hosted Windows runner must allow a disposable non-admin user'
}
$account = 'theiaacl' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$bytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$password = 'Ab9!' + [Convert]::ToBase64String($bytes)
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$created = $false
try {
    New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires -Description 'Transient Theia CI pipe-ACL denial probe' -ErrorAction Stop | Out-Null
    $created = $true
    # Account is intentionally only in the default Users group.
    $env:THEIA_CROSS_SID_USERNAME = "$env:COMPUTERNAME\$account"
    $env:THEIA_CROSS_SID_PASSWORD = $password
    cargo test -p theia --locked --test windows_pipe_cross_sid -- --ignored --exact different_windows_sid_is_denied_by_kernel_dacl --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Cross-logon kernel ACL E2E failed' }
}
finally {
    Remove-Item Env:THEIA_CROSS_SID_USERNAME, Env:THEIA_CROSS_SID_PASSWORD -ErrorAction SilentlyContinue
    $password = $null
    $secure = $null
    if ($created) { Remove-LocalUser -Name $account -ErrorAction Stop }
}
