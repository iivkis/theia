# M4.2e: CI-only cross-logon Named Pipe probe.
# Launcher runs under owner SID; -Probe runs under disposable non-admin SID.
param([switch]$Probe)
$ErrorActionPreference = 'Stop'

if ($Probe) {
    $actual = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($actual.User.Value -eq $env:THEIA_CROSS_SID_OWNER) {
        throw 'Probe must execute with a genuinely different Windows TokenUser SID'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($actual)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Probe must execute without administrator privileges'
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TheiaCrossSidCreateFile {
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr Open(string name, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

    function Open-Pipe([string]$Name) {
        if ([string]::IsNullOrWhiteSpace($Name) -or -not $Name.StartsWith('\\.\pipe\')) {
            throw 'Target must be a full local Windows pipe name supplied by the owner'
        }
        # GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING: actual kernel result.
        $handle = [TheiaCrossSidCreateFile]::Open($Name, [uint32]3221225472, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($handle -ne [IntPtr]::new(-1)) {
            if (-not [TheiaCrossSidCreateFile]::CloseHandle($handle)) {
                throw 'Closing the probe pipe handle failed'
            }
            return 0
        }
        return $code
    }

    $positive = Open-Pipe $env:THEIA_CROSS_SID_POSITIVE_PIPE
    if ($positive -ne 0) {
        throw "Different SID must first open Everyone positive-control pipe; Windows error=$positive"
    }
    $denied = Open-Pipe $env:THEIA_CROSS_SID_TARGET_PIPE
    if ($denied -ne 5) {
        throw "Protected Theia pipe must fail with kernel ERROR_ACCESS_DENIED (5); got $denied"
    }
    Write-Output 'CROSS_SID_KERNEL_DENY_OK'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($env:THEIA_CROSS_SID_USERNAME) -or
    [string]::IsNullOrWhiteSpace($env:THEIA_CROSS_SID_PASSWORD)) {
    throw 'CI did not provision the second Windows logon'
}
$secret = ConvertTo-SecureString $env:THEIA_CROSS_SID_PASSWORD -AsPlainText -Force
$credential = [pscredential]::new($env:THEIA_CROSS_SID_USERNAME, $secret)
# Do not copy account credentials into the alternate user's environment.
Remove-Item Env:THEIA_CROSS_SID_PASSWORD -ErrorAction SilentlyContinue
$basename = 'theia-cross-sid-' + [guid]::NewGuid().ToString('N')
$stdout = Join-Path $env:RUNNER_TEMP ($basename + '.out')
$stderr = Join-Path $env:RUNNER_TEMP ($basename + '.err')
try {
    $args = @('-NoProfile', '-NonInteractive', '-File', ('"' + $PSCommandPath + '"'), '-Probe')
    $child = Start-Process -FilePath (Get-Command pwsh).Source -Credential $credential -ArgumentList $args -WorkingDirectory $env:WINDIR -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $child.WaitForExit(45000)) {
        $child.Kill()
        throw 'Second-SID kernel probe timed out'
    }
    $out = [IO.File]::ReadAllText($stdout)
    $err = [IO.File]::ReadAllText($stderr)
    if ($child.ExitCode -ne 0 -or -not $out.Contains('CROSS_SID_KERNEL_DENY_OK')) {
        throw "Second-SID kernel probe failed: exit=$($child.ExitCode); stdout=$out; stderr=$err"
    }
    Write-Output 'CROSS_SID_KERNEL_DENY_OK'
}
finally {
    Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
}
