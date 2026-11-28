# Independent Windows Firewall guard for one authorized UDP lab tuple.
# No global default changes, custom driver, or automatic OS rule deletion.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Verify','ReconcileAbsent')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$JournalDirectory,
    [string]$LocalAddress,
    [string]$RemoteAddress,
    [ValidateRange(1,65535)][int]$LocalPort,
    [ValidateRange(1,65535)][int]$RemotePort,
    [string]$Program,
    [string]$ProgramSha256,
    [string]$IntentSha256,
    [switch]$RequireDifferentBoot,
    [switch]$IsolatedTestMachine
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$IsolatedTestMachine) { throw 'Explicit authorized disposable machine consent required.' }
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
$dir=[IO.Path]::GetFullPath($JournalDirectory)
$item=Get-Item -LiteralPath $dir -Force
if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected existing protected journal directory.' }
# The operator must provision the directory and its trusted ancestry.
# Check for a protected administrator/SYSTEM-only DACL before any mutation.
$acl=Get-Acl -LiteralPath $dir
$allowed=@('S-1-5-18','S-1-5-32-544')
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if (!$acl.AreAccessRulesProtected -or $owner -notin $allowed) { throw 'Unprotected journal directory.' }
$seen=@()
foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($ace.IdentityReference.Value -notin $allowed -or $ace.AccessControlType -ne 'Allow' -or
        $ace.IsInherited -or ($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw 'Unexpected journal ACL.'
    }
    $seen+=$ace.IdentityReference.Value
}
if (@($seen|Sort-Object -Unique).Count -ne 2) { throw 'Missing administrator or SYSTEM ACL.' }
for ($p=$item; $null -ne $p; $p=$p.Parent) {
    if ($p.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path rejected.' }
}
$machine=[string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid)
$boot=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')
$intentPath=Join-Path $dir 'intent.json'
$lockPath=Join-Path $dir 'transaction.lock'
function Write-Once([string]$Path,$Object) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Object | ConvertTo-Json -Depth 8 -Compress))
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $f.Write($bytes,0,$bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
}
function Read-Pinned([string]$Path,[string]$Expected) {
    if ($Expected -notmatch '^[a-fA-F0-9]{64}$') { throw 'Expected independently recorded manifest hash.' }
    $f=Get-Item -LiteralPath $Path -Force
    if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -lt 1 -or $f.Length -gt 16384) { throw 'Invalid journal file.' }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $length=$stream.Length
        if ($length -lt 1 -or $length -gt 16384) { throw 'Journal length changed.' }
        $bytes=[byte[]]::new([int]$length)
        $offset=0
        while ($offset -lt $bytes.Length) {
            $n=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($n -le 0) { throw 'Truncated journal.' }
            $offset+=$n
        }
        if ($stream.ReadByte() -ne -1) { throw 'Journal grew.' }
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')} finally {$sha.Dispose()}
        if ($actual -ne $Expected) { throw 'Journal hash mismatch.' }
        return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
    } finally { $stream.Dispose() }
}
function Assert-Unicast([string]$Value) {
    $ip=[Net.IPAddress]::Parse($Value)
    if ($ip.ToString() -cne $Value -or [Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or
        $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.IsIPv4MappedToIPv6) {
        throw 'Expected canonical unicast non-loopback address.'
    }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $first=$ip.GetAddressBytes()[0]
        if ($first -eq 0 -or $first -ge 224) { throw 'Invalid IPv4 scope.' }
    } elseif ($ip.ScopeId -ne 0) { throw 'Scoped IPv6 denied.' }
    return $ip
}
function Assert-Intent($record) {
    if ($record.Version -ne 1 -or $record.MachineGuid -ne $machine -or
        $record.Name -notmatch '^Theia-WinDivert-GuardLab-[a-f0-9]{32}$' -or
        $record.Marker -cne ('Theia owned UDP guard lab '+$record.Name.Substring('Theia-WinDivert-GuardLab-'.Length)) -or
        $record.ProgramSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        $record.LocalPort -lt 1 -or $record.LocalPort -gt 65535 -or $record.RemotePort -lt 1 -or $record.RemotePort -gt 65535) { throw 'Invalid guard intent.' }
    $a=Assert-Unicast $record.LocalAddress
    $b=Assert-Unicast $record.RemoteAddress
    if ($a.AddressFamily -ne $b.AddressFamily -or $a.Equals($b)) { throw 'Invalid guard tuple.' }
    if (![IO.Path]::IsPathRooted($record.Program) -or $record.Program.IndexOfAny([char[]]'*?%') -ge 0) { throw 'Invalid guard program.' }
}
function Get-ExactRule([string]$Store,[string]$Name) {
    # Query the store rather than swallowing provider failures as absence.
    $all=@(Get-NetFirewallRule -PolicyStore $Store | Where-Object { $_.Name -ieq $Name })
    if ($all.Count -gt 1) { throw 'Ambiguous guard rule.' }
    if ($all.Count -eq 0) { return $null }
    if ($all[0].Name -cne $Name) { throw 'Rule name changed.' }
    return $all[0]
}
function Assert-Guard($record,[string]$Store) {
    $rule=Get-ExactRule $Store $record.Name
    if ($null -eq $rule -or $rule.Enabled.ToString() -ne 'True' -or $rule.Action.ToString() -ne 'Block' -or
        $rule.Direction.ToString() -ne 'Outbound' -or $rule.Profile.ToString() -ne 'Any' -or
        $rule.Description -cne $record.Marker -or $rule.DisplayName -cne $record.Name) {
        throw "Missing or changed rule in $Store."
    }
    $addr=@($rule | Get-NetFirewallAddressFilter)
    $ports=@($rule | Get-NetFirewallPortFilter)
    $app=@($rule | Get-NetFirewallApplicationFilter)
    $service=@($rule | Get-NetFirewallServiceFilter)
    $interfaces=@($rule | Get-NetFirewallInterfaceFilter)
    $types=@($rule | Get-NetFirewallInterfaceTypeFilter)
    if ($addr.Count -ne 1 -or $ports.Count -ne 1 -or $app.Count -ne 1 -or $service.Count -ne 1 -or $interfaces.Count -ne 1 -or $types.Count -ne 1) { throw 'Ambiguous rule filters.' }
    $prefix=if ($record.LocalAddress.Contains(':')) {'/128'}else{'/32'}
    $local=@($record.LocalAddress,($record.LocalAddress+$prefix))
    $remote=@($record.RemoteAddress,($record.RemoteAddress+$prefix))
    if (@($addr[0].LocalAddress).Count -ne 1 -or @($addr[0].RemoteAddress).Count -ne 1 -or
        @($addr[0].LocalAddress)[0] -notin $local -or @($addr[0].RemoteAddress)[0] -notin $remote -or
        $ports[0].Protocol.ToString() -notin @('UDP','17') -or
        @($ports[0].LocalPort).Count -ne 1 -or @($ports[0].RemotePort).Count -ne 1 -or
        [string]$ports[0].LocalPort -ne [string]$record.LocalPort -or [string]$ports[0].RemotePort -ne [string]$record.RemotePort -or
        $app[0].Program -ne $record.Program -or $app[0].Package -ne 'Any' -or
        $service[0].Service -ne 'Any' -or [string]$interfaces[0].InterfaceAlias -ne 'Any' -or
        [string]$types[0].InterfaceType -ne 'Any') { throw "Changed scope in $Store." }
}
function Assert-Firewall {
    if ((Get-Service MpsSvc).Status -ne 'Running') { throw 'Windows Firewall service inactive.' }
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object { $_.Enabled.ToString() -ne 'True' -or $_.AllowLocalFirewallRules.ToString() -eq 'False' }).Count -ne 0) {
        throw 'Effective firewall policy does not permit the guard.'
    }
}
# Cooperative lock serializes this script, not other administrators.
if (Test-Path -LiteralPath $lockPath) {
    $lockItem=Get-Item -LiteralPath $lockPath -Force
    if ($lockItem.PSIsContainer -or ($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid lock file.' }
}
$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    if ($Mode -eq 'Prepare') {
        if ($RequireDifferentBoot -or (Test-Path -LiteralPath $intentPath)) { throw 'Previous intent requires review; Prepare cannot require a later boot.' }
        Assert-Firewall
        $a=Assert-Unicast $LocalAddress
        $b=Assert-Unicast $RemoteAddress
        if ($a.AddressFamily -ne $b.AddressFamily -or $a.Equals($b) -or $LocalPort -eq 0 -or $RemotePort -eq 0) { throw 'Invalid tuple.' }
        if (@(Get-NetIPAddress -IPAddress $LocalAddress).Count -ne 1) { throw 'Local address not unique.' }
        $file=Get-Item -LiteralPath $Program -Force
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Extension -ne '.exe' -or
            $ProgramSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid program.' }
        $lease=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $ProgramSha256) { throw 'Program hash mismatch.' }
            $id=[Guid]::NewGuid().ToString('N')
            $record=[pscustomobject]@{Version=1;MachineGuid=$machine;BootUtc=$boot;Name="Theia-WinDivert-GuardLab-$id";Marker="Theia owned UDP guard lab $id";
                LocalAddress=$LocalAddress;RemoteAddress=$RemoteAddress;LocalPort=$LocalPort;RemotePort=$RemotePort;Program=$file.FullName;ProgramSha256=$ProgramSha256}
            Assert-Intent $record
            if ($null -ne (Get-ExactRule PersistentStore $record.Name) -or $null -ne (Get-ExactRule ActiveStore $record.Name)) { throw 'Rule name conflict.' }
            Write-Once $intentPath $record
            $IntentSha256=(Get-FileHash -LiteralPath $intentPath -Algorithm SHA256).Hash
            # The intent is durable before persistent mutation. Never remove
            # a rule on exception: retain the evidence for manual review.
            $parameters=@{
                PolicyStore='PersistentStore';Name=$record.Name;DisplayName=$record.Name;Description=$record.Marker
                Direction='Outbound';Action='Block';Enabled='True';Profile='Any';Protocol='UDP'
                LocalAddress=$record.LocalAddress;RemoteAddress=$record.RemoteAddress;LocalPort=$record.LocalPort
                RemotePort=$record.RemotePort;Program=$record.Program
            }
            New-NetFirewallRule @parameters | Out-Null
        } finally { $lease.Dispose() }
    }
    $record=Read-Pinned $intentPath $IntentSha256
    Assert-Intent $record
    if ($RequireDifferentBoot -and $boot -eq $record.BootUtc) { throw 'Reboot has not been observed.' }
    if ($Mode -eq 'ReconcileAbsent') {
        # Read-only reconciliation after independent administrator removal.
        # This is not atomic CAS of Windows Firewall policy.
        if ($null -ne (Get-ExactRule PersistentStore $record.Name) -or $null -ne (Get-ExactRule ActiveStore $record.Name)) {
            throw 'Rule still exists; retain journal for review. No automatic deletion.'
        }
        $null=Read-Pinned $intentPath $IntentSha256
        $report=[pscustomobject]@{Version=1;IntentSha256=$IntentSha256;Rule=$record.Name;BootUtc=$boot;ObservedAbsent=$true;
            AtomicOsCas=$false;PhysicalAcceptance=$false;CaptureReady=$false}
        Write-Once (Join-Path $dir 'absence-observation.json') $report
    } else {
        Assert-Firewall
        Assert-Guard $record PersistentStore
        Assert-Guard $record ActiveStore
        $null=Read-Pinned $intentPath $IntentSha256
        $report=[pscustomobject]@{Version=1;IntentSha256=$IntentSha256;Rule=$record.Name;BootUtc=$boot;DifferentBoot=($boot -ne $record.BootUtc);
            PersistentRuleObserved=$true;EffectiveRuleObserved=$true;AtomicOsCas=$false;PhysicalAcceptance=$false;CaptureReady=$false}
        Write-Once (Join-Path $dir ("observed-"+[Guid]::NewGuid().ToString('N')+'.json')) $report
    }
    $report | ConvertTo-Json
} finally {$lock.Dispose()}
