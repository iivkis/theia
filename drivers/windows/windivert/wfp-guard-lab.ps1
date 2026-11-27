# Explicit disposable-machine fixture. Blocks ALL outbound IPv4/IPv6 at
# the selected interface (not only TCP/UDP). Do not run over remote access.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Verify','Recover','CaptureVerify','RedirectVerify')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$JournalDirectory,
    [Parameter(Mandatory=$true)][string]$Helper,
    [Parameter(Mandatory=$true)][string]$HelperSha256,
    [string[]]$InterfaceGuid,
    [switch]$IncludeBootTime,
    [string]$IntentSha256,
    [switch]$IsolatedTestMachine,
    [switch]$ConfirmRecovery,
    [switch]$RequireDifferentBoot,
    [string]$TheiaExe,
    [string]$TheiaSha256,
    [string]$DriverDirectory,
    [string]$DllSha256,
    [string]$SysSha256,
    [uint32]$CaptureInterfaceIndex,
    [uint32]$CarrierInterfaceIndex,
    [string]$ClientConfig,
    [string]$ClientConfigSha256,
    [switch]$ConfirmIsolatedTwoInterface,
    [ValidateRange(1,30)][int]$CaptureSeconds=10
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$IsolatedTestMachine) { throw 'Explicit disposable machine and local console consent required.' }
if ($Mode -eq 'Recover' -and !$ConfirmRecovery) { throw 'Recovery requires explicit confirmation.' }
if ($Mode -ne 'Prepare' -and ($IncludeBootTime -or $InterfaceGuid)) { throw 'Verify/recovery must use the exact pinned intent.' }
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
$allowed=@('S-1-5-18','S-1-5-32-544')
function Assert-ProtectedDirectory([string]$Path) {
    $item=Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected existing protected directory.' }
    $acl=Get-Acl -LiteralPath $item.FullName
    if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Unprotected directory.' }
    $seen=@()
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.IdentityReference.Value -notin $allowed -or $ace.AccessControlType -ne 'Allow' -or
            $ace.IsInherited -or ($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'Unexpected directory ACL.' }
        $seen+=$ace.IdentityReference.Value
    }
    if (@($seen|Sort-Object -Unique).Count -ne 2) { throw 'Missing administrator or SYSTEM ACL.' }
    for ($p=$item; $null -ne $p; $p=$p.Parent) {
        if ($p.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path rejected.' }
    }
    return $item.FullName
}
function Assert-Regular([string]$Path) {
    $f=Get-Item -LiteralPath $Path -Force
    if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular file required.' }
    $acl=Get-Acl -LiteralPath $f.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Unexpected file owner.' }
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.IdentityReference.Value -notin $allowed -or $ace.AccessControlType -ne 'Allow') { throw 'Unexpected file ACL.' }
    }
    return $f
}
function Hash-Bytes([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Write-Once([string]$Path,$Object) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Object | ConvertTo-Json -Depth 5 -Compress))
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $f.Write($bytes,0,$bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
    return (Hash-Bytes $bytes)
}
function Read-Pinned([IO.FileStream]$Stream,[string]$Expected) {
    if ($Expected -cnotmatch '^[a-f0-9]{64}$' -or $Stream.Length -lt 1 -or $Stream.Length -gt 8192) { throw 'Invalid pinned intent.' }
    $Stream.Position=0
    $bytes=[byte[]]::new([int]$Stream.Length)
    $offset=0
    while ($offset -lt $bytes.Length) {
        $n=$Stream.Read($bytes,$offset,$bytes.Length-$offset)
        if ($n -le 0) { throw 'Truncated intent.' }
        $offset+=$n
    }
    if ($Stream.ReadByte() -ne -1 -or (Hash-Bytes $bytes) -cne $Expected) { throw 'Intent mismatch.' }
    return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
}
function CanonicalGuid([string]$Value) {
    $g=[Guid]::Parse($Value)
    if ($g -eq [Guid]::Empty) { throw 'Empty GUID.' }
    return $g.ToString('B')
}
$dir=Assert-ProtectedDirectory $JournalDirectory
$helperFile=Assert-Regular ([IO.Path]::GetFullPath($Helper))
$null=Assert-ProtectedDirectory $helperFile.DirectoryName
if ($helperFile.Extension -ine '.exe' -or $HelperSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Pinned helper executable required.' }
$helperLease=[IO.File]::Open($helperFile.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash($helperLease)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($hash -ne $HelperSha256) { throw 'Helper hash mismatch.' }
    $machine=[string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid)
    $boot=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')
    $intent=Join-Path $dir 'wfp-intent.json'
    $lockPath=Join-Path $dir 'wfp.lock'
    if (Test-Path -LiteralPath $lockPath) { $null=Assert-Regular $lockPath }
    $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        if ($Mode -eq 'Prepare') {
            if ($RequireDifferentBoot -or $ConfirmRecovery -or (Test-Path -LiteralPath $intent)) { throw 'Existing or invalid transaction; review required.' }
            if (!$InterfaceGuid -or @($InterfaceGuid).Count -gt 8) { throw 'Review one to eight explicit non-loopback interfaces.' }
            $plans=@()
            foreach ($value in $InterfaceGuid) {
                $id=CanonicalGuid $value
                $luid=(& $helperFile.FullName interface $id)
                if ($LASTEXITCODE -ne 0 -or $luid -cnotmatch '^[a-f0-9]{16}$' -or $luid -eq '0000000000000000') { throw 'Interface not verified.' }
                if (@($plans | Where-Object { $_.Interface -ceq $id -or $_.Luid -ceq $luid }).Count -ne 0) { throw 'Duplicate interface.' }
                $plan=[ordered]@{Interface=$id;Luid=$luid;Sub=[Guid]::NewGuid().ToString('B');V4=[Guid]::NewGuid().ToString('B');
                    V6=[Guid]::NewGuid().ToString('B');Marker=[Guid]::NewGuid().ToString('B')}
                if ($IncludeBootTime) {
                    $plan['Boot4']=[Guid]::NewGuid().ToString('B')
                    $plan['Boot6']=[Guid]::NewGuid().ToString('B')
                }
                $plans+=[pscustomobject]$plan
            }
            $record=[pscustomobject]@{Version=2;Machine=$machine;BootUtc=$boot;HelperSha256=$hash;
                BootTime=[bool]$IncludeBootTime;Interfaces=$plans}
            $IntentSha256=Write-Once $intent $record
            # Emit the digest before the transaction, even if it fails.
            Write-Host "Durable intent SHA256: $IntentSha256"
        }
        $null=Assert-Regular $intent
        # Deny replacement or write while the BFE transaction is in progress.
        $intentLease=[IO.File]::Open($intent,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $r=Read-Pinned $intentLease $IntentSha256
            if ($r.Version -notin @(1,2) -or $r.Machine -cne $machine -or $r.HelperSha256 -cne $hash) { throw 'Intent scope/version mismatch.' }
            if ($RequireDifferentBoot -and $r.BootUtc -eq $boot) { throw 'Reboot has not been observed.' }
            $operation=switch($Mode) {'Prepare' {'install'} 'Verify' {'inspect'} 'CaptureVerify' {'inspect'} 'RedirectVerify' {'inspect'} 'Recover' {'recover'}}
            if ($r.Version -eq 1) {
                $plans=@($r)
                $bootConfigured=$false
                $native=@($operation)
            } else {
                if ($r.BootTime -isnot [bool] -or !$r.Interfaces -or @($r.Interfaces).Count -gt 8) { throw 'Invalid v2 guard scope.' }
                $plans=@($r.Interfaces)
                $bootConfigured=$r.BootTime
                $variant=if ($bootConfigured) {'boot'} else {'persistent'}
                $native=@("$operation-many",$variant)
            }
            $seenInterfaces=@();$seenLuids=@();$seenKeys=@()
            foreach ($plan in $plans) {
                if ($plan.Luid -cnotmatch '^[a-f0-9]{16}$' -or $plan.Luid -eq '0000000000000000' -or
                    $plan.Interface -cin $seenInterfaces -or $plan.Luid -cin $seenLuids) { throw 'Invalid or duplicate interface scope.' }
                $fields=@('Interface','Sub','V4','V6','Marker')
                if ($bootConfigured) {$fields+=@('Boot4','Boot6')}
                foreach ($key in $fields) {
                    if ((CanonicalGuid $plan.$key) -cne $plan.$key) { throw 'Noncanonical intent GUID.' }
                    if ($key -ne 'Interface') {
                        if ($plan.$key -cin $seenKeys) {throw 'Duplicate object identity.'}
                        $seenKeys+=$plan.$key
                    }
                }
                $seenInterfaces+=$plan.Interface;$seenLuids+=$plan.Luid
                $native+=@($plan.Interface,$plan.Luid,$plan.Sub,$plan.V4,$plan.V6,$plan.Marker)
                if ($bootConfigured) {$native+=@($plan.Boot4,$plan.Boot6)}
            }
            $native+='isolated-test-machine'
            $state=(& $helperFile.FullName @native)
            if ($LASTEXITCODE -ne 0) { throw 'WFP transaction failed or conflicted; retain journal.' }
            $expected=if ($Mode -eq 'Recover') {'absent'} else {'exact'}
            if ($state -cne $expected) { throw 'Unexpected committed WFP state; retain journal.' }
            $null=Read-Pinned $intentLease $IntentSha256
            $captureObserved=$null
            $redirectCompleted=$false
            if ($Mode -in @('CaptureVerify','RedirectVerify')) {
                if (!$TheiaExe -or !$DriverDirectory -or !$CaptureInterfaceIndex -or
                    $TheiaSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    $DllSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    $SysSha256 -cnotmatch '^[a-f0-9]{64}$') {
                    throw 'Explicit pinned capture inputs required.'
                }
                $adapters=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $CaptureInterfaceIndex })
                if ($adapters.Count -ne 1 -or (CanonicalGuid ([string]$adapters[0].InterfaceGuid)) -cnotin $seenInterfaces) { throw 'Capture interface is not covered by the pinned guard.' }
                $configLease=$null
                if ($Mode -eq 'RedirectVerify') {
                    if (!$ConfirmIsolatedTwoInterface -or !$CarrierInterfaceIndex -or
                        $CarrierInterfaceIndex -eq $CaptureInterfaceIndex -or $CaptureSeconds -lt 5 -or
                        !$ClientConfig -or $ClientConfigSha256 -cnotmatch '^[a-f0-9]{64}$') {
                        throw 'Explicit pinned config and separate outside carrier interface required.'
                    }
                    $carriers=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $CarrierInterfaceIndex })
                    if ($carriers.Count -ne 1 -or (CanonicalGuid ([string]$carriers[0].InterfaceGuid)) -cin $seenInterfaces) {
                        throw 'Lab carrier interface must be outside the persistent guard scope.'
                    }
                    $carrierGuid=CanonicalGuid ([string]$carriers[0].InterfaceGuid)
                    $config=Assert-Regular ([IO.Path]::GetFullPath($ClientConfig))
                    $null=Assert-ProtectedDirectory $config.DirectoryName
                    if ($config.Extension -ine '.toml') { throw 'Pinned client TOML required.' }
                }
                $exe=Assert-Regular ([IO.Path]::GetFullPath($TheiaExe))
                $null=Assert-ProtectedDirectory $exe.DirectoryName
                if ($exe.Extension -ine '.exe') { throw 'Executable required.' }
                $driverDir=Assert-ProtectedDirectory $DriverDirectory
                $exeLease=[IO.File]::Open($exe.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try {
                    $digest=[Security.Cryptography.SHA256]::Create()
                    try { $actual=[BitConverter]::ToString($digest.ComputeHash($exeLease)).Replace('-','').ToLowerInvariant() } finally { $digest.Dispose() }
                    if ($actual -cne $TheiaSha256) { throw 'Capture executable hash mismatch.' }
                    try {
                        if ($Mode -eq 'RedirectVerify') {
                            $configLease=[IO.File]::Open($config.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                            if ($configLease.Length -lt 1 -or $configLease.Length -gt 1048576) { throw 'Invalid client config length.' }
                            $digest=[Security.Cryptography.SHA256]::Create()
                            try { $actual=[BitConverter]::ToString($digest.ComputeHash($configLease)).Replace('-','').ToLowerInvariant() } finally { $digest.Dispose() }
                            if ($actual -cne $ClientConfigSha256) { throw 'Client config hash mismatch.' }
                            $null=(& $exe.FullName client windivert --interface-redirect-lab --config $config.FullName --directory $driverDir --dll-sha256 $DllSha256 --sys-sha256 $SysSha256 --capture-interface $CaptureInterfaceIndex --carrier-interface $CarrierInterfaceIndex --seconds $CaptureSeconds --confirm-isolated-two-interface)
                            if ($LASTEXITCODE -ne 0) { throw 'Joint redirect command failed; retain guard.' }
                            $carriers=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $CarrierInterfaceIndex })
                            if ($carriers.Count -ne 1 -or (CanonicalGuid ([string]$carriers[0].InterfaceGuid)) -cne $carrierGuid) {
                                throw 'Carrier interface changed during redirect.'
                            }
                            $redirectCompleted=$true
                        } else {
                            $captureOutput=(& $exe.FullName client windivert --scope-drop-lab --directory $driverDir --dll-sha256 $DllSha256 --sys-sha256 $SysSha256 --interface-index $CaptureInterfaceIndex --seconds $CaptureSeconds --confirm-block | Out-String)
                            $captureExit=$LASTEXITCODE
                            $observations=[regex]::Matches($captureOutput,'(?m)\bobserved=(\d+)\b')
                            if ($captureExit -ne 0 -or $observations.Count -ne 1) { throw 'Capture verification failed.' }
                            $captureObserved=[uint64]$observations[0].Groups[1].Value
                            if ($captureObserved -eq 0) { throw 'No packets observed; joint capture evidence is inconclusive.' }
                        }
                    } finally {
                        $state=(& $helperFile.FullName @native)
                        if ($LASTEXITCODE -ne 0 -or $state -cne 'exact') { throw 'Guard changed during capture; retain journal.' }
                        $null=Read-Pinned $intentLease $IntentSha256
                    }
                } finally {
                    if ($null -ne $configLease) { $configLease.Dispose() }
                    $exeLease.Dispose()
                }
            }
            [pscustomobject]@{Version=$r.Version;IntentSha256=$IntentSha256;BootUtc=$boot;State=$state;
                JointCaptureChecked=($Mode -eq 'CaptureVerify');CaptureObserved=$captureObserved;
                JointRedirectCommandCompleted=$redirectCompleted;RedirectExchangeVerified=$false;
                FullHostCarrierExclusionVerified=$false;
                Interfaces=$seenInterfaces;TransactionalObjectCas=$true;PacketEnforcementVerified=$false;
                BootTimeObjectsConfigured=($bootConfigured -and $state -ceq 'exact');
                BootTimeCoverageVerified=$false;ProductionCaptureReady=$false} | ConvertTo-Json -Compress
        } finally { $intentLease.Dispose() }
    } finally { $lock.Dispose() }
} finally { $helperLease.Dispose() }
