[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Active','Stopped')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidateRange(2,4294967294)][uint32]$Compartment,
    [Parameter(Mandatory=$true)][string]$Ipv4Echo,
    [Parameter(Mandatory=$true)][string]$Ipv6Echo,
    [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$Port,
    [Parameter(Mandatory=$true)][string]$BuildEvidence,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BuildEvidenceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$DriverSha256,
    [Parameter(Mandatory=$true)][string]$Evidence,
    [Parameter(Mandatory=$true)][switch]$IsolatedNonIpsecLab
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$IsolatedNonIpsecLab) { throw 'Explicit isolated non-IPsec lab approval required.' }
# Must be a separate application process, not the SYSTEM runtime PID.
. (Join-Path $PSScriptRoot 'build-evidence.ps1')
$proof=Read-TheiaBuildEvidence $BuildEvidence $BuildEvidenceSha256 $SourceSha $DriverSha256
$driver=Join-Path ([Environment]::SystemDirectory) 'drivers\TheiaWfpLab.sys'
if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne $DriverSha256) { throw 'Installed driver digest mismatch.' }
& (Get-Command signtool.exe -ErrorAction Stop).Source verify /kp $driver
if ($LASTEXITCODE -ne 0) { throw 'Kernel signature verification failed.' }
$path=[IO.Path]::GetFullPath($Evidence)
if (Test-Path -LiteralPath $path) { throw 'Evidence must be create-only.' }
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
public static class TheiaUdpProbe {
    [DllImport("iphlpapi.dll")] static extern uint GetCurrentThreadCompartmentId();
    [DllImport("iphlpapi.dll")] static extern uint SetCurrentThreadCompartmentId(uint id);
    public static uint Current() { return GetCurrentThreadCompartmentId(); }
    public static string Probe(uint scope,string address,int port,bool connected,int length) {
        IPAddress ip=IPAddress.Parse(address);
        IPEndPoint peer=new IPEndPoint(ip,port);
        if (IPAddress.IsLoopback(ip)||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)
            ||ip.IsIPv6Multicast||ip.IsIPv6LinkLocal||ip.IsIPv4MappedToIPv6
            ||(ip.AddressFamily==AddressFamily.InterNetwork&&ip.GetAddressBytes()[0]>=224))
            throw new ArgumentException("Expected an authorized concrete echo peer");
        uint old=GetCurrentThreadCompartmentId();
        if (SetCurrentThreadCompartmentId(scope)!=0||GetCurrentThreadCompartmentId()!=scope)
            throw new InvalidOperationException("Compartment switch failed");
        try {
            using (Socket socket=new Socket(ip.AddressFamily,SocketType.Dgram,ProtocolType.Udp)) {
                if (ip.AddressFamily==AddressFamily.InterNetworkV6) socket.DualMode=false;
                socket.ReceiveTimeout=3000;
                socket.SendTimeout=3000;
                byte[] send=new byte[length];
                using (RandomNumberGenerator random=RandomNumberGenerator.Create()) random.GetBytes(send);
                byte[] receive=new byte[length+1];
                socket.Bind(new IPEndPoint(ip.AddressFamily==AddressFamily.InterNetwork?IPAddress.Any:IPAddress.IPv6Any,0));
                if (connected) socket.Connect(peer);
                int n=connected?socket.Send(send):socket.SendTo(send,peer);
                if (n!=length) throw new InvalidOperationException("Short UDP send");
                EndPoint from=new IPEndPoint(ip.AddressFamily==AddressFamily.InterNetwork?IPAddress.Any:IPAddress.IPv6Any,0);
                n=socket.ReceiveFrom(receive,ref from);
                if (!peer.Equals(from)||n!=length) throw new InvalidOperationException("Wrong original peer or length");
                for (int i=0;i<n;++i) if (receive[i]!=send[i]) throw new InvalidOperationException("Wrong echo bytes");
                return "Echo";
            }
        } catch (SocketException e) {
            switch(e.SocketErrorCode) {
                case SocketError.TimedOut: case SocketError.AccessDenied:
                case SocketError.ConnectionReset: case SocketError.ConnectionRefused:
                    return e.SocketErrorCode.ToString();
                default: throw;
            }
        } finally {
            if (SetCurrentThreadCompartmentId(old)!=0||GetCurrentThreadCompartmentId()!=old)
                throw new InvalidOperationException("Compartment restoration failed");
        }
    }
}
'@
if ([TheiaUdpProbe]::Current() -ne 1) { throw 'Launch this independent probe in the default compartment.' }
$results=@()
foreach ($target in @(@{Family='IPv4';Address=$Ipv4Echo},@{Family='IPv6';Address=$Ipv6Echo})) {
    $ip=[Net.IPAddress]::Parse($target.Address)
    if (($target.Family -eq 'IPv4' -and $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) -or
        ($target.Family -eq 'IPv6' -and $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6)) { throw 'Wrong peer family.' }
    foreach ($connected in @($true,$false)) {
        foreach ($length in @(0,32,1200)) {
            if ([TheiaUdpProbe]::Probe(1,$target.Address,$Port,$connected,$length) -ne 'Echo') {
                throw 'Independent echo control failed before capture probe.'
            }
            $result=[TheiaUdpProbe]::Probe($Compartment,$target.Address,$Port,$connected,$length)
            if ([TheiaUdpProbe]::Probe(1,$target.Address,$Port,$connected,$length) -ne 'Echo') {
                throw 'Independent echo control failed after capture probe.'
            }
            if (($Phase -eq 'Active' -and $result -ne 'Echo') -or
                ($Phase -eq 'Stopped' -and $result -eq 'Echo')) { throw "Unexpected UDP result: $($target.Family) $connected $length $result" }
            $results+= [pscustomobject]@{Family=$target.Family;Connected=$connected;Length=$length;Outcome=$result;ControlBefore=$true;ControlAfter=$true}
        }
    }
}
$record=[pscustomobject]@{
    Version=1;Phase=$Phase;SourceSha=$proof.SourceSha;DriverSha256=$DriverSha256.ToUpperInvariant()
    BuildEvidenceSha256=$BuildEvidenceSha256.ToUpperInvariant();Compartment=$Compartment
    Utc=[DateTime]::UtcNow.ToString('o');Results=$results
    # This proves socket observations only. Remote captures, STOP/reboot
    # lifecycle evidence and policy provenance must be reviewed separately.
    PhysicalAcceptanceComplete=$false
}
$bytes=[Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 5))
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
$record | ConvertTo-Json -Depth 5
