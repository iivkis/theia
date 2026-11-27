param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$CertificateThumbprint,
    [switch]$VerifyKernelSignature
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Output directory must not already exist' }
New-Item -ItemType Directory -Path $destination | Out-Null
$msbuild = (Get-Command msbuild.exe -ErrorAction Stop).Source
$cl = (Get-Command cl.exe -ErrorAction Stop).Source
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($Executable)) failed ($LASTEXITCODE)" }
}
Invoke-Checked $msbuild @((Join-Path $root 'theia_wfp_lab.vcxproj'), '/t:Build', '/p:Configuration=Release', '/p:Platform=x64', "/p:OutDir=$destination\", "/p:IntDir=$destination\obj\", '/p:SignMode=Off', '/m:1')
$driver = Join-Path $destination 'theia_wfp_lab.sys'
if (!(Test-Path -LiteralPath $driver -PathType Leaf)) { throw 'Expected .sys not produced' }
Invoke-Checked $cl @('/nologo','/W4','/O2','/DUNICODE','/D_UNICODE', (Join-Path $root 'theia_bfe_lab.c'), "/Fo$destination\theia_bfe_lab.obj", "/Fe$destination\theia_bfe_lab.exe", '/link', 'fwpuclnt.lib','rpcrt4.lib')
if ($CertificateThumbprint -or $VerifyKernelSignature) {
    $sign = (Get-Command signtool.exe -ErrorAction Stop).Source
    if ($CertificateThumbprint) {
        if ($CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid certificate thumbprint' }
        # The certificate/key must already exist in the authorized store.
        # This is local signing, NOT Microsoft attestation/WHQL signing.
        Invoke-Checked $sign @('sign','/sha1',$CertificateThumbprint,'/fd','SHA256',$driver)
    }
    Invoke-Checked $sign @('verify','/kp','/v',$driver)
} else {
    Write-Warning 'Unsigned build only. Not eligible for installation or release.'
}
Get-FileHash -Algorithm SHA256 -LiteralPath $driver,(Join-Path $destination 'theia_bfe_lab.exe') |
    Select-Object Algorithm,Hash,Path | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath (Join-Path $destination 'hashes.json')
