param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl,
    [switch]$VerifyKernelSignature
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$git = (Get-Command git.exe -ErrorAction Stop).Source
$sourceSha = (& $git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceSha -notmatch '^[0-9a-f]{40}$') { throw 'Exact source revision unavailable.' }
$trackedChanges = & $git -C $root status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0 -or $trackedChanges) { throw 'Build requires an unchanged tracked source tree.' }
if ($TimestampUrl -and (!$CertificateThumbprint -or $TimestampUrl -notmatch '^https://[^\s]+$')) {
    throw 'Timestamp URL requires an explicit signing certificate and HTTPS.'
}
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
$pdb = Join-Path $destination 'theia_wfp_lab.pdb'
if (!(Test-Path -LiteralPath $pdb -PathType Leaf)) { throw 'Expected WDK linker PDB not produced' }
$controller = Join-Path $destination 'theia_bfe_lab.exe'
Invoke-Checked $cl @('/nologo','/W4','/O2','/DUNICODE','/D_UNICODE', (Join-Path $root 'theia_bfe_lab.c'), "/Fo$destination\theia_bfe_lab.obj", "/Fe$controller", '/link', 'fwpuclnt.lib','rpcrt4.lib')
$kernelVerified = $false
if ($CertificateThumbprint -or $VerifyKernelSignature) {
    $sign = (Get-Command signtool.exe -ErrorAction Stop).Source
    if ($CertificateThumbprint) {
        if ($CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid certificate thumbprint' }
        # The certificate/key must already exist in the authorized store.
        # This is local signing, NOT Microsoft attestation/WHQL signing.
        $signArgs = @('sign','/sha1',$CertificateThumbprint,'/fd','SHA256')
        if ($TimestampUrl) { $signArgs += @('/tr',$TimestampUrl,'/td','SHA256') }
        $signArgs += $driver
        Invoke-Checked $sign $signArgs
    }
    Invoke-Checked $sign @('verify','/kp','/v',$driver)
    $kernelVerified = $true
} else {
    Write-Warning 'Unsigned build only. Not eligible for installation or release.'
}
$finalSha = (& $git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $finalSha -ne $sourceSha) { throw 'Source revision changed during build.' }
$trackedChanges = & $git -C $root status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0 -or $trackedChanges) { throw 'Tracked source changed during build.' }
Get-FileHash -Algorithm SHA256 -LiteralPath $driver,$controller,$pdb |
    Select-Object Algorithm,Hash,Path | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath (Join-Path $destination 'hashes.json')
[pscustomobject]@{
    Version = 1
    SourceSha = $sourceSha
    DriverSha256 = (Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash
    ControllerSha256 = (Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash
    PdbSha256 = (Get-FileHash -LiteralPath $pdb -Algorithm SHA256).Hash
    KernelSignatureVerified = $kernelVerified
    MicrosoftKernelSignatureVerified = $false
    MicrosoftAttestationVerified = $false
    PhysicalAcceptanceVerified = $false
    CaptureReady = $false
} | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath (Join-Path $destination 'build-evidence.json')
