# Tests normalization and rejection, not signing or driver load.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'attestation-common.ps1')
$dir=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
function Put16([byte[]]$b,[int]$o,[uint16]$v) { [Array]::Copy([BitConverter]::GetBytes($v),0,$b,$o,2) }
function Put32([byte[]]$b,[int]$o,[uint32]$v) { [Array]::Copy([BitConverter]::GetBytes($v),0,$b,$o,4) }
function Expect-Rejection([scriptblock]$check) {
    $rejected=$false
    try { & $check | Out-Null } catch { $rejected=$true }
    if (!$rejected) { throw 'Unexpected acceptance of invalid attestation input.' }
}
try {
    # Deliberately non-executable synthetic header fixture. The fake
    # certificate table below is only a parser fixture, NOT a signature.
    $u=[byte[]]::new(1021)
    Put16 $u 0 0x5a4d
    Put32 $u 60 128
    Put32 $u 128 0x4550
    Put16 $u 132 0x8664
    Put16 $u 134 1
    Put16 $u 148 240
    Put16 $u 152 0x20b
    Put32 $u 212 512
    Put16 $u 220 1
    Put32 $u 260 16
    Put32 $u 408 256
    Put32 $u 412 512
    $u[600]=123
    $original=Join-Path $dir 'original.sys'
    [IO.File]::WriteAllBytes($original,$u)
    $identity=Get-TheiaImageIdentity $original $false
    $s=[byte[]]::new(1040)
    [Array]::Copy($u,$s,$u.Length)
    Put32 $s 216 0x12345678
    Put32 $s 296 1024
    Put32 $s 300 16
    Put32 $s 1024 12
    Put16 $s 1028 0x200
    Put16 $s 1030 2
    $signed=Join-Path $dir 'fixture.sys'
    [IO.File]::WriteAllBytes($signed,$s)
    if ((Get-TheiaImageIdentity $signed $true) -ne $identity) { throw 'Signature-only normalization mismatch.' }
    Expect-Rejection { Get-TheiaImageIdentity $original $true }
    Expect-Rejection { Get-TheiaImageIdentity $signed $false }
    $s[600]=124
    [IO.File]::WriteAllBytes($signed,$s)
    if ((Get-TheiaImageIdentity $signed $true) -eq $identity) { throw 'Modified executable accepted.' }
    $s[600]=123
    $s[1023]=1
    [IO.File]::WriteAllBytes($signed,$s)
    if ((Get-TheiaImageIdentity $signed $true) -eq $identity) { throw 'Nonzero padding accepted.' }
    $s[1023]=0
    Put32 $s 300 8
    [IO.File]::WriteAllBytes($signed,$s)
    Expect-Rejection { Get-TheiaImageIdentity $signed $true }
    Put32 $s 300 16
    foreach ($index in @(1028,1030,1039)) {
        $changed=[byte[]]$s.Clone()
        $changed[$index]=$changed[$index] -bxor 1
        [IO.File]::WriteAllBytes($signed,$changed)
        Expect-Rejection { Get-TheiaImageIdentity $signed $true }
    }
    $changed=[byte[]]$s.Clone()
    Put32 $changed 412 1000
    [IO.File]::WriteAllBytes($signed,$changed)
    Expect-Rejection { Get-TheiaImageIdentity $signed $true }
    Put16 $s 132 0x14c
    [IO.File]::WriteAllBytes($signed,$s)
    Expect-Rejection { Get-TheiaImageIdentity $signed $true }
    $json=Join-Path $dir 'manifest.json'
    '{"Version":1}' | Set-Content -LiteralPath $json -Encoding utf8
    $hash=(Get-FileHash -LiteralPath $json -Algorithm SHA256).Hash
    if ((Read-TheiaPinnedJson $json $hash).Version -ne 1) { throw 'Manifest roundtrip failed.' }
    '{"Version":2}' | Set-Content -LiteralPath $json -Encoding utf8
    Expect-Rejection { Read-TheiaPinnedJson $json $hash }
    Write-Output 'Attestation image and manifest negative tests passed; no driver signed or installed.'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
