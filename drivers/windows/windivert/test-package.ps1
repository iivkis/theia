$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'package.ps1')
Add-Type -AssemblyName System.IO.Compression
$dir=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
function Reject([scriptblock]$Action) {
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    if (!$failed) { throw 'Invalid input accepted.' }
}
function Fixture([string]$Name,[string[]]$Entries) {
    $path=Join-Path $dir $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew)
    try {
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach ($name in $Entries) {
                $entry=$zip.CreateEntry($name)
                $item=$entry.Open()
                try { $item.WriteByte(42) } finally { $item.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
    return $path
}
try {
    $zip=Fixture 'valid.zip' @('WinDivert-2.2.2-A/x64/WinDivert.dll','WinDivert-2.2.2-A/LICENSE')
    $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    Reject { Open-ApprovedArchive $zip ('0'*64) }
    $archive=Open-ApprovedArchive $zip $hash
    try {
        $dest=Join-Path $dir 'dll'
        Copy-UniqueEntry $archive.Zip 'x64/WinDivert.dll' $dest 1024
        if ([IO.File]::ReadAllBytes($dest)[0] -ne 42) { throw 'Wrong entry.' }
        Reject { Copy-UniqueEntry $archive.Zip 'x64/WinDivert.dll' $dest 1024 }
        Reject { Copy-UniqueEntry $archive.Zip 'x64/WinDivert64.sys' (Join-Path $dir 'missing') 1024 }
        Reject { Copy-UniqueEntry $archive.Zip 'x64/WinDivert.dll' (Join-Path $dir 'large') 0 }
    } finally { $archive.Zip.Dispose(); $archive.Stream.Dispose() }
    foreach ($case in @(
        @{Name='duplicate.zip';Entries=@('x64/WinDivert.dll','WinDivert-2.2.2-A/x64/WinDivert.dll')},
        @{Name='traversal.zip';Entries=@('x64/WinDivert.dll','../evil')},
        @{Name='wrong-version.zip';Entries=@('WinDivert-2.2.1-A/x64/WinDivert.dll')}
    )) {
        $zip=Fixture $case.Name $case.Entries
        $archive=Open-ApprovedArchive $zip (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        try { Reject { Copy-UniqueEntry $archive.Zip 'x64/WinDivert.dll' (Join-Path $dir 'bad') 1024 } }
        finally { $archive.Zip.Dispose(); $archive.Stream.Dispose() }
    }
    Write-Output 'WinDivert package fixture checks passed. No driver installed.'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
