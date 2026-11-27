# Helpers for exact pinned, selective extraction of upstream artifacts.
function Open-ApprovedArchive([string]$Path,[string]$Expected) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -lt 1 -or $file.Length -gt 67108864) { throw 'Invalid archive.' }
    $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $digest=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } finally { $sha.Dispose() }
        if ($digest -ne $Expected) { throw 'Archive SHA256 mismatch.' }
        $stream.Position=0
        Add-Type -AssemblyName System.IO.Compression
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        if ($zip.Entries.Count -gt 4096) { $zip.Dispose(); throw 'Archive entry limit exceeded.' }
        return [pscustomobject]@{Stream=$stream;Zip=$zip}
    } catch { $stream.Dispose(); throw }
}
function Copy-UniqueEntry([IO.Compression.ZipArchive]$Zip,[string]$Suffix,[string]$Destination,[long]$Maximum,[switch]$RootOnly) {
    $matches=@()
    foreach ($entry in $Zip.Entries) {
        $name=$entry.FullName
        # Reject malformed names globally rather than trusting extraction
        # behavior on Windows. Do not materialize any archive path.
        if ($name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or
            ($name.Split('/') -contains '..') -or ($name.Split('/') -contains '.')) { throw 'Unsafe archive entry.' }
        $parts=$name.Split('/')
        $relative=$name
        if ($parts.Length -gt 1 -and $parts[0] -match '^WinDivert-2\.2\.2(?:-[ABC])?$') {
            $relative=($parts[1..($parts.Length-1)] -join '/')
        }
        if ($relative -ieq $Suffix -or ($RootOnly -and $relative -ieq "$Suffix.txt")) { $matches+= $entry }
    }
    if ($matches.Count -ne 1) { throw "Expected one official entry: $Suffix" }
    $entry=$matches[0]
    if ($entry.Length -lt 1 -or $entry.Length -gt $Maximum) { throw 'Entry length outside bounds.' }
    $input=$entry.Open()
    try {
        $output=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $buffer=[byte[]]::new(65536)
            $count=0L
            while (($n=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                $count+=$n
                if ($count -gt $entry.Length -or $count -gt $Maximum) { throw 'Entry exceeded length.' }
                $output.Write($buffer,0,$n)
            }
            if ($count -ne $entry.Length) { throw 'Truncated entry.' }
            $output.Flush($true)
        } finally { $output.Dispose() }
    } finally { $input.Dispose() }
}
