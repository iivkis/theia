# The evidence file is an independently pinned build record, not a
# substitute for the actual kernel signature check. Do not execute it.
function Read-TheiaBuildEvidence {
    param(
        [string]$Path,
        [string]$ExpectedEvidenceSha256,
        [string]$ExpectedSourceSha,
        [string]$ExpectedDriverSha256
    )
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -lt 2 -or $item.Length -gt 8192) {
        throw 'Invalid build evidence file.'
    }
    $stream = [IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $actual = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')
        } finally { $sha.Dispose() }
        if ($actual -ne $ExpectedEvidenceSha256.ToUpperInvariant()) { throw 'Build evidence digest mismatch.' }
        $stream.Position = 0
        $reader = [IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,1024,$true)
        try { $evidence = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    if ($evidence.Version -ne 1 -or $evidence.SourceSha -cne $ExpectedSourceSha.ToLowerInvariant() -or
        $evidence.DriverSha256 -ne $ExpectedDriverSha256.ToUpperInvariant() -or
        $evidence.ControllerSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        $evidence.KernelSignatureVerified -isnot [bool] -or !$evidence.KernelSignatureVerified -or
        $evidence.MicrosoftKernelSignatureVerified -isnot [bool] -or !$evidence.MicrosoftKernelSignatureVerified -or
        $evidence.CaptureReady -isnot [bool] -or $evidence.CaptureReady) {
        throw 'Exact signed-build evidence is missing or inconsistent.'
    }
    return $evidence
}
