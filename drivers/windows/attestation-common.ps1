# Shared strict file and PE checks for offline attestation exchange.
function Get-TheiaRegularFile([string]$Path,[long]$Maximum=16777216) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -lt 1 -or $file.Length -gt $Maximum) { throw 'Invalid or oversized input file.' }
    return $file
}
function Assert-TheiaHash([string]$Path,[string]$Expected) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$' -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Expected) {
        throw "SHA256 mismatch: $([IO.Path]::GetFileName($Path))"
    }
}
function Read-TheiaPinnedJson([string]$Path,[string]$Expected) {
    $file=Get-TheiaRegularFile $Path 16384
    # One immutable byte snapshot for hashing and parsing.
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','') } finally { $sha.Dispose() }
    if ($actual -ne $Expected) { throw 'Pinned manifest digest mismatch.' }
    return ([Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xfeff) | ConvertFrom-Json)
}
function Get-TheiaImageIdentity([string]$Path,[bool]$RequireCertificate) {
    $file=Get-TheiaRegularFile $Path
    $b=[IO.File]::ReadAllBytes($file.FullName)
    if ($b.Length -lt 512 -or [BitConverter]::ToUInt16($b,0) -ne 0x5a4d) { throw 'Invalid DOS header.' }
    $pe=[long][BitConverter]::ToUInt32($b,60)
    if ($pe -lt 64 -or $pe+24+240 -gt $b.Length -or
        [BitConverter]::ToUInt32($b,[int]$pe) -ne 0x4550 -or
        [BitConverter]::ToUInt16($b,[int]($pe+4)) -ne 0x8664) { throw 'Expected AMD64 PE image.' }
    $opt=[int]($pe+24)
    $optionalSize=[BitConverter]::ToUInt16($b,[int]($pe+20))
    $sections=[BitConverter]::ToUInt16($b,[int]($pe+6))
    $sectionStart=$opt+$optionalSize
    if ($optionalSize -lt 240 -or $sections -lt 1 -or $sections -gt 96 -or
        $sectionStart+40*$sections -gt $b.Length -or
        [BitConverter]::ToUInt16($b,$opt) -ne 0x20b -or
        [BitConverter]::ToUInt16($b,$opt+68) -ne 1 -or
        [BitConverter]::ToUInt32($b,$opt+108) -lt 5) { throw 'Expected complete PE32+ native driver.' }
    $security=$opt+112+4*8
    $offset=[long][BitConverter]::ToUInt32($b,$security)
    $size=[long][BitConverter]::ToUInt32($b,$security+4)
    if (($offset -eq 0) -ne ($size -eq 0)) { throw 'Malformed certificate table.' }
    if ($RequireCertificate) {
        if ($offset -lt $opt+$optionalSize -or $size -lt 8 -or $offset%8 -ne 0 -or
            $offset+$size -ne $b.Length) { throw 'Expected embedded certificate table at EOF.' }
        $end=[int]$offset
        # The certificate table is excluded from image identity, never
        # from SignTool verification. Validate its framing before hashing.
        $cursor=$offset
        while ($cursor -lt $b.Length) {
            if ($cursor+8 -gt $b.Length) { throw 'Truncated WIN_CERTIFICATE.' }
            $length=[long][BitConverter]::ToUInt32($b,[int]$cursor)
            $aligned=[long](8*[Math]::Ceiling($length/8.0))
            if ($length -le 8 -or $cursor+$aligned -gt $b.Length -or
                [BitConverter]::ToUInt16($b,[int]($cursor+4)) -ne 0x200 -or
                [BitConverter]::ToUInt16($b,[int]($cursor+6)) -ne 2) { throw 'Invalid WIN_CERTIFICATE.' }
            for ($i=$cursor+$length;$i -lt $cursor+$aligned;++$i) {
                if ($b[$i] -ne 0) { throw 'Nonzero certificate alignment padding.' }
            }
            $cursor+=$aligned
        }
    } else {
        if ($offset -ne 0) { throw 'Submission source must be unsigned.' }
        $end=$b.Length
    }
    $headers=[long][BitConverter]::ToUInt32($b,$opt+60)
    if ($headers -lt $sectionStart+40*$sections -or $headers -gt $end) { throw 'Invalid PE headers size.' }
    for ($i=0;$i -lt $sections;++$i) {
        $section=$sectionStart+40*$i
        $rawSize=[long][BitConverter]::ToUInt32($b,$section+16)
        $rawOffset=[long][BitConverter]::ToUInt32($b,$section+20)
        if ($rawSize -ne 0 -and ($rawOffset -lt $headers -or $rawOffset+$rawSize -gt $end)) {
            throw 'PE section extends beyond executable image.'
        }
    }
    # Intentionally stronger than a section-only comparison: only the
    # checksum, security directory, alignment padding and certificate table
    # may differ. Reject other modifications even if signature is valid.
    $normalized=[byte[]]::new([int](8*[Math]::Ceiling($end/8.0)))
    [Array]::Copy($b,0,$normalized,0,$end)
    [Array]::Clear($normalized,$opt+64,4)
    [Array]::Clear($normalized,$security,8)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($normalized)).Replace('-','') } finally { $sha.Dispose() }
}
function Assert-TheiaMicrosoftKernelSignature([string]$Path) {
    $signtool=(Get-Command signtool.exe -ErrorAction Stop).Source
    & $signtool verify /kp /v $Path | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Windows kernel-mode signing policy verification failed.' }
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignatureType -ne 'Authenticode' -or
        $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne 'Microsoft Windows Hardware Compatibility Publisher') {
        throw 'Expected a valid embedded Microsoft hardware publisher signature.'
    }
}

# Read the currently enforced kernel code-integrity state. Never change
# BCD, Secure Boot, HVCI or the machine certificate trust configuration.
function Assert-TheiaCodeIntegrity {
    if (!('TheiaInstallCodeIntegrity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TheiaInstallCodeIntegrity {
    [StructLayout(LayoutKind.Sequential)]
    struct Information { public uint Length; public uint Options; }
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int kind, ref Information value, uint length, out uint returned);
    public static uint Read() {
        var info = new Information { Length = 8 };
        uint returned;
        int status = NtQuerySystemInformation(103, ref info, 8, out returned);
        if (status != 0 || info.Length != 8 || returned != 8)
            throw new InvalidOperationException("Code integrity state unavailable");
        return info.Options;
    }
}
'@
    }
    $options=[TheiaInstallCodeIntegrity]::Read()
    if (($options -band 1) -eq 0 -or ($options -band 0xe2) -ne 0) {
        throw 'Kernel code integrity must be enabled without test/preproduction/debug signing allowances.'
    }
    return $options
}
