[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$out=[IO.Path]::GetFullPath($OutputDirectory)
if (!(Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out | Out-Null }
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
if ($LASTEXITCODE -ne 0 -or !$vs) { throw 'MSVC not found.' }
$vc=Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$src=Join-Path $PSScriptRoot 'wfp-guard.cpp'
$exe=Join-Path $out 'theia-wfp-guard-lab.exe'
$obj=Join-Path $out 'wfp-guard.obj'
# Quote all SDK/build paths; this fixture never installs filters.
$cmd='call "'+$vc+'" && cl.exe /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE "'+$src+'" /Fo"'+$obj+'" /Fe"'+$exe+'"'
& cmd.exe /d /c $cmd
if ($LASTEXITCODE -ne 0) { throw 'WFP guard compile failed.' }
& $exe self-test
if ($LASTEXITCODE -ne 0) { throw 'WFP guard self-test failed.' }
Get-FileHash -LiteralPath $exe -Algorithm SHA256
