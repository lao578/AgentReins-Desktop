<##
Build the Windows desktop executable and an Inno Setup installer.

Requirements: Windows, Python 3.9+, and Inno Setup 6 (ISCC.exe). The script
does not download tools implicitly; install Inno Setup from its official
installer or set -InnoCompiler to a custom ISCC.exe path.
##>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:AGENTREINS_VERSION) { $env:AGENTREINS_VERSION } else { '0.1.0' }),
    [string]$InnoCompiler = '',
    [switch]$SkipExecutable
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

if (-not $SkipExecutable) {
    & (Join-Path $root 'portable\build-windows.ps1') -Clean
    if ($LASTEXITCODE -ne 0) { throw "Windows executable build failed ($LASTEXITCODE)" }
}
$exe = Join-Path $root 'dist\AgentReins.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing executable: $exe" }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$exe.sha256" -Value "$hash *AgentReins.exe" -Encoding ascii
$nativeHost = Join-Path $root 'dist\AgentReinsNativeHost.exe'
if (-not (Test-Path -LiteralPath $nativeHost -PathType Leaf)) { throw "Missing Native Messaging host: $nativeHost" }

if (-not $InnoCompiler) {
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { $InnoCompiler = $command.Source }
    else {
        $candidates = @(
            "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path $_) }
        if ($candidates) { $InnoCompiler = $candidates[0] }
    }
}
if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw 'Inno Setup 6 ISCC.exe was not found. Install Inno Setup or pass -InnoCompiler PATH.'
}

$env:AGENTREINS_VERSION = $Version
& $InnoCompiler "/DAGENTREINS_VERSION=$Version" (Join-Path $PSScriptRoot 'AgentReins.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($LASTEXITCODE)" }
$installer = Join-Path $root "dist\installer\AgentReins-$Version-Windows-x64-Setup.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Installer not found: $installer" }
$installerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$installer.sha256" -Value "$installerHash  $(Split-Path $installer -Leaf)" -Encoding ascii
Write-Host "Built $installer"
