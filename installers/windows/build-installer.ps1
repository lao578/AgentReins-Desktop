<##
Build the Windows desktop executable and an Inno Setup installer.

Requirements: Windows, Python 3.9+, and Inno Setup 6 (ISCC.exe). The script
does not download tools implicitly; install Inno Setup from its official
installer or set -InnoCompiler to a custom ISCC.exe path.
##>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:AGENTREINS_VERSION) { $env:AGENTREINS_VERSION } else { '0.1.1' }),
    [string]$InnoCompiler = '',
    [switch]$SkipExecutable,
    # Optional Authenticode signing.  The normal developer build stays
    # unsigned; CI supplies these values only when protected secrets exist.
    [string]$SigningCertificate = $(if ($env:AGENTREINS_WINDOWS_SIGN_CERT) { $env:AGENTREINS_WINDOWS_SIGN_CERT } else { '' }),
    [string]$TimestampUrl = $(if ($env:AGENTREINS_WINDOWS_TIMESTAMP_URL) { $env:AGENTREINS_WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' })
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$env:AGENTREINS_VERSION = $Version

if (-not $SkipExecutable) {
    & (Join-Path $root 'portable\build-windows.ps1') -Clean
    if ($LASTEXITCODE -ne 0) { throw "Windows executable build failed ($LASTEXITCODE)" }
}
$exe = Join-Path $root 'dist\AgentReins.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing executable: $exe" }
$nativeHost = Join-Path $root 'dist\AgentReinsNativeHost.exe'
if (-not (Test-Path -LiteralPath $nativeHost -PathType Leaf)) { throw "Missing Native Messaging host: $nativeHost" }

# ETW is intentionally optional: when the .NET 8 SDK is available, include
# the self-contained elevated helper; otherwise the installer remains fully
# functional with the unprivileged polling watcher.
$etwBuild = Join-Path $root 'windows\AgentReinsEtw\build.ps1'
if ((Test-Path -LiteralPath $etwBuild) -and (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    & $etwBuild
    if ($LASTEXITCODE -ne 0) { throw "Optional ETW helper build failed ($LASTEXITCODE)" }
} else {
    Write-Host 'Optional ETW helper not built (install .NET 8 SDK to include it).'
}
$etwHelper = Join-Path $root 'dist\etw-helper\AgentReinsEtwHelper.exe'

function Resolve-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kits) {
        $candidate = Get-ChildItem -Path (Join-Path $kits '*\x64\signtool.exe') -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Sign-Artifact([string]$Path, [string]$Tool) {
    if (-not $env:AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD) {
        throw 'AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD is required when Windows signing is enabled.'
    }
    & $Tool sign /q /fd SHA256 /f $SigningCertificate /p $env:AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD /tr $TimestampUrl /td SHA256 /d 'AgentReins' $Path
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for $Path ($LASTEXITCODE)" }
    & $Tool verify /pa /q $Path
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for $Path ($LASTEXITCODE)" }
}

$signTool = $null
if ($SigningCertificate) {
    if (-not (Test-Path -LiteralPath $SigningCertificate -PathType Leaf)) { throw "Signing certificate not found: $SigningCertificate" }
    $signTool = Resolve-SignTool
    if (-not $signTool) { throw 'Windows signing requested but signtool.exe was not found.' }
    Write-Host "Signing Windows binaries with Authenticode certificate: $SigningCertificate"
    Sign-Artifact $exe $signTool
    Sign-Artifact $nativeHost $signTool
    if (Test-Path -LiteralPath $etwHelper -PathType Leaf) { Sign-Artifact $etwHelper $signTool }
}

# Hash after signing so sidecars describe the exact bytes distributed.
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$exe.sha256" -Value "$hash  AgentReins.exe" -Encoding ascii

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

& $InnoCompiler "/DAGENTREINS_VERSION=$Version" (Join-Path $PSScriptRoot 'AgentReins.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($LASTEXITCODE)" }
$installer = Join-Path $root "dist\installer\AgentReins-$Version-Windows-x64-Setup.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Installer not found: $installer" }
if ($signTool) { Sign-Artifact $installer $signTool }
$installerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$installer.sha256" -Value "$installerHash  $(Split-Path $installer -Leaf)" -Encoding ascii
Write-Host "Built $installer"
