<#
Build a self-contained Windows GUI executable with PyInstaller.

The script intentionally builds on the host Windows Python so PyInstaller
produces a native PE executable. It does not cross-compile from Linux/macOS.
#>
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$OneDir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$buildVersion = if ($env:AGENTREINS_VERSION) { $env:AGENTREINS_VERSION.Trim().TrimStart('v', 'V') } else { '0.1.1' }
if ($buildVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "AGENTREINS_VERSION must be semantic version text (got '$buildVersion')"
}
$buildVersionDir = Join-Path $root 'build\agentreins-version'
$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $python) { throw 'Python 3.9 or newer is required. Install it from python.org.' }

function Invoke-Python([string[]]$PyArgs) {
    if ($python.Name -eq 'py.exe') {
        $launcherArgs = @('-3') + $PyArgs
        & $python.Source @launcherArgs
    } else {
        & $python.Source @PyArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "Python command failed with exit code $LASTEXITCODE" }
}

try { Invoke-Python @('-c', 'import PyInstaller; print(PyInstaller.__version__)') }
catch {
    Write-Host 'PyInstaller is not installed; installing it for the current user...'
    Invoke-Python @('-m', 'pip', 'install', '--user', '--upgrade', 'pyinstaller')
}

# Bundle the optional tray implementation in release builds. If installation
# is unavailable, the application still has a taskbar-minimize fallback.
try { Invoke-Python @('-c', 'import pystray, PIL') }
catch {
    Write-Host 'Optional tray dependencies not found; installing pystray and Pillow...'
    try { Invoke-Python @('-m', 'pip', 'install', '--user', '--upgrade', 'pystray', 'Pillow') }
    catch { Write-Warning 'Tray dependencies unavailable; continuing with taskbar fallback.' }
}

$spec = Join-Path $PSScriptRoot 'agentreins_desktop.spec'
$args = @('-m', 'PyInstaller', '--noconfirm', '--clean', $spec)
if ($Clean) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $root 'build'), (Join-Path $root 'dist')
}
New-Item -ItemType Directory -Force -Path $buildVersionDir | Out-Null
Set-Content -LiteralPath (Join-Path $buildVersionDir 'agentreins_build_version.py') -Value "VERSION = '$buildVersion'" -Encoding ascii
if ($OneDir) {
    # One-dir builds are useful for debugging startup failures and are
    # selected with a direct CLI rebuild instead of the one-file spec.
    $args = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'AgentReins', '--paths', $buildVersionDir,
        '--hidden-import', 'agent_adapters', '--hidden-import', 'update_checker',
        '--hidden-import', 'operations_runtime', '--hidden-import', 'operations_cli', '--hidden-import', 'turn_journal',
        '--hidden-import', 'evidence_projection', '--hidden-import', 'safety_features',
        '--hidden-import', 'provider_config', '--hidden-import', 'process_rules',
        (Join-Path $PSScriptRoot 'agentreins_desktop.py'))
}
Push-Location $root
try {
    Invoke-Python $args
} finally {
    Pop-Location
}

$output = if ($OneDir) { Join-Path $root 'dist\AgentReins\AgentReins.exe' } else { Join-Path $root 'dist\AgentReins.exe' }
if (-not (Test-Path $output)) {
    throw "Build completed but expected executable was not found at $output"
}
Write-Host "Built $output"

# Build the Native Messaging host separately. It intentionally has no console
# window and uses the same Python runtime as the desktop shell. The installer
# registers this executable with Chrome/Edge after copying it to {app}.
$nativeEntry = Join-Path $PSScriptRoot 'native_host.py'
Push-Location $root
try {
    Invoke-Python @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--name', 'AgentReinsNativeHost', '--console', $nativeEntry)
} finally {
    Pop-Location
}
$nativeOutput = Join-Path $root 'dist\AgentReinsNativeHost.exe'
if (-not (Test-Path $nativeOutput)) { throw "Native host build completed but expected executable was not found at $nativeOutput" }
Write-Host "Built $nativeOutput"
