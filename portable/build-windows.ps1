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

$spec = Join-Path $PSScriptRoot 'agentreins_desktop.spec'
$args = @('-m', 'PyInstaller', '--noconfirm', '--clean', $spec)
if ($Clean) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $root 'build'), (Join-Path $root 'dist')
}
if ($OneDir) {
    # One-dir builds are useful for debugging startup failures and are
    # selected with a direct CLI rebuild instead of the one-file spec.
    $args = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'AgentReins', (Join-Path $PSScriptRoot 'agentreins_desktop.py'))
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
