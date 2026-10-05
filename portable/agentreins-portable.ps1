param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = (Get-Command py -ErrorAction SilentlyContinue)
if (-not $python) { $python = (Get-Command python -ErrorAction SilentlyContinue) }
if (-not $python) { throw 'Python 3.9 or newer is required. Install it from python.org or the Microsoft Store.' }
if ($python.Name -eq 'py.exe') {
    & $python.Source -3 (Join-Path $PSScriptRoot 'agentreins_portable.py') @Arguments
} else {
    & $python.Source (Join-Path $PSScriptRoot 'agentreins_portable.py') @Arguments
}
exit $LASTEXITCODE
