[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$Output = ""
)
$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "AgentReinsEtw.csproj"
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET 8 SDK is required to build AgentReinsEtwHelper.exe."
}
if (-not $Output) { $Output = Join-Path (Split-Path -Parent $PSScriptRoot) "..\dist\etw-helper" }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force -Path $Output | Out-Null
& dotnet publish $project -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $Output
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }
$binary = Join-Path $Output "AgentReinsEtwHelper.exe"
if (-not (Test-Path -LiteralPath $binary)) { throw "Expected helper was not produced: $binary" }

# Reuse the release signing inputs when the parent workflow has configured
# Authenticode. Local builds remain unsigned and do not require a certificate.
if ($env:AGENTREINS_WINDOWS_SIGN_CERT) {
    if (-not $env:AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD) {
        throw "AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD is required when signing ETW helper."
    }
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        if (Test-Path -LiteralPath $kits) {
            $signtool = Get-ChildItem -Path (Join-Path $kits '*\x64\signtool.exe') -File -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | Select-Object -First 1
        }
    }
    if (-not $signtool) { throw "signtool.exe not found; cannot sign ETW helper." }
    $toolPath = if ($signtool.Source) { $signtool.Source } else { $signtool.FullName }
    $timestamp = if ($env:AGENTREINS_WINDOWS_TIMESTAMP_URL) { $env:AGENTREINS_WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
    & $toolPath sign /q /fd SHA256 /f $env:AGENTREINS_WINDOWS_SIGN_CERT /p $env:AGENTREINS_WINDOWS_SIGN_CERT_PASSWORD /tr $timestamp /td SHA256 /d 'AgentReins ETW Helper' $binary
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for ETW helper ($LASTEXITCODE)" }
    & $toolPath verify /pa /q $binary
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for ETW helper ($LASTEXITCODE)" }
}
Write-Host "Built $binary"
