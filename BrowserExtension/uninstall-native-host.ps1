param(
    [string]$ManifestName = 'com.agentspec.agentreins.web'
)
$ErrorActionPreference = 'SilentlyContinue'
$manifest = Join-Path $env:LOCALAPPDATA 'AgentReins\native-host.json'
Remove-Item -LiteralPath $manifest -Force -ErrorAction SilentlyContinue
foreach ($keyRoot in @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
    'HKCU:\Software\Chromium\NativeMessagingHosts',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'
)) {
    Remove-Item -LiteralPath (Join-Path $keyRoot $ManifestName) -Recurse -Force -ErrorAction SilentlyContinue
}
$manifestDirectory = Split-Path -Parent $manifest
if (Test-Path -LiteralPath $manifestDirectory -PathType Container) {
    $remaining = Get-ChildItem -LiteralPath $manifestDirectory -Force -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item -LiteralPath $manifestDirectory -Force -ErrorAction SilentlyContinue
    }
}
