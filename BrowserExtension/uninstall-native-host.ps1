param(
    [string]$ManifestName = 'com.agentspec.agentreins.web'
)
$ErrorActionPreference = 'SilentlyContinue'
$manifest = Join-Path $env:LOCALAPPDATA 'AgentReins\native-host.json'
Remove-Item -LiteralPath $manifest -Force -ErrorAction SilentlyContinue
foreach ($keyRoot in @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'
)) {
    Remove-Item -LiteralPath (Join-Path $keyRoot $ManifestName) -Recurse -Force -ErrorAction SilentlyContinue
}
