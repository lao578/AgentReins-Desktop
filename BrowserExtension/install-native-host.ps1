param(
    [string]$HostBinary = (Join-Path $PSScriptRoot '..\AgentReinsNativeHost.exe')
)

$ErrorActionPreference = 'Stop'
$HostBinary = [IO.Path]::GetFullPath($HostBinary)
if (-not (Test-Path -LiteralPath $HostBinary -PathType Leaf)) {
    throw "AgentReinsNativeHost.exe was not found at $HostBinary"
}

$manifestDirectory = Join-Path $env:LOCALAPPDATA 'AgentReins'
$manifestPath = Join-Path $manifestDirectory 'native-host.json'
New-Item -ItemType Directory -Force -Path $manifestDirectory | Out-Null

$manifest = [ordered]@{
    name = 'com.agentspec.agentreins.web'
    description = 'AgentReins local web-agent evidence bridge'
    path = $HostBinary
    type = 'stdio'
    allowed_origins = @('chrome-extension://hcmoeaheokpfbbggdmkdeaiokakiampk/')
} | ConvertTo-Json -Depth 4
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($manifestPath, $manifest, $utf8NoBom)

foreach ($browser in @(
    @{ Name = 'Google Chrome'; Key = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts' },
    @{ Name = 'Chromium'; Key = 'HKCU:\Software\Chromium\NativeMessagingHosts' },
    @{ Name = 'Microsoft Edge'; Key = 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts' }
)) {
    $key = Join-Path $browser.Key 'com.agentspec.agentreins.web'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name '(default)' -Value $manifestPath -PropertyType String -Force | Out-Null
    Write-Output "Installed AgentReins native host for $($browser.Name): $manifestPath"
}
