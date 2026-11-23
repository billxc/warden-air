param(
  [switch]$Local
)

$ErrorActionPreference = "Stop"

$HostName = "io.github.billxc.warden_air"
$ExtensionId = "nphekoiaefcbmdmoknadaohgnloneeaj"
$RawBase = if ($env:WARDEN_AIR_RAW_BASE) { $env:WARDEN_AIR_RAW_BASE } else { "https://raw.githubusercontent.com/billxc/warden-air/main" }
$AppDir = Join-Path $env:LOCALAPPDATA "warden-air"

if ($Local -and $PSScriptRoot) {
  $RepoRoot = Split-Path -Parent $PSScriptRoot
  $HostDir = Join-Path $RepoRoot "host"
} else {
  $HostDir = Join-Path $AppDir "host"
  New-Item -ItemType Directory -Force -Path $HostDir | Out-Null

  Write-Host "Downloading Warden Air host from GitHub..."
  foreach ($File in @("agent.mjs", "host.mjs", "paths.mjs", "vault.mjs", "run-host.cmd")) {
    $OutFile = Join-Path $HostDir $File
    Invoke-WebRequest -UseBasicParsing -Uri "$RawBase/host/$File" -OutFile $OutFile
  }
  Write-Host "Installed host files to: $HostDir"
}

$HostCmd = Join-Path $HostDir "run-host.cmd"
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
$ManifestPath = Join-Path $AppDir "$HostName.json"

$ManifestObj = [ordered]@{
  name = $HostName
  description = "Warden Air native messaging host"
  path = $HostCmd
  type = "stdio"
  allowed_origins = @("chrome-extension://$ExtensionId/")
}
$ManifestObj | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path $ManifestPath

$RegistryTargets = @(
  "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
  "HKCU:\Software\Chromium\NativeMessagingHosts\$HostName",
  "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName",
  "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$HostName",
  "HKCU:\Software\Vivaldi\NativeMessagingHosts\$HostName"
)

foreach ($RegKey in $RegistryTargets) {
  New-Item -Path $RegKey -Force | Out-Null
  Set-ItemProperty -Path $RegKey -Name "(Default)" -Value $ManifestPath
  Write-Host "Registered: $RegKey -> $ManifestPath"
}

$BwData = Join-Path $env:APPDATA "Bitwarden\data.json"
if (Test-Path $BwData) {
  if (-not (Select-String -Path $BwData -Pattern '"global_autofillSettings_enableDuckDuckGoBrowserIntegration":\s*true' -Quiet)) {
    Write-Host "Tip: To enable password saving on Windows, quit Bitwarden Desktop and set `"global_autofillSettings_enableDuckDuckGoBrowserIntegration`": true in $BwData."
  }
}

Write-Host "Done."
