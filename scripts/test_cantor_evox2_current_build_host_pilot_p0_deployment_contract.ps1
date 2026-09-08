[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$deploy = Join-Path $PSScriptRoot 'deploy_cantor_evox2_current_build_host_pilot_p0.ps1'
$raw = Get-Content -LiteralPath $deploy -Raw
[void][scriptblock]::Create($raw)
foreach ($required in @(
    "`$remoteRoot = 'C:\AI\services\cantor-current-pilot-48479932'",
    "`$expectedSource='8e37e3e701d41d61328f89296ae77b8ea3707812'",
    'cantor-b1-production-broker-projection-evidence-verify.exe',
    "optional_query_status='skipped_incompatible'",
    'Get-ProtectedIdentities',
    'Get-ProviderIdentity',
    'persistent_process_count=0',
    'listener_delta=0',
    'configuration_changed=$false'
)) {
    if (-not $raw.Contains($required)) { throw "deployment contract token missing: $required" }
}
foreach ($forbidden in @('Invoke-Expression', 'Start-Process', 'schtasks', 'New-Service', 'Set-Service', 'netsh', 'reg.exe', 'winget', 'cargo install', 'rustup', 'http://', 'https://')) {
    if ($raw.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw "deployment contract contains forbidden token: $forbidden" }
}

$refused = $false
try { & $deploy -SshHost 'bad host' -PackageRoot $PackageRoot | Out-Null } catch { $refused = $true }
if (-not $refused) { throw 'unsafe SSH alias was admitted' }
$refused = $false
try { & $deploy -SshHost 'evo-x2' -PackageRoot $PackageRoot -LocalEvidenceRoot 'D:\CantorBuilds\outside-evidence' | Out-Null } catch { $refused = $true }
if (-not $refused) { throw 'outside local evidence path was admitted' }

[pscustomobject]@{
    profile = 'cantor-evox2-current-build-pilot-deployment-contract-tests/0.1'
    status = 'passed'
    syntax = 'passed'
    required_tokens = 9
    forbidden_tokens = 12
    pre_network_refusals = 2
    remote_calls = 0
} | ConvertTo-Json -Compress
