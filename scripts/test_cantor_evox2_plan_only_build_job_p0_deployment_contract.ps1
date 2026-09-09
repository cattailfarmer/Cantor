[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $PackageRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$deploy = Join-Path $PSScriptRoot 'deploy_cantor_evox2_plan_only_build_job_p0.ps1'
$raw = Get-Content -LiteralPath $deploy -Raw
[void][scriptblock]::Create($raw)
foreach ($required in @(
    "`$remoteRoot = 'C:\AI\services\cantor-build-planner-d805681d'",
    "`$expectedSource='4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'",
    'cantor-evox2-plan-only-build-job.exe',
    'cantor-evox2-plan-only-build-job-verify.exe',
    'Get-ProtectedIdentities',
    'Get-ProviderIdentity',
    'compiler_processes=2',
    'verifier_processes=2',
    'verify_cantor_evox2_plan_only_build_job_p0_live_evidence.ps1',
    'merge-base --is-ancestor',
    'status --porcelain=v1',
    'ls-remote --exit-code',
    'persistent_process_count=$processCount',
    'physical_build_performed=$false',
    "powershell.exe -NoProfile -NonInteractive -OutputFormat Text -Command '[scriptblock]::Create([Console]::In.ReadToEnd()).Invoke()'"
)) { if (-not $raw.Contains($required)) { throw "deployment contract token missing: $required" } }
foreach ($forbidden in @('Invoke-Expression', 'Start-Process', 'schtasks', 'New-Service', 'Set-Service', 'netsh', 'reg.exe', 'winget', 'cargo install', 'rustup', 'http://', 'https://', 'EncodedCommand')) {
    if ($raw.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw "deployment contract contains forbidden token: $forbidden" }
}
$refused = $false
try { & $deploy -SshHost 'bad host' -PackageRoot $PackageRoot | Out-Null } catch { $refused = $true }
if (-not $refused) { throw 'unsafe SSH alias was admitted' }
$refused = $false
try { & $deploy -SshHost 'evo-x2' -PackageRoot $PackageRoot -LocalEvidenceRoot 'C:\outside-evidence' | Out-Null } catch { $refused = $true }
if (-not $refused) { throw 'outside local evidence path was admitted' }

[pscustomobject]@{profile='cantor-evox2-plan-only-build-job-deployment-contract-tests/0.1';status='passed';syntax='passed';required_tokens=15;forbidden_tokens=13;pre_network_refusals=2;stdin_script_transports=1;remote_calls=0} | ConvertTo-Json -Compress
