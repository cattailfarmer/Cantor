[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $RequireExactGates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_runner_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-scratch-build-remote-preflight-runner-evidence/0.1' -or $manifest.manifest_uuid -cne '4345ae52-665c-4b7d-95b7-3dfefe565e44' -or $manifest.source_uuid -cne '476bf430-ae3a-4f69-8116-b5461803604b' -or $manifest.design_uuid -cne '8b60c955-8358-481c-aa57-0901a925fd69' -or $manifest.predecessor_bookend -cne 'b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0' -or $manifest.producer_implementation_commit -cne '606588a6dd542b31816d116abf909f50d0881937' -or $manifest.producer_bookend_commit -cne 'b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0') { throw 'runner evidence identity differs' }
if (@($manifest.artifacts).Count -ne 26) { throw 'runner evidence artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)\.\.(/|$)') { throw 'runner artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'runner artifact duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "runner artifact identity differs: $relative" }
}
$runner = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\evox2_scratch_build_remote_preflight_runner.rs') -Raw
$containment = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\self_work_update_broker_b1_cdrive_windows_containment.rs') -Raw
foreach ($required in @('Evox2ScratchBuildRemotePreflightSingleUsePermit','run_evox2_scratch_build_remote_preflight_once','runner_implementation_only_live_invocation_not_authorized','single_use_permit_consumed_after_published_contract_replay','validate_evox2_scratch_build_remote_preflight_run','runner_receipt_sha256')) { if ($runner -cnotmatch [regex]::Escape($required)) { throw "runner surface differs: $required" } }
if ([regex]::Matches($runner, '(?m)^\s*#\[test\]\s*$').Count -ne 10) { throw 'runner focused test count differs' }
if ($runner -cmatch '(?m)^pub\s+fn\s+[^\r\n]*permit' -or $runner -cmatch '(?m)^\s*impl\s+Evox2ScratchBuildRemotePreflightSingleUsePermit') { throw 'runner production permit constructor is present' }
if (Test-Path -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\bin\cantor-evox2-scratch-build-remote-preflight-runner.rs')) { throw 'runner invocation binary is present' }
if ($runner.Contains('Command::new') -or $runner.Contains('CreateProcessW(')) { throw 'runner introduced a second process primitive' }
if ($containment -cnotmatch 'run_evox2_scratch_build_remote_preflight_contained_process' -or $containment -cnotmatch 'AssignProcessToJobObject' -or $containment -cnotmatch 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE') { throw 'runner containment reuse differs' }
$expected = @{ artifact_count = 26; focused_tests = 10; argument_atoms = 19; timeout_ms = 30000; stream_limit_bytes = 65536; maximum_active_processes = 1; maximum_total_processes = 1; public_permit_constructors = 0; invocation_binaries = 0; provider_requests_performed = 0; remote_calls_performed = 0; effects_performed = 0; live_invocations_performed = 0 }
foreach ($name in $expected.Keys) { if ([int64] $manifest.verification.$name -ne [int64] $expected[$name]) { throw "runner evidence count differs: $name" } }
if ($RequireExactGates -and -not [bool] $manifest.verification.exact_workspace_gates_passed) { throw 'runner exact workspace gates remain open' }
"cantor_evox2_scratch_build_remote_preflight_runner_evidence_verified=true artifacts=26 focused_tests=10 public_permit_constructors=0 invocation_binaries=0 provider_requests_performed=0 remote_calls_performed=0 effects_performed=0 live_invocations_performed=0 exact_gates=$([bool] $manifest.verification.exact_workspace_gates_passed)"
