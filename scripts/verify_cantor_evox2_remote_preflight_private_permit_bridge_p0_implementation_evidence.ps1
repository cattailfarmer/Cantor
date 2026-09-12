[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $RequireExactGates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-remote-preflight-private-permit-bridge-implementation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '6eef4fb2-320c-4ae0-9299-003295f84c8d' -or
    $manifest.canonical_uuid -cne '06d82d16-143a-4abb-9c70-c03163285842' -or
    $manifest.signature_uuid -cne '3f7d776d-e012-4efc-9426-d40cf6af7fcb' -or
    $manifest.formation_commit -cne '001c75ad761d6890c29db793d6d133bdcca037b8' -or
    $manifest.formation_bookend -cne 'd76d0fe0086c8b7b5fab20fbda444524d071d126') { throw 'private permit bridge implementation evidence identity differs' }
if (@($manifest.artifacts).Count -ne 31) { throw 'private permit bridge implementation artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)[.][.](/|$)') { throw 'private permit bridge artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'private permit bridge duplicate artifact coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "private permit bridge artifact identity differs: $relative" }
}

$lib = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/lib.rs') -Raw
$bridge = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/evox2_remote_preflight_private_permit_bridge.rs') -Raw
$runner = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/evox2_scratch_build_remote_preflight_runner.rs') -Raw
$production = $bridge.Split(@('#[cfg(test)]'), 2, [StringSplitOptions]::None)[0]
if ([regex]::Matches($lib, '(?m)^pub\(crate\) mod evox2_remote_preflight_private_permit_bridge;$').Count -ne 1 -or
    $lib -cmatch '(?m)^pub mod evox2_remote_preflight_private_permit_bridge;$' -or
    $lib -cmatch '(?m)^pub use evox2_remote_preflight_private_permit_bridge') { throw 'private permit bridge module visibility differs' }
if ([regex]::Matches($production, '(?m)^pub\(crate\) struct Evox2RemotePreflightLiveAdmission \{$').Count -ne 1 -or
    [regex]::Matches($production, '(?m)^pub\(crate\) fn run_evox2_remote_preflight_private_permit_bridge_once\($').Count -ne 1 -or
    [regex]::Matches($production, 'runner\(permit\)').Count -ne 1) { throw 'private permit bridge production cardinality differs' }
foreach ($token in @('Serialize','Deserialize','Default','std::fs','std::net','std::process','Command::','std::env','loop {','while ','retry(','thread::spawn','live_initiation')) {
    if ($production.Contains($token)) { throw "private permit bridge gained forbidden production token: $token" }
}
if ([regex]::Matches($runner, '(?m)^pub\(crate\) fn issue_evox2_scratch_build_remote_preflight_single_use_permit\($').Count -ne 1 -or
    $runner.Contains('impl Clone for Evox2ScratchBuildRemotePreflightSingleUsePermit') -or
    $runner.Contains('impl Serialize for Evox2ScratchBuildRemotePreflightSingleUsePermit') -or
    $runner.Contains('impl Deserialize for Evox2ScratchBuildRemotePreflightSingleUsePermit')) { throw 'private permit issuer or existing permit surface differs' }
$allSource = (Get-ChildItem -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src') -Recurse -File -Filter '*.rs' | Sort-Object FullName | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
if ([regex]::Matches($allSource, 'issue_evox2_scratch_build_remote_preflight_single_use_permit\(').Count -ne 2 -or
    [regex]::Matches($allSource, 'run_evox2_remote_preflight_private_permit_bridge_once\(').Count -ne 1) { throw 'private permit bridge source call graph differs' }
foreach ($relative in @('crates/cantor_ecosystem/src/bin/cantor-evox2-remote-preflight-private-permit-bridge.rs','crates/cantor_ecosystem/src/evox2_remote_preflight_private_permit_bridge/live_initiation.rs','crates/cantor_ecosystem/src/evox2_remote_preflight_private_permit_bridge/live_initiation/mod.rs')) {
    if (Test-Path -LiteralPath (Join-Path $rootPath $relative)) { throw "forbidden private permit bridge route exists: $relative" }
}

$expected = @{
    artifact_count = 31; focused_debug_passed = 7; focused_release_passed = 7; semantic_tests = 4; static_absence_tests = 3
    admission_type_declarations = 1; production_admission_constructors = 0; permit_issuers = 1; production_bridge_entries = 1
    production_bridge_calls = 0; terminal_dispositions = 4; maximum_attempts = 1; maximum_permits = 1
    maximum_runner_entries = 1; maximum_processes = 1; retry_count = 0; workspace_tests_failed = 0
    production_permits_minted = 0; production_runner_invocations = 0; process_spawns = 0; provider_requests = 0
    remote_calls = 0; effects = 0; synthetic_trials = 0
}
foreach ($name in $expected.Keys) { if ([int64] $manifest.verification.$name -ne [int64] $expected[$name]) { throw "private permit bridge evidence count differs: $name" } }
if ($RequireExactGates) {
    foreach ($name in @('workspace_clippy_warnings_denied','workspace_format_passed','powershell_7_evidence_passed','windows_powershell_5_1_evidence_passed','exact_workspace_gates_passed')) {
        if (-not [bool] $manifest.verification.$name) { throw "private permit bridge exact gate differs: $name" }
    }
    if ([int] $manifest.verification.workspace_result_groups -le 0 -or [int] $manifest.verification.workspace_tests_passed -le 0) { throw 'private permit bridge workspace totals remain open' }
}

"cantor_evox2_remote_preflight_private_permit_bridge_implementation_evidence_verified=true artifacts=31 semantic_tests=4 static_absence_tests=3 admission_constructors=0 permit_issuers=1 production_bridge_calls=0 production_permits=0 production_runner_invocations=0 process_spawns=0 provider_requests=0 remote_calls=0 effects=0 synthetic_trials=0 exact_gates=$([bool] $manifest.verification.exact_workspace_gates_passed)"
