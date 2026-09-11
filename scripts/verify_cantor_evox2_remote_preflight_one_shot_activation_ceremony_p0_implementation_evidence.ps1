[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $RequireExactGates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-implementation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '75e86c34-af3f-4092-856c-73bb5cab5db4' -or
    $manifest.canonical_uuid -cne 'd2724a39-56bd-47ae-8787-064a6196dbfb' -or
    $manifest.signature_uuid -cne '1feeedea-716a-4b47-ac28-d7e5b7045842' -or
    $manifest.formation_commit -cne '7b508b67a7b16c091e4dbea512c691b885e33a2f' -or
    $manifest.formation_bookend -cne '169c7720914b53c7800293f8352e1ede84846013') { throw 'activation implementation evidence identity differs' }
if (@($manifest.artifacts).Count -ne 46) { throw 'activation implementation artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)[.][.](/|$)') { throw 'activation implementation artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'activation implementation duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "activation implementation artifact identity differs: $relative" }
}
$v = $manifest.verification
$expected = @{
    artifact_count = 46; focused_debug_passed = 16; focused_release_passed = 16; focused_ignored = 1
    retained_artifacts = 11; independent_replays = 2; roles = 8; stages = 8; clock_reads = 0
    workspace_result_groups = 325; workspace_tests_passed = 1975; workspace_tests_failed = 0; workspace_tests_ignored = 22
    signature_creations = 0; permits_minted = 0; runner_invocations = 0; process_spawns = 0
    provider_requests = 0; remote_calls = 0; effects = 0; synthetic_trials = 0
}
foreach ($name in $expected.Keys) { if ([int64] $v.$name -ne [int64] $expected[$name]) { throw "activation implementation evidence count differs: $name" } }
foreach ($name in @('workspace_clippy_warnings_denied','workspace_format_passed','powershell_7_evidence_passed','windows_powershell_5_1_evidence_passed','native_lifecycle_provider_independent_passed')) { if (-not [bool] $v.$name) { throw "activation implementation gate differs: $name" } }
if ($RequireExactGates -and -not [bool] $v.exact_workspace_gates_passed) { throw 'activation implementation exact workspace gates remain open' }

$ceremony = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/evox2_remote_preflight_one_shot_activation_ceremony.rs') -Raw
$evidence = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/evox2_remote_preflight_one_shot_activation_ceremony_evidence.rs') -Raw
$cli = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_ecosystem/src/bin/cantor-evox2-remote-preflight-activation-evidence-verify.rs') -Raw
foreach ($token in @('std::fs','std::net','std::process','Command::','SigningKey','mint_private_execution_permit','invoke_evox2_scratch_build_remote_preflight_runner')) { if ($ceremony.Contains($token)) { throw "activation ceremony gained effect token: $token" } }
foreach ($token in @('std::net','Command::','SigningKey','mint_private_execution_permit','invoke_evox2_scratch_build_remote_preflight_runner')) { if ($evidence.Contains($token) -or $cli.Contains($token)) { throw "activation verifier gained effect token: $token" } }
foreach ($token in @('EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT','EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND','live_authorization_admitted: false','permit_mint_authorized: false','runner_invocation_authorized: false')) { if (-not $ceremony.Contains($token) -and -not $evidence.Contains($token)) { throw "activation implementation invariant absent: $token" } }

$retainedRoot = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence'
$retainedNames = @(Get-ChildItem -LiteralPath $retainedRoot -Force | Sort-Object Name | ForEach-Object { $_.Name })
$expectedNames = @('activation_request.json','authorize_correspondence.json','authorize_decision.json','controller_plan.json','controller_request.json','evidence_manifest.json','producer_plan.json','program.json','proposal_verification.json','proposal.json','reject_correspondence.json','reject_decision.json') | Sort-Object
if (($retainedNames -join "`n") -cne ($expectedNames -join "`n")) { throw 'retained evidence membership differs' }
$verification = Get-Content -LiteralPath (Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_verification.json') -Raw | ConvertFrom-Json
if ($verification.evidence_verification_sha256 -cne 'b943a945fe3d71d2cf93f8dc260bbfa20261f1eecbd0a48a673e752c84f69bbf' -or
    [int] $verification.artifact_count -ne 11 -or [int] $verification.independent_replay_count -ne 2 -or
    -not [bool] $verification.authorize_and_reject_distinct -or -not [bool] $verification.signature_correspondence -or
    [bool] $verification.live_authorization_admitted -or [bool] $verification.permit_mint_authorized -or [bool] $verification.runner_invocation_authorized) { throw 'retained activation verification differs' }
foreach ($name in @('clock_reads','signature_creations','permit_mints','runner_invocations','process_spawns','provider_requests','remote_calls','effects','synthetic_trials')) { if ([int64] $verification.effect_account.$name -ne 0) { throw "retained activation effect account differs: $name" } }

"cantor_evox2_remote_preflight_activation_implementation_evidence_verified=true artifacts=46 focused_debug=16 focused_release=16 workspace_groups=325 workspace_passed=1975 workspace_failed=0 workspace_ignored=22 retained_artifacts=11 independent_replays=2 native_lifecycle=true live_authorization=false permits=0 runner_invocations=0 process_spawns=0 provider_requests=0 remote_calls=0 effects=0 synthetic_trials=0 exact_gates=$([bool] $v.exact_workspace_gates_passed)"
