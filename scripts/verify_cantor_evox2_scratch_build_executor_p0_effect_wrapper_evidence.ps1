[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $RequireExactGates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\effect_wrapper_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-scratch-build-effect-wrapper-evidence/0.1' -or $manifest.manifest_uuid -cne 'c93d6b10-1b6a-4762-9cba-b56249f25b45' -or $manifest.canonical_uuid -cne '935e020f-8c6f-49e4-b355-63eabd3b778b' -or $manifest.controller_implementation_commit -cne 'c0fd8175a6fba0f61a53868b2660bc361dadb96c' -or $manifest.controller_publication_bookend -cne 'e153c9f60f04c76ef85c77a068106d747774ad47' -or $manifest.package_set_sha256 -cne 'fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e') { throw 'effect-wrapper evidence identity differs' }
if (@($manifest.artifacts).Count -ne 28) { throw 'effect-wrapper evidence artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)\.\.(/|$)') { throw 'effect-wrapper artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'effect-wrapper artifact duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "effect-wrapper artifact identity differs: $relative" }
}
function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}
function Get-OneLine([string] $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    if (-not $raw.EndsWith("`n", [StringComparison]::Ordinal) -or $raw.EndsWith("`n`n", [StringComparison]::Ordinal)) { throw 'effect-wrapper fixture line framing differs' }
    $value = $raw.Substring(0, $raw.Length - 1)
    if ($value.Contains("`r") -or $value.Contains("`n")) { throw 'effect-wrapper fixture is not one LF-framed line' }
    $value
}
function Assert-Digest([string] $Raw, [string] $Property, [string] $Domain) {
    $value = $Raw | ConvertFrom-Json
    $digest = [string] $value.$Property
    $token = '"' + $Property + '":"' + $digest + '"'
    $unsigned = $Raw.Replace($token, ('"' + $Property + '":""'))
    if ($unsigned -ceq $Raw -or (Get-TextSha256 ($Domain + [char]0 + $unsigned)) -cne $digest) { throw "effect-wrapper fixture digest differs: $Property" }
}
$controllerRoot = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\controller_fixture'
$fixtureRoot = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\effect_wrapper_fixture'
$request = Get-OneLine (Join-Path $controllerRoot 'request.json') | ConvertFrom-Json
$plan = Get-OneLine (Join-Path $controllerRoot 'plan.json') | ConvertFrom-Json
$programRaw = Get-OneLine (Join-Path $fixtureRoot 'program.json')
$stateRaw = Get-OneLine (Join-Path $fixtureRoot 'initial_state.json')
$preflightRaw = Get-OneLine (Join-Path $fixtureRoot 'preflight_refusal.json')
$refusalRaw = Get-OneLine (Join-Path $fixtureRoot 'operational_refusal.json')
$verificationRaw = Get-OneLine (Join-Path $fixtureRoot 'refusal_verification.json')
Assert-Digest $programRaw 'program_sha256' 'cantor-evox2-scratch-build-deployment-effect-program-v1'
Assert-Digest $stateRaw 'state_sha256' 'cantor-evox2-scratch-build-effect-state-v1'
Assert-Digest $preflightRaw 'preflight_sha256' 'cantor-evox2-scratch-build-controller-preflight-v1'
Assert-Digest $refusalRaw 'refusal_sha256' 'cantor-evox2-scratch-build-controller-operational-refusal-v1'
$program = $programRaw | ConvertFrom-Json
$state = $stateRaw | ConvertFrom-Json
$preflight = $preflightRaw | ConvertFrom-Json
$refusal = $refusalRaw | ConvertFrom-Json
$verification = $verificationRaw | ConvertFrom-Json
$roles = @('local_package_verifier', 'publication_lineage_verifier', 'bounded_remote_preflight', 'bounded_package_transfer', 'remote_package_verifier', 'create_new_atomic_service_installer', 'fixed_profile_host_harness', 'immutable_evidence_retriever', 'independent_live_evidence_verifier', 'transient_transport_cleaner')
if ($program.request_sha256 -cne $request.request_sha256 -or $program.plan_sha256 -cne $plan.plan_sha256 -or $program.package_set_sha256 -cne $request.package_set_sha256 -or @($program.stages).Count -ne 10 -or [int] $program.stage_count -ne 10 -or $program.authority_disposition -cne 'compiled_effect_roles_not_live_authority' -or [bool] $program.execution_authorized -or [bool] $program.remote_contact_authorized -or [int] $program.provider_requests -ne 0 -or [int] $program.remote_calls -ne 0 -or [int] $program.effects -ne 0) { throw 'effect-wrapper program semantics differ' }
for ($index = 0; $index -lt 10; $index++) { if ([int] $program.stages[$index].ordinal -ne ($index + 1) -or [string] $program.stages[$index].kind -cne [string] $plan.stages[$index].kind -or [string] $program.stages[$index].executor_role -cne $roles[$index] -or [string] $program.stages[$index].required_authority -cne [string] $plan.stages[$index].required_authority -or [bool] $program.stages[$index].effectful -ne [bool] $plan.stages[$index].effectful -or -not [bool] $program.stages[$index].stop_on_failure) { throw 'effect-wrapper stage correspondence differs' } }
if ($state.program_sha256 -cne $program.program_sha256 -or [int] $state.next_stage_ordinal -ne 1 -or [int] $state.completed_stage_count -ne 0 -or @($state.observation_sha256s).Count -ne 0 -or $state.status -cne 'active' -or $state.disposition -cne 'awaiting_stage' -or [bool] $state.evidence_is_fixture -or [int] $state.remote_calls -ne 0 -or [int] $state.effects -ne 0) { throw 'effect-wrapper initial state differs' }
if ($preflight.request_sha256 -cne $request.request_sha256 -or $preflight.plan_sha256 -cne $plan.plan_sha256 -or $preflight.program_sha256 -cne $program.program_sha256 -or $preflight.status -cne 'refused' -or $preflight.reason -cne 'provider_unavailable_before_commission' -or $preflight.observation_source -cne 'supplied_provider_free_fixture' -or [bool] $preflight.commission_admitted -or [bool] $preflight.receipt_expected -or [bool] $preflight.remote_contact_made -or [int] $preflight.remote_calls -ne 0 -or [int] $preflight.effects -ne 0) { throw 'effect-wrapper preflight refusal differs' }
if ($refusal.preflight_sha256 -cne $preflight.preflight_sha256 -or $refusal.disposition -cne 'operational_refusal_before_commission_no_receipt' -or [bool] $refusal.commission_admitted -or [bool] $refusal.receipt_present -or [int] $refusal.retrieved_artifact_count -ne 0 -or [int] $refusal.provider_requests -ne 0 -or [int] $refusal.remote_calls -ne 0 -or [int] $refusal.effects -ne 0) { throw 'effect-wrapper operational refusal differs' }
if ($verification.status -cne 'passed' -or $verification.branch -cne $refusal.disposition -or $verification.program_sha256 -cne $program.program_sha256 -or $verification.preflight_sha256 -cne $preflight.preflight_sha256 -or $verification.refusal_sha256 -cne $refusal.refusal_sha256 -or [bool] $verification.physical_build_performed -or -not [bool] $verification.protected_state_unchanged -or -not [bool] $verification.provider_state_unchanged -or -not [bool] $verification.evidence_is_fixture -or [int] $verification.provider_requests -ne 0 -or [int] $verification.remote_calls -ne 0 -or [int] $verification.effects -ne 0) { throw 'effect-wrapper refusal verification differs' }
$expected = @{ artifact_count = 28; focused_tests = 15; stage_count = 10; effectful_stage_count = 7; checked_fixture_forms = 5; isolated_successes = 1; isolated_refusals = 5; provider_requests = 0; remote_calls = 0; effects = 0 }
foreach ($name in $expected.Keys) { if ([int] $manifest.verification.$name -ne [int] $expected[$name]) { throw "effect-wrapper evidence count differs: $name" } }
if ([bool] $manifest.verification.remote_contact_authorized -or [bool] $manifest.verification.execution_authorized -or -not [bool] $manifest.verification.evidence_is_fixture) { throw 'effect-wrapper evidence authority differs' }
if ($RequireExactGates -and -not [bool] $manifest.verification.exact_workspace_gates_passed) { throw 'effect-wrapper exact workspace gates remain open' }
"cantor_evox2_scratch_build_effect_wrapper_evidence_verified=true artifacts=28 focused_tests=15 stages=10 effectful_stages=7 fixture_forms=5 isolated_successes=1 isolated_refusals=5 provider_requests=0 remote_calls=0 execution_authorized=false effects=0 exact_gates=$([bool] $manifest.verification.exact_workspace_gates_passed)"
