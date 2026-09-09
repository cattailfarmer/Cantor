[CmdletBinding()]
param([string] $Root = (Split-Path -Parent $PSScriptRoot))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_plan_only_build_job_p0/local_core_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-plan-only-build-job-local-core-evidence/0.1' 'profile'
Assert-Equal $manifest.manifest_uuid '722a146b-9ffb-4f01-aed5-3a2d80581e9c' 'manifest_uuid'
Assert-Equal $manifest.canonical_uuid '3482e2ce-817c-4788-b185-35adaad414f7' 'canonical_uuid'
Assert-Equal $manifest.formation_signature_uuid '58968a69-538e-43ee-85db-3401765d1fd4' 'formation_signature_uuid'
Assert-Equal $manifest.formation_bookend_commit 'fb8e9ba7c8d4e44695c31da5334a91d7e3896c7a' 'formation_bookend_commit'
if (@($manifest.artifacts).Count -ne 18) { throw 'artifact_count mismatch' }

$seen = @{}
foreach ($artifact in $manifest.artifacts) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') { throw 'nonportable artifact path' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'duplicate artifact path' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "linked artifact $relative" }
    if ($item.Length -ne [int64] $artifact.bytes) { throw "byte mismatch $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string] $artifact.sha256) { throw "hash mismatch $relative" }
}

$required = @(
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/evox2_plan_only_build_job.rs',
    'crates/cantor_core/src/bin/cantor-evox2-plan-only-build-job.rs',
    'crates/cantor_core/src/bin/cantor-evox2-plan-only-build-job-verify.rs',
    'crates/cantor_core/tests/evox2_plan_only_build_job.rs',
    'scripts/verify_cantor_evox2_plan_only_build_job_p0_local_core.ps1',
    'scripts/test_cantor_evox2_plan_only_build_job_p0_local_core.ps1'
)
foreach ($relative in $required) {
    if (-not $seen.ContainsKey($relative.ToUpperInvariant())) { throw "required artifact missing $relative" }
}

$module = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/src/evox2_plan_only_build_job.rs') -Raw
foreach ($token in @(
    'pub const EVOX2_BUILD_PLAN_PROFILE: &str = "cantor-evox2-plan-only-build-job/0.1";',
    'pub const EVOX2_BUILD_PLAN_CANONICAL_UUID: &str = "3482e2ce-817c-4788-b185-35adaad414f7";',
    'pub const EVOX2_BUILD_PLAN_SIGNATURE_UUID: &str = "58968a69-538e-43ee-85db-3401765d1fd4";',
    'operation_count: 7,',
    'authority_grants: Vec::new(),',
    'disposition: "planned_effectless".to_owned()',
    'effects: 0,'
)) {
    if (-not $module.Contains($token)) { throw "module token missing: $token" }
}
foreach ($forbidden in @('std::fs', 'std::process', 'std::env', 'TcpStream', 'reqwest::', 'tokio::', 'unsafe {')) {
    if ($module.Contains($forbidden)) { throw "pure module contains forbidden effect surface: $forbidden" }
}

$tests = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/tests/evox2_plan_only_build_job.rs') -Raw
if (($tests | Select-String -Pattern '#\[test\]' -AllMatches).Matches.Count -ne 11) { throw 'focused Rust test count mismatch' }
foreach ($token in @('fresh_cli_processes_compile_verify_and_refuse_tamper', 'dependency_cycle_refuses_after_digest_repair', 'authority_grant_and_unresolved_removal_refuse_after_digest_repair')) {
    if (-not $tests.Contains($token)) { throw "focused Rust test token missing: $token" }
}

$verification = $manifest.verification
$expectedCounts = @{
    artifact_count = 18
    rust_source_files = 4
    rust_test_files = 1
    focused_tests = 11
    operations = 7
    authority_denials = 15
    authority_grants = 0
    unresolved = 5
    compiler_processes = 2
    verifier_processes = 2
    provider_requests = 0
    remote_calls = 0
    effects = 0
}
foreach ($key in $expectedCounts.Keys) {
    if ([int64] $verification.$key -ne [int64] $expectedCounts[$key]) { throw "verification count mismatch $key" }
}
foreach ($key in @('focused_debug_passed', 'focused_overflow_checked_release_passed', 'workspace_debug_passed', 'workspace_overflow_checked_release_passed', 'workspace_clippy_warnings_denied', 'format_passed', 'byte_identical_recompilation')) {
    if ($verification.$key -ne $true) { throw "verification gate mismatch $key" }
}
if ($verification.package_constructed -ne $false -or $verification.remote_effects_authorized -ne $false -or $verification.physical_build_authorized -ne $false) { throw 'phase authority promotion admitted' }

'cantor_evox2_plan_only_build_job_p0_local_core_verified=true artifacts=18 rust_sources=4 rust_tests=1 focused_tests=11 operations=7 denials=15 grants=0 unresolved=5 compiler_processes=2 verifier_processes=2 provider_requests=0 remote_calls=0 effects=0 package_constructed=false remote_effects_authorized=false'
