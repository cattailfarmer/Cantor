[CmdletBinding()]
param([string] $Root = (Split-Path -Parent $PSScriptRoot))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_scratch_build_executor_p0/local_core_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-scratch-build-executor-local-core-evidence/0.1' 'profile'
Assert-Equal $manifest.manifest_uuid 'ad76a288-7cb0-4ef6-b6b4-40f3b6e57f4e' 'manifest_uuid'
Assert-Equal $manifest.canonical_uuid '935e020f-8c6f-49e4-b355-63eabd3b778b' 'canonical_uuid'
Assert-Equal $manifest.formation_signature_uuid '610fe633-34ec-40a5-a95c-170d0cffb3c1' 'formation_signature_uuid'
Assert-Equal $manifest.formation_bookend_commit '7bbf6e3c77866b971939e0f56f0984f6c61fcda3' 'formation_bookend_commit'
if (@($manifest.artifacts).Count -ne 18) { throw 'artifact_count mismatch' }

$seen = @{}
foreach ($artifact in $manifest.artifacts) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw 'nonportable artifact path' }
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
    'specifications/Cantor_EVO_X2_Scratch_Build_Executor_P0.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Satisfaction_Signature.sop',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/evox2_scratch_build_executor.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-commission-verify.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-receipt-verify.rs',
    'crates/cantor_core/tests/evox2_scratch_build_executor.rs',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_local_core.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_local_core.ps1'
)
foreach ($relative in $required) {
    if (-not $seen.ContainsKey($relative.ToUpperInvariant())) { throw "required artifact missing $relative" }
}

$module = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/src/evox2_scratch_build_executor.rs') -Raw
foreach ($token in @(
    'pub const EVOX2_SCRATCH_BUILD_PROFILE: &str = "cantor-evox2-scratch-build-executor/0.1";',
    'pub const EVOX2_SCRATCH_BUILD_CANONICAL_UUID: &str = "935e020f-8c6f-49e4-b355-63eabd3b778b";',
    'pub const EVOX2_SCRATCH_BUILD_SIGNATURE_UUID: &str = "610fe633-34ec-40a5-a95c-170d0cffb3c1";',
    '"source_transfer",',
    '"autonomous_work",',
    '"workspace_release",',
    'Cargo operation executable identity differs',
    'executor operation executable identity differs',
    'total operation duration differs'
)) {
    if (-not $module.Contains($token)) { throw "module token missing: $token" }
}
foreach ($forbidden in @('std::fs', 'std::process', 'std::env', 'TcpStream', 'reqwest::', 'tokio::', 'unsafe {')) {
    if ($module.Contains($forbidden)) { throw "pure module contains forbidden effect surface: $forbidden" }
}

$tests = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/tests/evox2_scratch_build_executor.rs') -Raw
if (($tests | Select-String -Pattern '#\[test\]' -AllMatches).Matches.Count -ne 16) { throw 'focused Rust test count mismatch' }
foreach ($token in @('receipt_cross_binds_cargo_and_executor_executable_identities', 'cumulative_operation_duration_bound_refuses', 'fresh_verifier_processes_pass_and_refuse_tamper', 'conservation_drift_and_persistent_process_refuse')) {
    if (-not $tests.Contains($token)) { throw "focused Rust test token missing: $token" }
}

$verification = $manifest.verification
$expectedCounts = @{
    artifact_count = 18
    rust_source_files = 4
    rust_test_files = 1
    focused_tests = 16
    operations = 7
    authority_denials = 14
    authority_grants = 5
    commission_fields = 21
    toolchain_fields = 11
    operation_record_fields = 20
    receipt_fields = 20
    verifier_processes = 2
    provider_requests = 0
    remote_calls = 0
    effects = 0
}
foreach ($key in $expectedCounts.Keys) {
    if ([int64] $verification.$key -ne [int64] $expectedCounts[$key]) { throw "verification count mismatch $key" }
}
foreach ($key in @('focused_debug_passed', 'focused_overflow_checked_release_passed', 'workspace_debug_passed', 'workspace_overflow_checked_release_passed', 'workspace_clippy_warnings_denied', 'format_passed', 'executable_identity_cross_bound')) {
    if ($verification.$key -ne $true) { throw "verification gate mismatch $key" }
}
if ($verification.package_constructed -ne $false -or $verification.remote_effects_authorized -ne $false -or $verification.physical_build_authorized -ne $false) { throw 'phase authority promotion admitted' }

'cantor_evox2_scratch_build_executor_p0_local_core_verified=true artifacts=18 rust_sources=4 rust_tests=1 focused_tests=16 operations=7 denials=14 grants=5 commission_fields=21 toolchain_fields=11 operation_record_fields=20 receipt_fields=20 verifier_processes=2 provider_requests=0 remote_calls=0 effects=0 package_constructed=false remote_effects_authorized=false physical_build_authorized=false'
