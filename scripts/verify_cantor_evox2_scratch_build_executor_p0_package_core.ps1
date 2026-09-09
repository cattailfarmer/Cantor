[CmdletBinding()]
param([string] $Root = (Split-Path -Parent $PSScriptRoot))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_scratch_build_executor_p0/package_core_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-scratch-build-executor-package-core-evidence/0.1' 'profile'
Assert-Equal $manifest.manifest_uuid '91a27269-01df-44e4-805e-4cc4bf786169' 'manifest_uuid'
Assert-Equal $manifest.canonical_uuid '935e020f-8c6f-49e4-b355-63eabd3b778b' 'canonical_uuid'
Assert-Equal $manifest.local_core_bookend_commit '1edd3a5596660b9789d7bf43eba82d2ee4917744' 'local_core_bookend_commit'
if (@($manifest.artifacts).Count -ne 31) { throw 'artifact count mismatch' }

$seen = @{}
foreach ($artifact in $manifest.artifacts) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw 'nonportable artifact path' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'duplicate artifact coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "linked artifact $relative" }
    if ($item.Length -ne [int64] $artifact.bytes) { throw "byte mismatch $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string] $artifact.sha256) { throw "hash mismatch $relative" }
}

$required = @(
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Acyclic_Package_Design_2026-09-09.sop',
    'crates/cantor_core/src/evox2_scratch_build_archive.rs',
    'crates/cantor_core/src/evox2_scratch_build_executor.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-commission.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-package-verify.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-executor.rs',
    'crates/cantor_core/tests/evox2_scratch_build_executor.rs',
    'narrative/operational_faults/1788984100000_evox2_scratch_build_absent_workspace_working_directory_contradiction.sop',
    'narrative/operational_faults/1788986200000_evox2_scratch_build_preflight_refusal_observation_gap.sop'
)
foreach ($relative in $required) {
    if (-not $seen.ContainsKey($relative.ToUpperInvariant())) { throw "required artifact missing $relative" }
}

$semantic = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/src/evox2_scratch_build_executor.rs') -Raw
foreach ($token in @(
    'cantor-evox2-scratch-build-command-set/0.1',
    'cantor-evox2-scratch-build-implementation-manifest/0.1',
    'cantor-evox2-scratch-build-deployment-envelope/0.1',
    'acyclic package correspondence differs',
    'not_observed_due_to_preflight_refusal',
    'C:/AI/workspaces',
    'source.tar'
)) {
    if (-not $semantic.Contains($token)) { throw "semantic token missing: $token" }
}
foreach ($forbidden in @('std::fs', 'std::process', 'TcpStream', 'reqwest::', 'tokio::', 'unsafe {')) {
    if ($semantic.Contains($forbidden)) { throw "semantic module contains effect surface: $forbidden" }
}

$archive = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/src/evox2_scratch_build_archive.rs') -Raw
foreach ($token in @('archive special member refused', 'archive duplicate case-folded coordinate refused', 'PAX key refused', 'create_new(true)', 'atomic workspace establishment failed')) {
    if (-not $archive.Contains($token)) { throw "archive token missing: $token" }
}
$tests = Get-Content -LiteralPath (Join-Path $rootPath 'crates/cantor_core/tests/evox2_scratch_build_executor.rs') -Raw
if (($tests | Select-String -Pattern '#\[test\]' -AllMatches).Matches.Count -ne 16) { throw 'focused Rust test count mismatch' }
foreach ($token in @('package_graph_refuses_cycles_membership_and_digest_drift', 'commission_compiler_process_is_deterministic_and_manifest_bound', 'pinned_git_archive_passes_strict_ustar_pax_admission')) {
    if (-not $tests.Contains($token)) { throw "focused test token missing: $token" }
}

$verification = $manifest.verification
$expectedCounts = @{
    artifact_count = 31
    focused_tests = 16
    archive_unit_tests = 3
    package_layers = 3
    package_artifacts = 20
    command_records = 4
    operations = 7
    authority_grants = 5
    authority_denials = 14
    provider_requests = 0
    remote_calls = 0
    effects = 0
}
foreach ($key in $expectedCounts.Keys) {
    if ([int64] $verification.$key -ne [int64] $expectedCounts[$key]) { throw "verification count mismatch $key" }
}
foreach ($key in @('focused_debug_passed', 'focused_overflow_checked_release_passed', 'clippy_warnings_denied', 'format_passed', 'real_pinned_archive_passed', 'raw_byte_refusal_passed', 'acyclic_correspondence_passed')) {
    if ($verification.$key -ne $true) { throw "verification gate mismatch $key" }
}
if ($verification.package_constructed -ne $false -or $verification.live_effects_authorized -ne $false -or $verification.physical_build_performed -ne $false) { throw 'phase authority promotion admitted' }

'cantor_evox2_scratch_build_executor_p0_package_core_verified=true artifacts=31 focused_tests=16 archive_tests=3 package_layers=3 package_artifacts=20 commands=4 operations=7 grants=5 denials=14 provider_requests=0 remote_calls=0 effects=0 package_constructed=false live_effects_authorized=false'
