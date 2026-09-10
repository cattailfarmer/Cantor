[CmdletBinding()]
param([string] $Root = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\harness_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Exact($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name differs" }
}

Assert-Exact $manifest.profile 'cantor-evox2-scratch-build-executor-harness-implementation-evidence/0.1' 'profile'
Assert-Exact $manifest.manifest_uuid '51c51a83-1ff3-497d-92f1-9998f8cf8583' 'manifest UUID'
Assert-Exact $manifest.canonical_uuid '935e020f-8c6f-49e4-b355-63eabd3b778b' 'canonical UUID'
Assert-Exact $manifest.package_core_bookend_commit 'f87734eab7b93f7ccb2370667cbb88089d72201d' 'package-core bookend'
if (@($manifest.artifacts).Count -ne 27) { throw 'artifact cardinality differs' }
$seen = @{}
foreach ($artifact in $manifest.artifacts) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw 'artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'duplicate artifact coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string] $artifact.sha256) { throw "artifact identity differs: $relative" }
}
foreach ($required in @(
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-package-compose.rs',
    'crates/cantor_ecosystem/src/evox2_scratch_build_contained_process.rs',
    'crates/cantor_ecosystem/src/bin/cantor-evox2-scratch-build-operation-runner.rs',
    'scripts/invoke-cantor-evox2-scratch-build-once.ps1',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_package.ps1',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Design_2026-09-09.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Coverage.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0HarnessImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Phase_Checkpoint.sop',
    'narrative/turns/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/file_changes/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/change_sets/9cf81f2d-79e4-4cd6-81c2-09d3eac7ca84.sop'
)) {
    if (-not $seen.ContainsKey($required.ToUpperInvariant())) { throw "required artifact absent: $required" }
}

$core = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_core\src\evox2_scratch_build_executor.rs') -Raw
foreach ($token in @('const PACKAGE_ARTIFACTS: [(&str, &str); 21]', 'contained_operation_runner', 'toolchain_probe_once', 'stopped_receipt_sealer')) {
    if (-not $core.Contains($token)) { throw "core harness token absent: $token" }
}
$containment = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\self_work_update_broker_b1_cdrive_windows_containment.rs') -Raw
foreach ($token in @('CREATE_SUSPENDED', 'AssignProcessToJobObject', 'retain_output_overflow()', 'forced_termination = true')) {
    if (-not $containment.Contains($token)) { throw "containment token absent: $token" }
}
$contract = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\evox2_scratch_build_contained_process.rs') -Raw
foreach ($token in @('7_190_000', '16_777_216', '16_384', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_PROFILE_', 'CARGO_TARGET_')) {
    if (-not $contract.Contains($token)) { throw "contained contract token absent: $token" }
}
$runner = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_ecosystem\src\bin\cantor-evox2-scratch-build-operation-runner.rs') -Raw
foreach ($token in @('create_new(true)', 'toolchain-probe.stdout.bin', 'target-byte fixed point', 'report_seal_process', 'run_evox2_scratch_build_contained_process')) {
    if (-not $runner.Contains($token)) { throw "operation runner token absent: $token" }
}
foreach ($forbidden in @('Command::new', 'TcpStream', 'reqwest::', 'tokio::', 'unsafe {')) {
    if ($runner.Contains($forbidden)) { throw "operation runner contains forbidden surface: $forbidden" }
}
$harness = Get-Content -LiteralPath (Join-Path $rootPath 'scripts\invoke-cantor-evox2-scratch-build-once.ps1') -Raw
foreach ($token in @('C:/AI/services/cantor-scratch-build-4fdd29cb', 'Invoke-Operation 1', 'foreach ($ordinal in 3..6)', "Complete-StoppedReceipt 'failed'", 'Assert-Conservation', 'Get-ProviderState', 'persistent_processes')) {
    if (-not $harness.Contains($token)) { throw "host harness token absent: $token" }
}
foreach ($forbidden in @('ssh.exe', 'scp.exe', 'Invoke-Expression', 'cmd.exe', 'Start-Process', 'Remove-Item')) {
    if ($harness.Contains($forbidden)) { throw "host harness contains forbidden dispatch: $forbidden" }
}
$builder = Get-Content -LiteralPath (Join-Path $rootPath 'scripts\build_cantor_evox2_scratch_build_executor_p0_package.ps1') -Raw
foreach ($token in @('ImplementationCommit', 'PublicationBookendCommit', 'publication bookend must be the immediate single-parent child', "Join-Path `$sourceRoot", '--locked', '--offline', 'artifact_count = 21', 'package_file_count = 24', 'remote_calls = 0', 'effects = 0')) {
    if (-not $builder.Contains($token)) { throw "package builder token absent: $token" }
}
$coreTests = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_core\tests\evox2_scratch_build_executor.rs') -Raw
if (($coreTests | Select-String -Pattern '#\[test\]' -AllMatches).Matches.Count -ne 17) { throw 'core focused test count differs' }
$contractTests = ($contract | Select-String -Pattern '#\[test\]' -AllMatches).Matches.Count
if ($contractTests -ne 2) { throw 'contained-process test count differs' }
foreach ($relative in @(
    'scripts/invoke-cantor-evox2-scratch-build-once.ps1',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_package.ps1',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_harness_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_harness_implementation.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_harness_implementation.ps1'
)) {
    $tokens = $null
    $errors = $null
    [void] [Management.Automation.Language.Parser]::ParseFile((Join-Path $rootPath $relative), [ref] $tokens, [ref] $errors)
    if ($errors.Count -ne 0) { throw "PowerShell parse differs: $relative" }
}
$expected = @{
    artifact_count = 27; core_focused_tests = 17; contained_process_tests = 2; package_artifacts = 21; package_files = 24
    operation_records = 7; toolchain_probes = 1; authority_grants = 5; authority_denials = 14; isolated_adversarial_refusals = 4
    provider_requests = 0; remote_calls = 0; effects = 0
}
foreach ($name in $expected.Keys) {
    if ([int64] $manifest.verification.$name -ne [int64] $expected[$name]) { throw "verification count differs: $name" }
}
foreach ($name in @('focused_debug_passed', 'clippy_warnings_denied', 'powershell7_parse_passed', 'windows_powershell51_parse_passed', 'format_passed')) {
    if ($manifest.verification.$name -ne $true) { throw "verification gate differs: $name" }
}
if ($manifest.verification.package_constructed -ne $false -or $manifest.verification.live_effects_authorized -ne $false -or $manifest.verification.physical_build_performed -ne $false) { throw 'implementation evidence promotes a later phase' }

'cantor_evox2_scratch_build_harness_implementation_verified=true artifacts=27 core_tests=17 contained_tests=2 package_artifacts=21 package_files=24 operations=7 probes=1 grants=5 denials=14 isolated_refusals=4 provider_requests=0 remote_calls=0 effects=0 package_constructed=false live_effects_authorized=false'
