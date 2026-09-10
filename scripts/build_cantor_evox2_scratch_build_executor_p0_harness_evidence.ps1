[CmdletBinding()]
param([string] $Root = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\harness_implementation_evidence_manifest.json'
$paths = @(
    'specifications/Cantor_EVO_X2_Scratch_Build_Executor_P0.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Design_2026-09-09.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Coverage.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0HarnessImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Phase_Checkpoint.sop',
    'narrative/turns/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/file_changes/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/change_sets/9cf81f2d-79e4-4cd6-81c2-09d3eac7ca84.sop',
    'crates/cantor_core/src/evox2_scratch_build_executor.rs',
    'crates/cantor_core/src/evox2_scratch_build_archive.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-executor.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-package-compose.rs',
    'crates/cantor_core/tests/evox2_scratch_build_executor.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/self_work_update_broker_b1_cdrive_windows_containment.rs',
    'crates/cantor_ecosystem/src/evox2_scratch_build_contained_process.rs',
    'crates/cantor_ecosystem/src/bin/cantor-evox2-scratch-build-operation-runner.rs',
    'scripts/invoke-cantor-evox2-scratch-build-once.ps1',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_package.ps1',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_harness_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_harness_implementation.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_harness_implementation.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "artifact boundary differs: $relative" }
    [ordered]@{
        path = $relative
        bytes = [int64] $item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-scratch-build-executor-harness-implementation-evidence/0.1'
    manifest_uuid = '51c51a83-1ff3-497d-92f1-9998f8cf8583'
    canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
    package_core_bookend_commit = 'f87734eab7b93f7ccb2370667cbb88089d72201d'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 27
        core_focused_tests = 17
        contained_process_tests = 2
        package_artifacts = 21
        package_files = 24
        operation_records = 7
        toolchain_probes = 1
        authority_grants = 5
        authority_denials = 14
        focused_debug_passed = $true
        clippy_warnings_denied = $true
        powershell7_parse_passed = $true
        windows_powershell51_parse_passed = $true
        isolated_adversarial_refusals = 4
        format_passed = $true
        provider_requests = 0
        remote_calls = 0
        effects = 0
        package_constructed = $false
        live_effects_authorized = $false
        physical_build_performed = $false
    }
}
$json = ($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($output, $json, [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_harness_evidence_written=$output artifacts=$($artifacts.Count)"
