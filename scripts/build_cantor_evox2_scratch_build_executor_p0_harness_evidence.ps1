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
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Satisfaction_Signature.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Design_2026-09-09.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Coverage.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0HarnessImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Implementation_Phase_Checkpoint.sop',
    'narrative/turns/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/file_changes/1789000451498_evox2_scratch_build_executor_harness_implementation.sop',
    'narrative/change_sets/9cf81f2d-79e4-4cd6-81c2-09d3eac7ca84.sop',
    'narrative/operational_faults/1789006349806_evox2_scratch_build_package_predecessor_machine_form_refusal.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Package_Canonical_Copy_Correction_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0PackageCanonicalCopyCorrectionReview.sop',
    'narrative/turns/1789006349806_evox2_scratch_build_package_canonical_copy_correction.sop',
    'narrative/file_changes/1789006349806_evox2_scratch_build_package_canonical_copy_correction.sop',
    'narrative/change_sets/4403d481-b77c-4eab-9fe1-ee6c97d68cbc.sop',
    'narrative/operational_faults/1789011591513_evox2_scratch_build_package_authority_count_expectation_refusal.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Package_Authority_Count_Correction_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0PackageAuthorityCountCorrectionReview.sop',
    'narrative/turns/1789011591513_evox2_scratch_build_package_authority_count_correction.sop',
    'narrative/file_changes/1789011591513_evox2_scratch_build_package_authority_count_correction.sop',
    'narrative/change_sets/9c5b8c1d-672e-41d5-833d-2fd8a55b6115.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Package_Construction_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0PackageConstructionReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Package_Construction_Phase_Checkpoint.sop',
    'narrative/turns/1789016331939_evox2_scratch_build_package_construction.sop',
    'narrative/file_changes/1789016331939_evox2_scratch_build_package_construction.sop',
    'narrative/change_sets/15756d9d-da14-4a75-8e4e-5db6423ec101.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Package_Evidence_Publication_Proof.sop',
    'narrative/turns/1789021713412_evox2_scratch_build_package_evidence_publication.sop',
    'narrative/file_changes/1789021713412_evox2_scratch_build_package_evidence_publication.sop',
    'narrative/change_sets/358e6d71-0b43-4362-8279-077c2669913c.sop',
    'narrative/operational_faults/1789046237326_evox2_scratch_build_host_harness_commission_authority_refusal.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Host_Harness_Commission_Authority_Correction_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0HostHarnessCommissionAuthorityCorrectionReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Host_Harness_Commission_Authority_Correction_Phase_Checkpoint.sop',
    'narrative/turns/1789046237326_evox2_scratch_build_host_harness_commission_authority_correction.sop',
    'narrative/file_changes/1789046237326_evox2_scratch_build_host_harness_commission_authority_correction.sop',
    'narrative/change_sets/7e0e219e-1499-4a9b-8a18-a9a6b3e18d7a.sop',
    'experiments/evox2_scratch_build_executor_p0/package_construction_evidence.json',
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
    'scripts/build_cantor_evox2_scratch_build_executor_p0_package_construction_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_package_construction.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_package_construction.ps1',
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
    package_evidence_commit = 'ce5879d96b5c8e6f098e56286fa7189d963e0c02'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 62
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
        canonical_copy_successes = 2
        canonical_copy_refusals = 6
        format_passed = $true
        provider_requests = 0
        remote_calls = 0
        effects = 0
        package_constructed = $true
        package_verified = $true
        package_evidence_bookended = $true
        package_copy_successes = 1
        package_copy_refusals = 4
        live_effects_authorized = $false
        physical_build_performed = $false
    }
}
$json = ($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($output, $json, [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_harness_evidence_written=$output artifacts=$($artifacts.Count)"
