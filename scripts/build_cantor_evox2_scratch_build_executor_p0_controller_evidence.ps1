[CmdletBinding()]
param([string] $Root = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\controller_implementation_evidence_manifest.json'
$paths = @(
    'specifications/Cantor_EVO_X2_Scratch_Build_Executor_P0.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Deployment_Controller_Design_2026-09-10.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'crates/cantor_core/src/evox2_scratch_build_deployment_controller.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-deployment-plan.rs',
    'crates/cantor_core/tests/evox2_scratch_build_deployment_controller.rs',
    'experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json',
    'experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json',
    'experiments/evox2_scratch_build_executor_p0/controller_fixture/verification.json',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Deployment_Controller_Plan_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0DeploymentControllerPlanReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Deployment_Controller_Plan_Phase_Checkpoint.sop',
    'narrative/operational_faults/1789060055939_evox2_scratch_build_deployment_controller_plan_faults.sop',
    'narrative/turns/1789058506094_evox2_scratch_build_deployment_controller_plan.sop',
    'narrative/file_changes/1789058506094_evox2_scratch_build_deployment_controller_plan.sop',
    'narrative/change_sets/0d220612-23c1-41f1-8eb8-c9494e8fa382.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Deployment_Controller_Plan_Publication_Proof.sop',
    'narrative/turns/1789069105064_evox2_scratch_build_deployment_controller_plan_publication.sop',
    'narrative/file_changes/1789069105064_evox2_scratch_build_deployment_controller_plan_publication.sop',
    'narrative/change_sets/2e36c689-4a38-4eb4-bbaf-58af476858a1.sop',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_controller_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_controller_evidence.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_controller_evidence.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "controller artifact boundary differs: $relative" }
    [ordered]@{
        path = $relative
        bytes = [int64] $item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-scratch-build-deployment-controller-evidence/0.1'
    manifest_uuid = '3bca5072-b945-4861-85ba-542e097f64ec'
    canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
    package_evidence_commit = '4dc154234cd88c192495126a4374d74616ca0c3f'
    package_evidence_bookend_commit = '9e583948ea6c1f52604862c354e99d8ccb1195ba'
    package_implementation_commit = 'f5b904fc8cf48b34672dead0596e9de6e706f38b'
    package_set_sha256 = 'fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e'
    controller_implementation_commit = 'c0fd8175a6fba0f61a53868b2660bc361dadb96c'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 28
        focused_tests = 8
        stage_count = 10
        effectful_stage_count = 7
        isolated_successes = 1
        isolated_refusals = 4
        provider_requests = 0
        remote_calls = 0
        remote_contact_authorized = $false
        controller_plan_published = $true
        controller_plan_bookended = $true
        effect_wrapper_implementation_authorized = $true
        effects = 0
    }
}
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_controller_evidence_written=$output artifacts=$($artifacts.Count)"
