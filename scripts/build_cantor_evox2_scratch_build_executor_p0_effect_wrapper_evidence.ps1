[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $ExactGatesPassed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\effect_wrapper_implementation_evidence_manifest.json'
$paths = @(
    'source_documents/2026-09-10_evox2_scratch_build_effect_wrapper/EVO_X2_Scratch_Build_Effect_Wrapper_Source.sop',
    'source_documents/2026-09-11_evox2_scratch_build_live_preflight_observation/EVO_X2_Scratch_Build_Live_Preflight_Observation_Source.sop',
    'source_documents/2026-09-11_evox2_scratch_build_live_preflight_observation/Source_Document_Manifest.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Effect_Wrapper_Design_2026-09-10.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Live_Preflight_Observation_Design_2026-09-11.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'crates/cantor_core/src/evox2_scratch_build_deployment_controller.rs',
    'crates/cantor_core/src/evox2_scratch_build_deployment_effect.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-live-evidence-verify.rs',
    'crates/cantor_core/tests/evox2_scratch_build_deployment_effect.rs',
    'experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json',
    'experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json',
    'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json',
    'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/initial_state.json',
    'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/preflight_refusal.json',
    'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/operational_refusal.json',
    'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/refusal_verification.json',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Effect_Wrapper_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildExecutorP0EffectWrapperReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Effect_Wrapper_Phase_Checkpoint.sop',
    'narrative/turns/1789069911817_evox2_scratch_build_effect_wrapper_slice.sop',
    'narrative/file_changes/1789069911817_evox2_scratch_build_effect_wrapper_slice.sop',
    'narrative/change_sets/d63b15fd-f9ba-4d9e-b12f-088bc582c8b3.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Executor_P0_Effect_Wrapper_Publication_Proof.sop',
    'narrative/turns/1789088727746_evox2_scratch_build_effect_wrapper_publication.sop',
    'narrative/file_changes/1789088727746_evox2_scratch_build_effect_wrapper_publication.sop',
    'narrative/change_sets/edad6e13-7683-4628-99aa-728855d6daaa.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Live_Preflight_Observation_Compiler_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildLivePreflightObservationCompilerReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Live_Preflight_Observation_Compiler_Checkpoint.sop',
    'narrative/turns/1789129182211_evox2_scratch_build_live_preflight_observation_start.sop',
    'narrative/turns/1789135056011_evox2_scratch_build_live_preflight_observation_compiler.sop',
    'narrative/file_changes/1789135056011_evox2_scratch_build_live_preflight_observation_compiler.sop',
    'narrative/change_sets/6705d035-61fa-49fe-b88c-59aee5da1cbe.sop',
    'scripts/build_cantor_evox2_scratch_build_executor_p0_effect_wrapper_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_executor_p0_effect_wrapper_evidence.ps1',
    'scripts/test_cantor_evox2_scratch_build_executor_p0_effect_wrapper_evidence.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "effect-wrapper artifact boundary differs: $relative" }
    [ordered]@{
        path = $relative
        bytes = [int64] $item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-scratch-build-effect-wrapper-evidence/0.1'
    manifest_uuid = 'c93d6b10-1b6a-4762-9cba-b56249f25b45'
    canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
    controller_implementation_commit = 'c0fd8175a6fba0f61a53868b2660bc361dadb96c'
    controller_publication_bookend = 'e153c9f60f04c76ef85c77a068106d747774ad47'
    package_set_sha256 = 'fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 42
        focused_tests = 18
        stage_count = 10
        effectful_stage_count = 7
        checked_fixture_forms = 5
        observation_compiler_cases = 10
        isolated_successes = 1
        isolated_refusals = 5
        provider_requests = 0
        remote_calls = 0
        remote_contact_authorized = $false
        execution_authorized = $false
        evidence_is_fixture = $true
        exact_workspace_gates_passed = [bool] $ExactGatesPassed
        effects = 0
    }
}
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_effect_wrapper_evidence_written=$output artifacts=$($artifacts.Count) exact_gates=$([bool] $ExactGatesPassed)"
