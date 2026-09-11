[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $ExactGatesPassed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$paths = @(
    'source_documents/2026-09-11_evox2_scratch_build_remote_preflight_runner/EVO_X2_Scratch_Build_Remote_Preflight_Runner_Source.sop',
    'source_documents/2026-09-11_evox2_scratch_build_remote_preflight_runner/Source_Document_Manifest.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Runner_Design_2026-09-11.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Satisfaction_Signature.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Runner_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildRemotePreflightRunnerImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Runner_Implementation_Checkpoint.sop',
    'narrative/turns/1789147412726_evox2_scratch_build_remote_preflight_runner_start.sop',
    'narrative/turns/1789149304860_evox2_scratch_build_remote_preflight_runner_implementation.sop',
    'narrative/file_changes/1789149304860_evox2_scratch_build_remote_preflight_runner_implementation.sop',
    'narrative/change_sets/f68ed6ce-3beb-40bb-93fa-29030bf681b5.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Runner_Publication_Proof.sop',
    'narrative/turns/1789153553322_evox2_scratch_build_remote_preflight_runner_publication.sop',
    'narrative/file_changes/1789153553322_evox2_scratch_build_remote_preflight_runner_publication.sop',
    'narrative/change_sets/59deca10-b7cc-4a9a-8b25-f9eb7c57ff83.sop',
    'narrative/operational_faults/1789147610000_evox2_remote_preflight_runner_fixture_compile_fault.sop',
    'narrative/operational_faults/1789149000000_evox2_remote_preflight_runner_wsl_inherited_clippy_fault.sop',
    'narrative/operational_faults/1789149450000_evox2_remote_preflight_runner_powershell_exitcode_fault.sop',
    'narrative/operational_faults/1789153720029_evox2_remote_preflight_runner_publication_dependency_order_fault.sop',
    'crates/cantor_ecosystem/src/evox2_scratch_build_remote_preflight_runner.rs',
    'crates/cantor_ecosystem/src/self_work_update_broker_b1_cdrive_windows_containment.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_core/src/evox2_scratch_build_remote_preflight_producer.rs',
    'scripts/build_cantor_evox2_scratch_build_remote_preflight_runner_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_remote_preflight_runner_evidence.ps1',
    'scripts/test_cantor_evox2_scratch_build_remote_preflight_runner_evidence.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "runner artifact boundary differs: $relative" }
    [ordered]@{ path = $relative; bytes = [int64] $item.Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-scratch-build-remote-preflight-runner-evidence/0.1'
    manifest_uuid = '4345ae52-665c-4b7d-95b7-3dfefe565e44'
    source_uuid = '476bf430-ae3a-4f69-8116-b5461803604b'
    design_uuid = '8b60c955-8358-481c-aa57-0901a925fd69'
    predecessor_bookend = 'b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'
    producer_implementation_commit = '606588a6dd542b31816d116abf909f50d0881937'
    producer_bookend_commit = 'b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 31
        focused_tests = 10
        argument_atoms = 19
        timeout_ms = 30000
        stream_limit_bytes = 65536
        maximum_active_processes = 1
        maximum_total_processes = 1
        public_permit_constructors = 0
        invocation_binaries = 0
        provider_requests_performed = 0
        remote_calls_performed = 0
        effects_performed = 0
        live_invocations_performed = 0
        exact_workspace_gates_passed = [bool] $ExactGatesPassed
    }
}
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_runner_implementation_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_remote_preflight_runner_evidence_written=$output artifacts=$($artifacts.Count) exact_gates=$([bool] $ExactGatesPassed)"
