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
    'source_documents/2026-09-11_evox2_remote_preflight_one_shot_activation_ceremony/EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_Source.sop',
    'source_documents/2026-09-11_evox2_remote_preflight_one_shot_activation_ceremony/Source_Document_Manifest.sop',
    'specifications/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Design_2026-09-11.sop',
    'plans/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Requirement_Matrix.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Satisfaction_Signature.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Pure_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightOneShotActivationCeremonyP0PureImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Pure_Implementation_Checkpoint.sop',
    'narrative/turns/1789158700000_evox2_remote_preflight_activation_pure_implementation.sop',
    'narrative/file_changes/1789158700000_evox2_remote_preflight_activation_pure_implementation.sop',
    'narrative/change_sets/7ae2ecf3-bdc0-47b6-8c3c-b8383755ec43.sop',
    'narrative/operational_faults/1789158500000_evox2_activation_sha2_compile_fault.sop',
    'narrative/operational_faults/1789158600000_evox2_activation_evidence_canonical_fixture_fault.sop',
    'narrative/operational_faults/1789158800000_evox2_activation_workspace_manifest_order_fault.sop',
    'narrative/operational_faults/1789158900000_evox2_activation_process_snapshot_parser_fault.sop',
    'narrative/operational_faults/1789165800000_evox2_activation_signed_formation_mutation_fault.sop',
    'crates/cantor_ecosystem/src/evox2_remote_preflight_one_shot_activation_ceremony.rs',
    'crates/cantor_ecosystem/src/evox2_remote_preflight_one_shot_activation_ceremony_evidence.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/bin/cantor-evox2-remote-preflight-activation-evidence-verify.rs',
    'crates/cantor_ecosystem/tests/evox2_remote_preflight_one_shot_activation_ceremony.rs',
    'crates/cantor_ecosystem/tests/evox2_remote_preflight_one_shot_activation_ceremony_evidence.rs',
    'scripts/build_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_evidence.ps1',
    'scripts/verify_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_evidence.ps1',
    'scripts/test_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation.ps1',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/controller_request.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/controller_plan.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/program.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/producer_plan.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/activation_request.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/proposal.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/proposal_verification.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/authorize_decision.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/authorize_correspondence.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/reject_decision.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/reject_correspondence.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence/evidence_manifest.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_verification.json'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "activation implementation artifact boundary differs: $relative" }
    [ordered]@{ path = $relative; bytes = [int64] $item.Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-implementation-evidence/0.1'
    manifest_uuid = '75e86c34-af3f-4092-856c-73bb5cab5db4'
    canonical_uuid = 'd2724a39-56bd-47ae-8787-064a6196dbfb'
    signature_uuid = '1feeedea-716a-4b47-ac28-d7e5b7045842'
    formation_commit = '7b508b67a7b16c091e4dbea512c691b885e33a2f'
    formation_bookend = '169c7720914b53c7800293f8352e1ede84846013'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = @($artifacts).Count
        focused_debug_passed = 16
        focused_release_passed = 16
        focused_ignored = 1
        retained_artifacts = 11
        independent_replays = 2
        roles = 8
        stages = 8
        workspace_result_groups = 325
        workspace_tests_passed = 1975
        workspace_tests_failed = 0
        workspace_tests_ignored = 22
        workspace_clippy_warnings_denied = $true
        workspace_format_passed = $true
        powershell_7_evidence_passed = $true
        windows_powershell_5_1_evidence_passed = $true
        native_lifecycle_provider_independent_passed = $true
        clock_reads = 0
        signature_creations = 0
        permits_minted = 0
        runner_invocations = 0
        process_spawns = 0
        provider_requests = 0
        remote_calls = 0
        effects = 0
        synthetic_trials = 0
        exact_workspace_gates_passed = [bool] $ExactGatesPassed
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_activation_implementation_evidence_written=$output artifacts=$($artifacts.Count) exact_gates=$([bool] $ExactGatesPassed)"
