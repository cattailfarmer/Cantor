param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$relativePaths = @(
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_evidence_manifest.json',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Pure_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightOneShotActivationCeremonyP0PureImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Pure_Implementation_Checkpoint.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Pure_Implementation_Publication_Proof.sop',
    'narrative/turns/1789168600000_evox2_remote_preflight_activation_pure_implementation_publication.sop',
    'narrative/file_changes/1789168600000_evox2_remote_preflight_activation_pure_implementation_publication.sop',
    'narrative/change_sets/d3a63df5-1497-43e7-95bc-9668cad40c48.sop',
    'scripts/build_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_publication_evidence.ps1',
    'scripts/verify_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_publication_evidence.ps1',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop'
)
$artifacts = @()
foreach ($relative in $relativePaths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "activation publication artifact boundary differs: $relative" }
    $artifacts += [ordered]@{ path=$relative; bytes=[int64]$item.Length; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-implementation-publication-evidence/0.1'
    manifest_uuid = 'df10f5c4-a4be-4a67-bf6a-8cbb64944f8a'
    canonical_uuid = 'd2724a39-56bd-47ae-8787-064a6196dbfb'
    publication_proof_uuid = 'f7255ff3-9433-43cb-8c5c-211f8dd2635f'
    implementation_commit = '2726ea188b93e70ab8da48d77ec7c43278b64238'
    implementation_parent = '169c7720914b53c7800293f8352e1ede84846013'
    branch = 'codex/self-hosted-corpus'
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count=14
        implementation_remote_equal=$true
        exact_workspace_gates_passed=$true
        workspace_result_groups=325
        workspace_tests_passed=1975
        workspace_tests_failed=0
        workspace_tests_ignored=22
        provider_requests=0
        remote_calls=0
        effects=0
        permits_minted=0
        runner_invocations=0
        live_authority_created=$false
        bridge_formation_eligible_after_bookend=$true
        live_invocation_authorized=$false
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_publication_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 20 -Compress)), [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_activation_implementation_publication_evidence_built=true artifacts=$($artifacts.Count)"
