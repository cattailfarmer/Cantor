param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$relativePaths = @(
    'source_documents/2026-09-11_evox2_remote_preflight_one_shot_activation_ceremony/EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_Source.sop',
    'source_documents/2026-09-11_evox2_remote_preflight_one_shot_activation_ceremony/Source_Document_Manifest.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Input_Audit_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Requirements_Analysis_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Constraint_Ledger_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Delineation_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Dual_Hemisphere_Review_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Data_Design_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Threat_Review_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Seven_Fold_Exhaustion_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Design_2026-09-11.sop',
    'specifications/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0.sop',
    'specifications/exploded/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0.exploded.sop',
    'justifications/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Justification.sop',
    'solutions/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Solution.sop',
    'plans/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Plan.sop',
    'feature_support/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightOneShotActivationCeremonyP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Satisfaction_Signature.sop'
)
$artifacts = @()
foreach ($relative in $relativePaths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "linked artifact $relative" }
    $artifacts += [ordered]@{
        path = $relative
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-formation-evidence/0.1'
    canonical_uuid = 'd2724a39-56bd-47ae-8787-064a6196dbfb'
    source_snapshot_uuid = 'e4929ffa-1c10-451e-ad4d-ddbccc992c52'
    formation_signature_uuid = '1feeedea-716a-4b47-ac28-d7e5b7045842'
    predecessor_bookend = '0674395c78a998ce1c36c714e52bae68d0f83f58'
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = 21
        signature_binding_count = 20
        requirements = 24
        acceptance = 5
        profiles = 6
        roles = 8
        stages = 8
        argument_atoms = 19
        timeout_millis = 30000
        maximum_stdout_bytes = 65536
        maximum_stderr_bytes = 65536
        maximum_attempts = 1
        maximum_permits = 1
        maximum_active_processes = 1
        maximum_total_processes = 1
        retry_count = 0
        formation_permits_minted = 0
        formation_runner_invocations = 0
        provider_requests = 0
        remote_calls = 0
        effects = 0
        synthetic_trials = 0
        work_slice_language_is_operator_decision = $false
        formation_publication_is_operator_decision = $false
        fixture_success_is_operator_decision = $false
        permit_consumed_before_runner = $true
        permit_returned_after_failure = $false
        terminal_has_outgoing_edge = $false
        pure_implementation_only_after_bookend = $true
        permit_bridge_authorized_by_formation = $false
        live_invocation_authorized_by_formation = $false
        target_host = 'EVO-X2'
        ssh_host = 'evo-x2'
        executable_path = 'C:/Windows/System32/OpenSSH/ssh.exe'
        runner_implementation_commit = '0eb334670d825ea7123beb445df1a47e1bc81349'
        runner_bookend_commit = '0674395c78a998ce1c36c714e52bae68d0f83f58'
        producer_implementation_commit = '606588a6dd542b31816d116abf909f50d0881937'
        producer_bookend_commit = 'b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'
        controller_request_sha256 = 'e7dffae6d82cda84e9dd13d77d7d95ba2e403561e511dc7bfb9299b25ae79c8d'
        controller_plan_sha256 = '975e1dc17d8f0b678f76c5f8d74bb795c3f09b3cff31a57a0c3af29b39981c97'
        controller_program_sha256 = 'b8a832656aa3739ac87daffa81858b184b2eddf8c849d2a7f439926611521992'
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_evidence_manifest.json'
$parent = Split-Path -Parent $output
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$json = $manifest | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($output, $json, [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_formation_evidence_built=true artifacts=$($artifacts.Count)"
