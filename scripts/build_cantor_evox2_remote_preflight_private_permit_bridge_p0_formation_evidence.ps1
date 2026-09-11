param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$relativePaths = @(
    'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source.sop',
    'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/Source_Document_Manifest.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source_Custody_Proof.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source_Publication_Proof.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Input_Audit_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Requirements_Analysis_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Constraint_Ledger_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Delineation_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Dual_Hemisphere_Review_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Data_Design_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Threat_Review_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Seven_Fold_Exhaustion_2026-09-11.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Design_2026-09-11.sop',
    'specifications/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.sop',
    'specifications/exploded/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.exploded.sop',
    'justifications/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Justification.sop',
    'solutions/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Solution.sop',
    'plans/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Plan.sop',
    'feature_support/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightPrivatePermitBridgeP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Satisfaction_Signature.sop'
)
$artifacts = @()
foreach ($relative in $relativePaths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "private permit bridge formation artifact boundary differs: $relative" }
    $artifacts += [ordered]@{ path=$relative; bytes=[int64]$item.Length; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-private-permit-bridge-formation-evidence/0.1'
    manifest_uuid = 'ff7acb22-f491-491a-9b1e-c0c3a46d7c23'
    canonical_uuid = '06d82d16-143a-4abb-9c70-c03163285842'
    source_snapshot_uuid = '750fbbb5-f72f-4816-882f-d8b0ebf1acc7'
    formation_signature_uuid = '3f7d776d-e012-4efc-9426-d40cf6af7fcb'
    predecessor_bookend = '40b20537cbe8fbd143bb3298ea92ca8b77f46c33'
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count=23; signature_binding_count=22; requirements=24; acceptance=5; bridge_stages=6; terminal_dispositions=4
        maximum_admissions=1; maximum_permit_issuances=1; maximum_permits=1; maximum_runner_entries=1; maximum_processes=1; retry_count=0
        argument_atoms=19; timeout_millis=30000; maximum_stdout_bytes=65536; maximum_stderr_bytes=65536
        formation_permit_constructors=0; formation_permit_issuances=0; formation_runner_invocations=0; process_spawns=0; provider_requests=0; remote_calls=0; effects=0; synthetic_trials=0
        bridge_module_crate_private=$true; bridge_entry_crate_private=$true; runner_issuer_crate_private=$true
        production_admission_constructor_present=$false; public_bridge_export_present=$false; admission_serializable=$false; admission_cloneable=$false; terminal_capability_bearing=$false
        all_pure_validation_before_issuance=$true; admission_consumed_by_issuer=$true; permit_consumed_before_runner=$true; runner_entry_is_fn_once=$true; terminal_has_outgoing_edge=$false
        correspondence_is_live_admission=$false; work_slice_language_is_live_admission=$false; publication_is_invocation_authority=$false
        implementation_eligible_only_after_bookend=$true; live_initiation_authorized_by_formation=$false
        target_host='EVO-X2'; ssh_host='evo-x2'; executable_path='C:/Windows/System32/OpenSSH/ssh.exe'
        activation_implementation_commit='2726ea188b93e70ab8da48d77ec7c43278b64238'; activation_bookend_commit='80f2ef9f6eed3c797b911ba3c7f45e8d28130841'
        runner_implementation_commit='0eb334670d825ea7123beb445df1a47e1bc81349'; runner_bookend_commit='0674395c78a998ce1c36c714e52bae68d0f83f58'
        producer_implementation_commit='606588a6dd542b31816d116abf909f50d0881937'; producer_bookend_commit='b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 20 -Compress)), [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_private_permit_bridge_formation_evidence_built=true artifacts=$($artifacts.Count)"
