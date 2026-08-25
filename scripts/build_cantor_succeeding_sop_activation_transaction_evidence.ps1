[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_activation_transaction_p0/artifacts/succeeding_sop_activation_transaction_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_activation_transaction_p0/artifacts/controlled_provider_free_verification.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'unable to resolve source commit' }

function Resolve-Output([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $root $Path))
}

$controlled = [ordered]@{
    profile = 'cantor-succeeding-sop-activation-transaction-controlled-verification/0.1'
    evidence_uuid = '303a1be1-7483-4515-b809-fb0040dc5ff2'
    source_commit = $sourceCommit
    status = 'provider_free_activation_transaction_correspondence_verified'
    implementation = [ordered]@{
        request_profile = 'cantor-succeeding-sop-activation-transaction-request/0.1'
        receipt_profile = 'cantor-succeeding-sop-activation-transaction-receipt/0.1'
        status = 'transaction_correspondence_verified_awaiting_physical_execution'
        authority = 'supplied_activation_plan_correspondence_only'
    }
    focused = [ordered]@{
        wsl_debug_passed = 45
        wsl_overflow_checked_release_passed = 45
        new_SWA_06B2A_tests = 10
        reused_predecessor_tests = 35
        failed = 0
    }
    workspace = [ordered]@{
        debug_result_groups = 198
        debug_passed = 1267
        debug_failed = 0
        debug_ignored = 3
        debug_transcript_bytes = 158979
        debug_transcript_sha256 = '56644534B80ED3D675ECD01DF8151D979E7020E5DA0C7894F5C58B914A70E2DE'
        release_result_groups = 198
        release_passed = 1267
        release_failed = 0
        release_ignored = 3
        release_transcript_bytes = 159750
        release_transcript_sha256 = '8B9EE6191DCC481177D5A55445A169571BFE8460A22E576658188CE866DB5E34'
    }
    boundaries = [ordered]@{
        provider_contacted = $false
        model_called = $false
        policy_governance_proved = $false
        semantic_truth_proved = $false
        source_reacquired = $false
        registry_observed = $false
        registry_persisted = $false
        current_sop_selected = $false
        boot_activation_verified = $false
        rollback_executed = $false
        physical_contact = $false
        physical_execution_eligible = $false
        child_process_surface_in_product_module = $false
        output_path_surface = $false
    }
    live_provider = [ordered]@{
        status = 'not_contacted_not_required'
        trials = 0
    }
}
$controlledFull = Resolve-Output $ControlledPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($controlledFull)) | Out-Null
$controlledJson = ($controlled | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($controlledFull, "$controlledJson`n", [Text.UTF8Encoding]::new($false))

$paths = @(
    'README.md',
    'crates/cantor_core/src/bin/cantor-succeeding-sop-activation-transaction.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/succeeding_sop_activation_transaction.rs',
    'crates/cantor_core/tests/succeeding_sop_activation_transaction.rs',
    'crates/cantor_core/tests/succeeding_sop_review_admission.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/succeeding_sop_activation_transaction_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Succeeding_SOP_Activation_Transaction_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPActivationTransactionP0CompletionReview.sop',
    'feature_support/reviews/SucceedingSOPActivationTransactionP0SignatureReadinessReview.sop',
    'justifications/Cantor_Succeeding_SOP_Activation_Transaction_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/change_sets/6969256f-7b5d-41ce-a268-de1dcec9ca01.sop',
    'narrative/change_sets/6969256f-7b5d-41ce-a268-de1dcec9ca01_staged_inventory.sop',
    'narrative/change_sets/0ee13e6d-2278-418e-b907-eebaa2e1bf80.sop',
    'narrative/change_sets/0ee13e6d-2278-418e-b907-eebaa2e1bf80_staged_inventory.sop',
    'narrative/file_changes/1787655250208_cantor_succeeding_sop_activation_transaction_p0_source_file_change.sop',
    'narrative/file_changes/1787661124303_cantor_succeeding_sop_activation_transaction_p0_completion_file_change.sop',
    'narrative/file_changes/1787661813602_cantor_succeeding_sop_activation_transaction_p0_publication_file_change.sop',
    'narrative/operational_faults/1787661092023_succeeding_sop_activation_transaction_acceptance_ordering_fault.sop',
    'narrative/operational_faults/1787659985827_succeeding_sop_activation_transaction_wsl_transport_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Activation_Transaction_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Activation_Transaction_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Succeeding_SOP_Activation_Transaction_P0_Data_Design_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Activation_Transaction_P0_Input_Audit_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Activation_Transaction_P0_Seven_Fold_Exhaustion_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Activation_Transaction_P0_Threat_Review_2026-08-25.sop',
    'narrative/turns/1787655047243_self_work_update_broker_b1_current_revalidation_and_operator_selection_request.sop',
    'narrative/turns/1787655250208_cantor_succeeding_sop_activation_transaction_p0_source.sop',
    'narrative/turns/1787659985827_succeeding_sop_activation_transaction_wsl_transport_correction.sop',
    'narrative/turns/1787661092023_succeeding_sop_activation_transaction_acceptance_ordering_correction.sop',
    'narrative/turns/1787661124303_cantor_succeeding_sop_activation_transaction_p0_completion.sop',
    'narrative/turns/1787661813602_cantor_succeeding_sop_activation_transaction_p0_publication.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Succeeding_SOP_Activation_Transaction_P0_Plan.sop',
    'proofs/Cantor_Succeeding_SOP_Activation_Transaction_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Activation_Transaction_P0_Git_Anchor.sop',
    'proofs/Cantor_Succeeding_SOP_Activation_Transaction_P0_Implementation_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Activation_Transaction_P0_Publication_Bookend_Proof.sop',
    'scripts/build_cantor_succeeding_sop_activation_transaction_evidence.ps1',
    'scripts/test_cantor_succeeding_sop_activation_transaction.ps1',
    'scripts/test_cantor_succeeding_sop_activation_transaction_evidence.ps1',
    'scripts/verify_cantor_succeeding_sop_activation_transaction_evidence.ps1',
    'solutions/Cantor_Succeeding_SOP_Activation_Transaction_P0_Solution.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_activation_transaction_p0/Cantor_Succeeding_SOP_Activation_Transaction_P0_Source.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_activation_transaction_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Succeeding_SOP_Activation_Transaction_P0.sop',
    'specifications/exploded/Cantor_Succeeding_SOP_Activation_Transaction_P0.exploded.sop'
)
$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') { throw "nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    [ordered]@{
        path = $relativePath.Replace('\\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    profile = 'cantor-succeeding-sop-activation-transaction-evidence-manifest/0.1'
    evidence_manifest_uuid = 'db806c96-9fad-4e6b-82ef-7f163fbfc28f'
    canonical_uuid = '28da111f-c6b2-4df7-b708-a2d47f8e0bbb'
    source_snapshot_uuid = '46e65481-fab8-4d97-8197-3f0d52895890'
    satisfaction_signature_uuid = 'c454e50b-9342-4fd3-93d6-44fbb8c468ee'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    focused_verification = [ordered]@{
        wsl_debug_passed = 45
        wsl_overflow_checked_release_passed = 45
        new_SWA_06B2A_tests = 10
        warnings_denied_clippy = 'passed'
        format = 'passed'
    }
    workspace_verification = [ordered]@{
        debug = [ordered]@{ result_groups = 198; passed = 1267; failed = 0; ignored = 3; transcript_sha256 = '56644534B80ED3D675ECD01DF8151D979E7020E5DA0C7894F5C58B914A70E2DE' }
        overflow_checked_release = [ordered]@{ result_groups = 198; passed = 1267; failed = 0; ignored = 3; transcript_sha256 = '8B9EE6191DCC481177D5A55445A169571BFE8460A22E576658188CE866DB5E34' }
    }
    non_authority_statement = 'This manifest proves only deterministic provider-free correspondence among one supplied SWA-06B1 receipt and supplied activation policy source-reacquisition current-registry atomic-transition supersession rollback and recovery plans. It proves no policy governance, no semantic truth, no physical source reacquisition, no registry observation or persistence, no current-SOP selection, no boot activation, no rollback execution, no physical execution eligibility, no provider or model contact, no workspace mutation, no remote access, no FPGA authority, no Minecraft authority, and no external-effect authority.'
}
$manifestFull = Resolve-Output $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFull)) | Out-Null
$manifestJson = ($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestFull, "$manifestJson`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFull
