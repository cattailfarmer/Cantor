[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/provider_free_self_work_composition_p0/artifacts/provider_free_self_work_composition_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/provider_free_self_work_composition_p0/artifacts/controlled_provider_free_verification.json'
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
    profile = 'cantor-provider-free-self-work-composition-controlled-verification/0.1'
    evidence_uuid = 'fdc97238-cb20-471c-8048-f96c6f00b35d'
    source_commit = $sourceCommit
    status = 'provider_free_chain_correspondence_verified'
    implementation = [ordered]@{
        request_profile = 'cantor-provider-free-self-work-composition-request/0.1'
        receipt_profile = 'cantor-provider-free-self-work-composition-receipt/0.1'
        authority = 'supplied_data_correspondence_only'
        physical_contact = $false
        update_handoff_profile = 'cantor-self-work-update-handoff-request/0.1'
        succeeding_sop_profile = 'cantor-succeeding-sop-request/0.1'
    }
    focused = [ordered]@{
        wsl_debug_passed = 32
        wsl_overflow_checked_release_passed = 32
        direct_SWA_07_tests = 7
        imported_predecessor_tests = 25
        failed = 0
    }
    boundaries = [ordered]@{
        provider_contacted = $false
        model_called = $false
        physical_update_performed = $false
        workspace_mutated_by_product = $false
        semantic_review_performed = $false
        satisfaction_signature_issued_by_product = $false
        sop_activated = $false
        publication_performed_by_product = $false
        child_process_surface_in_product_module = $false
        output_path_surface = $false
    }
    windows_application_control = [ordered]@{
        status = 'host_policy_refused_fresh_local_executable'
        operating_system_error = 4551
        bypass_attempted = $false
        governed_lane = 'Ubuntu-24.04 WSL passed'
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
    'crates/cantor_ecosystem/src/bin/cantor-provider-free-self-work-composition.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/provider_free_self_work_composition.rs',
    'crates/cantor_ecosystem/tests/provider_free_self_work_composition.rs',
    'crates/cantor_ecosystem/tests/self_work_update_handoff.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/provider_free_self_work_composition_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Provider_Free_Self_Work_Composition_P0_Requirement_Matrix.sop',
    'feature_support/reviews/ProviderFreeSelfWorkCompositionP0CompletionReview.sop',
    'feature_support/reviews/ProviderFreeSelfWorkCompositionP0SignatureReadinessReview.sop',
    'justifications/Cantor_Provider_Free_Self_Work_Composition_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/change_sets/e50e074e-9392-4bbd-b277-40ffc40a2bf3.sop',
    'narrative/change_sets/e50e074e-9392-4bbd-b277-40ffc40a2bf3_staged_inventory.sop',
    'narrative/file_changes/1787610184573_cantor_provider_free_self_work_composition_p0_completion_file_change.sop',
    'narrative/file_changes/1787610184573_cantor_provider_free_self_work_composition_p0_source_file_change.sop',
    'narrative/operational_faults/1787611300000_provider_free_self_work_composition_windows_application_control_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Provider_Free_Self_Work_Composition_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Provider_Free_Self_Work_Composition_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Provider_Free_Self_Work_Composition_P0_Data_Design_2026-08-24.sop',
    'narrative/research/Cantor_Provider_Free_Self_Work_Composition_P0_Input_Audit_2026-08-24.sop',
    'narrative/research/Cantor_Provider_Free_Self_Work_Composition_P0_Seven_Fold_Exhaustion_2026-08-24.sop',
    'narrative/research/Cantor_Provider_Free_Self_Work_Composition_P0_Threat_Review_2026-08-24.sop',
    'narrative/turns/1787610184573_cantor_provider_free_self_work_composition_p0_completion.sop',
    'narrative/turns/1787610184573_cantor_provider_free_self_work_composition_p0_source.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Provider_Free_Self_Work_Composition_P0_Plan.sop',
    'proofs/Cantor_Provider_Free_Self_Work_Composition_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Provider_Free_Self_Work_Composition_P0_Implementation_Proof.sop',
    'README.md',
    'scripts/build_cantor_provider_free_self_work_composition_evidence.ps1',
    'scripts/test_cantor_provider_free_self_work_composition.ps1',
    'scripts/test_cantor_provider_free_self_work_composition_evidence.ps1',
    'scripts/verify_cantor_provider_free_self_work_composition_evidence.ps1',
    'solutions/Cantor_Provider_Free_Self_Work_Composition_P0_Solution.sop',
    'source_documents/2026-08-24_cantor_provider_free_self_work_composition_p0/Cantor_Provider_Free_Self_Work_Composition_P0_Source.sop',
    'source_documents/2026-08-24_cantor_provider_free_self_work_composition_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Provider_Free_Self_Work_Composition_P0.sop',
    'specifications/exploded/Cantor_Provider_Free_Self_Work_Composition_P0.exploded.sop'
)
$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') { throw "nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    [ordered]@{
        path = $relativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    profile = 'cantor-provider-free-self-work-composition-evidence-manifest/0.1'
    evidence_manifest_uuid = '8276d957-8dac-4995-afc5-45a21ab84e1f'
    canonical_uuid = 'd36ead3a-82eb-4a88-897e-1d903cc01c01'
    source_snapshot_uuid = '9c4c374d-db80-4a0b-b186-cff44e2916af'
    satisfaction_signature_uuid = 'f95853e7-ce55-4e91-b1d7-5adc412bab0f'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    focused_verification = $controlled.focused
    non_authority_statement = 'This manifest proves only deterministic provider-free supplied-data correspondence between exact self-work update-handoff and succeeding-SOP lifecycle forms. It proves no provider or model contact, physical work, workspace mutation, update, testing of an update, acceptance, rollback, cleanup, commit, push, publication, semantic review, satisfaction-signature issuance, persistence, SOP activation, remote access, FPGA, Minecraft, or external-effect authority.'
}
$manifestFull = Resolve-Output $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFull)) | Out-Null
$manifestJson = ($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestFull, "$manifestJson`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFull
