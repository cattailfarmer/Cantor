[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_review_admission_p0/artifacts/succeeding_sop_review_admission_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_review_admission_p0/artifacts/controlled_provider_free_verification.json'
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
    profile = 'cantor-succeeding-sop-review-admission-controlled-verification/0.1'
    evidence_uuid = '981398a2-3dc4-4a46-b675-fda1c0db97e8'
    source_commit = $sourceCommit
    status = 'provider_free_review_signature_admission_verified'
    implementation = [ordered]@{
        request_profile = 'cantor-succeeding-sop-review-admission-request/0.1'
        receipt_profile = 'cantor-succeeding-sop-review-admission-receipt/0.1'
        satisfaction_signature_protocol_uuid = 'ad10f10f-d506-48ef-a805-f8b0a133766c'
        status = 'cryptographically_verified_awaiting_physical_activation'
        authority = 'review_signature_correspondence_only'
    }
    focused = [ordered]@{
        wsl_debug_passed = 35
        wsl_overflow_checked_release_passed = 35
        new_SWA_06B1_tests = 9
        reused_predecessor_tests = 26
        failed = 0
    }
    workspace = [ordered]@{
        debug_result_groups = 196
        debug_passed = 1222
        debug_failed = 0
        debug_ignored = 3
        debug_transcript_bytes = 23419
        debug_transcript_sha256 = 'C9FDB5091CF2521E22B213490B3E9AC1746E0E114425F4D74F0D023CC243BFAA'
        release_result_groups = 196
        release_passed = 1222
        release_failed = 0
        release_ignored = 3
        release_transcript_bytes = 23409
        release_transcript_sha256 = '52CDFC03C294F05799B2C4D4A30EF34066FA7478E6EE34CA29B520E945EF7B7C'
    }
    boundaries = [ordered]@{
        provider_contacted = $false
        model_called = $false
        semantic_review_performed = $false
        policy_governance_proved = $false
        semantic_truth_proved = $false
        signing_key_in_production = $false
        signature_issued_by_product = $false
        source_read_or_written_by_product = $false
        sop_persisted = $false
        sop_activated = $false
        physical_activation_eligible = $false
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
    'crates/cantor_core/src/bin/cantor-succeeding-sop-review-admission.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/succeeding_sop_review_admission.rs',
    'crates/cantor_core/tests/succeeding_sop_proposal.rs',
    'crates/cantor_core/tests/succeeding_sop_review_admission.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/succeeding_sop_review_admission_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Succeeding_SOP_Review_Admission_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPReviewAdmissionP0CompletionReview.sop',
    'feature_support/reviews/SucceedingSOPReviewAdmissionP0SignatureReadinessReview.sop',
    'justifications/Cantor_Succeeding_SOP_Review_Admission_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/change_sets/72261d8f-0693-468b-ab15-c6fce79af0bf.sop',
    'narrative/change_sets/72261d8f-0693-468b-ab15-c6fce79af0bf_staged_inventory.sop',
    'narrative/file_changes/1787642092066_cantor_succeeding_sop_review_admission_p0_source_file_change.sop',
    'narrative/file_changes/1787649141057_cantor_succeeding_sop_review_admission_p0_completion_file_change.sop',
    'narrative/operational_faults/1787644618790_succeeding_sop_review_admission_transitive_evidence_ordering_fault.sop',
    'narrative/operational_faults/1787649141057_succeeding_sop_review_admission_wsl_transport_fault.sop',
    'narrative/operational_faults/1787649490496_succeeding_sop_review_admission_evidence_nonauthority_wording_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Review_Admission_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Review_Admission_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Succeeding_SOP_Review_Admission_P0_Data_Design_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Review_Admission_P0_Input_Audit_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Review_Admission_P0_Seven_Fold_Exhaustion_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Review_Admission_P0_Threat_Review_2026-08-25.sop',
    'narrative/turns/1787642092066_cantor_succeeding_sop_review_admission_p0_source.sop',
    'narrative/turns/1787644618790_cantor_succeeding_sop_review_admission_transitive_evidence_correction.sop',
    'narrative/turns/1787649141057_cantor_succeeding_sop_review_admission_p0_completion.sop',
    'narrative/turns/1787649141057_succeeding_sop_review_admission_wsl_transport_correction.sop',
    'narrative/turns/1787649490496_succeeding_sop_review_admission_evidence_nonauthority_correction.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Succeeding_SOP_Review_Admission_P0_Plan.sop',
    'proofs/Cantor_Succeeding_SOP_Review_Admission_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Review_Admission_P0_Implementation_Proof.sop',
    'scripts/build_cantor_succeeding_sop_review_admission_evidence.ps1',
    'scripts/test_cantor_succeeding_sop_review_admission.ps1',
    'scripts/test_cantor_succeeding_sop_review_admission_evidence.ps1',
    'scripts/verify_cantor_succeeding_sop_review_admission_evidence.ps1',
    'solutions/Cantor_Succeeding_SOP_Review_Admission_P0_Solution.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_review_admission_p0/Cantor_Succeeding_SOP_Review_Admission_P0_Source.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_review_admission_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Succeeding_SOP_Review_Admission_P0.sop',
    'specifications/exploded/Cantor_Succeeding_SOP_Review_Admission_P0.exploded.sop'
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
    profile = 'cantor-succeeding-sop-review-admission-evidence-manifest/0.1'
    evidence_manifest_uuid = '3ad46486-55fb-4f52-b89b-d6d5eb752192'
    canonical_uuid = 'ff7c9404-2676-4c41-ae98-419445b6ec45'
    source_snapshot_uuid = '5755947d-04e7-41b9-9373-691541a1b5de'
    satisfaction_signature_uuid = 'a3f20717-42b2-47e5-a186-2f03a30d0883'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    focused_verification = [ordered]@{
        wsl_debug_passed = 35
        wsl_overflow_checked_release_passed = 35
        new_SWA_06B1_tests = 9
        warnings_denied_clippy = 'passed'
        format = 'passed'
    }
    workspace_verification = [ordered]@{
        debug = [ordered]@{ result_groups = 196; passed = 1222; failed = 0; ignored = 3; transcript_sha256 = 'C9FDB5091CF2521E22B213490B3E9AC1746E0E114425F4D74F0D023CC243BFAA' }
        overflow_checked_release = [ordered]@{ result_groups = 196; passed = 1222; failed = 0; ignored = 3; transcript_sha256 = '52CDFC03C294F05799B2C4D4A30EF34066FA7478E6EE34CA29B520E945EF7B7C' }
    }
    non_authority_statement = 'This manifest proves only deterministic provider-free verification of a supplied SWA-06A receipt source-preservation record reviewer policy semantic-review payload and detached Ed25519 satisfaction signature. It proves no semantic review, no semantic truth, no policy governance, no reviewer competence, no freshness, no physical source custody, no SOP persistence, no SOP activation, no current-state selection, no provider or model contact, no signing-key custody, no signature issuance, no workspace mutation, no remote access, no FPGA authority, no Minecraft authority, and no external-effect authority.'
}
$manifestFull = Resolve-Output $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFull)) | Out-Null
$manifestJson = ($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestFull, "$manifestJson`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFull
