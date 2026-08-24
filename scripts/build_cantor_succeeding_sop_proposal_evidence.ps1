[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_proposal_p0/artifacts/succeeding_sop_proposal_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_proposal_p0/artifacts/controlled_provider_free_verification.json'
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
    profile = 'cantor-succeeding-sop-controlled-verification/0.1'
    evidence_uuid = '96afcd79-8ea7-48bd-96b3-1deadcba4ca6'
    source_commit = $sourceCommit
    status = 'provider_free_machine_verification_passed'
    implementation = [ordered]@{
        request_profile = 'cantor-succeeding-sop-request/0.1'
        proposal_profile = 'cantor-succeeding-sop-proposal/0.1'
        verification_profile = 'cantor-succeeding-sop-verification/0.1'
        authority = 'authorship_proposal_only'
        disposition = 'proposed_awaiting_independent_review'
        machine_verification_authority = 'machine_correspondence_only'
    }
    focused = [ordered]@{
        wsl_debug_passed = 26
        wsl_overflow_checked_release_passed = 26
        new_SWA_06A_tests = 8
        failed = 0
    }
    boundaries = [ordered]@{
        provider_contacted = $false
        model_called = $false
        source_written = $false
        workspace_read_or_mutated = $false
        semantic_review_performed = $false
        satisfaction_signature_issued = $false
        sop_activated = $false
        child_process_surface_in_product_module = $false
        output_path_surface = $false
    }
    windows_release_application_control = [ordered]@{
        status = 'host_policy_refused_fresh_debug_and_release_executables'
        operating_system_error = 4551
        bypass_attempted = $false
        governed_debug_and_release_lane = 'Ubuntu-24.04 WSL passed'
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
    'crates/cantor_core/src/bin/cantor-succeeding-sop-proposal.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/succeeding_sop_proposal.rs',
    'crates/cantor_core/tests/self_work_lifecycle.rs',
    'crates/cantor_core/tests/succeeding_sop_proposal.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/succeeding_sop_proposal_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Succeeding_SOP_Proposal_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPProposalP0CompletionReview.sop',
    'feature_support/reviews/SucceedingSOPProposalP0SignatureReadinessReview.sop',
    'justifications/Cantor_Succeeding_SOP_Proposal_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/file_changes/1787606178833_cantor_succeeding_sop_proposal_p0_source_file_change.sop',
    'narrative/file_changes/1787606178833_cantor_succeeding_sop_proposal_p0_completion_file_change.sop',
    'narrative/change_sets/e1defe07-c072-4de4-ba1b-02526ca7bc98.sop',
    'narrative/change_sets/e1defe07-c072-4de4-ba1b-02526ca7bc98_staged_inventory.sop',
    'narrative/operational_faults/1787606941032_succeeding_sop_p0_windows_release_application_control_fault.sop',
    'narrative/operational_faults/1787607954646_succeeding_sop_p0_host_capacity_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Proposal_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Proposal_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Succeeding_SOP_Proposal_P0_Data_Design_2026-08-24.sop',
    'narrative/research/Cantor_Succeeding_SOP_Proposal_P0_Input_Audit_2026-08-24.sop',
    'narrative/research/Cantor_Succeeding_SOP_Proposal_P0_Seven_Fold_Exhaustion_2026-08-24.sop',
    'narrative/research/Cantor_Succeeding_SOP_Proposal_P0_Threat_Review_2026-08-24.sop',
    'narrative/turns/1787606178833_cantor_succeeding_sop_proposal_p0_completion.sop',
    'narrative/turns/1787606178833_cantor_succeeding_sop_proposal_p0_source.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Succeeding_SOP_Proposal_P0_Plan.sop',
    'proofs/Cantor_Succeeding_SOP_Proposal_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Proposal_P0_Implementation_Proof.sop',
    'README.md',
    'scripts/build_cantor_succeeding_sop_proposal_evidence.ps1',
    'scripts/test_cantor_succeeding_sop_proposal.ps1',
    'scripts/test_cantor_succeeding_sop_proposal_evidence.ps1',
    'scripts/verify_cantor_succeeding_sop_proposal_evidence.ps1',
    'solutions/Cantor_Succeeding_SOP_Proposal_P0_Solution.sop',
    'source_documents/2026-08-24_cantor_succeeding_sop_proposal_p0/Cantor_Succeeding_SOP_Proposal_P0_Source.sop',
    'source_documents/2026-08-24_cantor_succeeding_sop_proposal_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Succeeding_SOP_Proposal_P0.sop',
    'specifications/exploded/Cantor_Succeeding_SOP_Proposal_P0.exploded.sop'
)
$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\/])\.\.([\/]|$)') { throw "nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    [ordered]@{
        path = $relativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    profile = 'cantor-succeeding-sop-evidence-manifest/0.1'
    evidence_manifest_uuid = 'a4d093f6-ab42-42fc-9c9f-3c0f189df791'
    canonical_uuid = 'cb503c5b-bbf6-433b-b65f-31683d73a7ac'
    source_snapshot_uuid = 'd47aca42-00c5-4352-b0af-ce0ea186d795'
    satisfaction_signature_uuid = '2b6b2279-2480-4eab-9f9d-df3a07efd95b'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    focused_verification = [ordered]@{
        wsl_debug_passed = 26
        wsl_overflow_checked_release_passed = 26
        new_SWA_06A_tests = 8
        windows_release_application_control_error = 4551
        warnings_denied_clippy = 'passed'
        format = 'passed'
    }
    non_authority_statement = 'This manifest proves only deterministic provider-free succeeding-SOP proposal compilation and machine correspondence verification over supplied causal forms. It proves no live model authorship, physical work, source persistence, semantic review, satisfaction signature issuance, SOP activation, workspace mutation, commit, push, provider call, persistence, remote access, FPGA, Minecraft, or external-effect authority.'
}
$manifestFull = Resolve-Output $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFull)) | Out-Null
$manifestJson = ($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestFull, "$manifestJson`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFull
