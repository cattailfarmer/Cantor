[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_fixture_persistence_p0/artifacts/succeeding_sop_fixture_persistence_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_fixture_persistence_p0/artifacts/controlled_verification.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Resolve-Output([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $root $Path))
}

$controlledFull = Resolve-Output $ControlledPath
$controlled = Get-Content -LiteralPath $controlledFull -Raw | ConvertFrom-Json
if ($controlled.profile -cne 'cantor-succeeding-sop-fixture-persistence-controlled-verification/0.1' -or
    $controlled.evidence_uuid -cne 'd96a8a0f-521b-4b5e-9299-99aff603ff4f' -or
    $controlled.source_commit -cne '8cb80c86f88e5b4cd407a09146f01cabec6766a5' -or
    $controlled.working_tree_basis -cne 'source_commit_plus_exact_owned_swa_06b2b1_delta' -or
    [bool]$controlled.windows.success_receipt -or
    [uint64]$controlled.live_provider.trials -ne 0 -or
    [bool]$controlled.boundaries.provider_contacted -or
    [bool]$controlled.boundaries.model_called -or
    [bool]$controlled.boundaries.externally_governed_activation) {
    throw 'controlled evidence identity or nonauthority boundary differs'
}

$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cne $controlled.source_commit) {
    throw 'HEAD must remain the controlled predecessor while building B2B1 evidence'
}

$paths = @(
    'README.md',
    'crates/cantor_core/Cargo.toml',
    'crates/cantor_core/examples/succeeding_sop_activation_fixture.rs',
    'crates/cantor_core/tests/succeeding_sop_activation_transaction.rs',
    'crates/cantor_core/tests/succeeding_sop_proposal.rs',
    'crates/cantor_core/tests/succeeding_sop_review_admission.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/succeeding_sop_fixture_persistence.rs',
    'crates/cantor_ecosystem/tests/fixtures/succeeding_sop_activation_transaction_receipt.json',
    'crates/cantor_ecosystem/tests/succeeding_sop_fixture_persistence.rs',
    'crates/cantor_ecosystem/tests/succeeding_sop_fixture_persistence_evidence.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/succeeding_sop_fixture_persistence_p0/artifacts/controlled_verification.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPFixturePersistenceP0CompletionReview.sop',
    'feature_support/reviews/SucceedingSOPFixturePersistenceP0SignatureReadinessReview.sop',
    'justifications/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/file_changes/1787693489535_cantor_succeeding_sop_fixture_persistence_p0_source_file_change.sop',
    'narrative/file_changes/1787699000001_cantor_succeeding_sop_fixture_persistence_p0_completion_file_change.sop',
    'narrative/operational_faults/1787694555836_succeeding_sop_fixture_persistence_windows_durability_fault.sop',
    'narrative/operational_faults/1787698000001_succeeding_sop_fixture_generator_test_harness_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Data_Design_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Input_Audit_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Seven_Fold_Exhaustion_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Threat_Review_2026-08-25.sop',
    'narrative/turns/1787693489534_cantor_succeeding_sop_fixture_persistence_p0_source.sop',
    'narrative/turns/1787694555837_succeeding_sop_fixture_persistence_windows_durability_fault.sop',
    'narrative/turns/1787698000002_succeeding_sop_fixture_generator_test_harness_correction.sop',
    'narrative/turns/1787699000000_cantor_succeeding_sop_fixture_persistence_p0_completion.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Plan.sop',
    'proofs/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Implementation_Proof.sop',
    'scripts/build_cantor_succeeding_sop_activation_fixture.ps1',
    'scripts/build_cantor_succeeding_sop_fixture_persistence_evidence.ps1',
    'scripts/test_cantor_succeeding_sop_fixture_persistence.ps1',
    'solutions/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Solution.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_fixture_persistence_p0/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Source.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_fixture_persistence_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Succeeding_SOP_Fixture_Persistence_P0.sop',
    'specifications/exploded/Cantor_Succeeding_SOP_Fixture_Persistence_P0.exploded.sop'
)

$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$artifacts = foreach ($relativePath in $paths) {
    if (-not $seen.Add($relativePath)) { throw "duplicate evidence path: $relativePath" }
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath.Contains('\') -or $relativePath -match '(^|/)(\.|\.\.)(/|$)') {
        throw "nonportable evidence path: $relativePath"
    }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "evidence path is not one physical file: $relativePath"
    }
    [ordered]@{
        path = $relativePath
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

$manifest = [ordered]@{
    profile = 'cantor-succeeding-sop-fixture-persistence-evidence-manifest/0.1'
    evidence_manifest_uuid = '094be7fe-975f-41d8-aec8-e355664a69fc'
    canonical_uuid = 'b87c0711-1151-438e-a2eb-35375e88b134'
    source_snapshot_uuid = '2c60682b-8233-46d0-8dbd-46c7c355b90b'
    satisfaction_signature_uuid = '7c3952ad-e4fd-4a99-9f88-96ccf182be25'
    source_commit = $controlled.source_commit
    working_tree_basis = $controlled.working_tree_basis
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    focused_verification = [ordered]@{
        wsl_debug_passed = [uint64]$controlled.wsl.debug_passed
        wsl_overflow_checked_release_passed = [uint64]$controlled.wsl.overflow_checked_release_passed
        upstream_activation_transaction_passed = [uint64]$controlled.wsl.upstream_activation_transaction_passed
        new_swa_06b2b1_tests = 7
        warnings_denied_clippy = 'passed'
        format = 'passed'
    }
    workspace_verification = [ordered]@{
        status = [string]$controlled.workspace.status
        debug = [ordered]@{
            result_groups = [uint64]$controlled.workspace.debug_result_groups
            passed = [uint64]$controlled.workspace.debug_passed
            failed = [uint64]$controlled.workspace.debug_failed
            ignored = [uint64]$controlled.workspace.debug_ignored
            transcript_bytes = [uint64]$controlled.workspace.debug_transcript_bytes
            transcript_sha256 = [string]$controlled.workspace.debug_transcript_sha256
        }
        overflow_checked_release = [ordered]@{
            result_groups = [uint64]$controlled.workspace.release_result_groups
            passed = [uint64]$controlled.workspace.release_passed
            failed = [uint64]$controlled.workspace.release_failed
            ignored = [uint64]$controlled.workspace.release_ignored
            transcript_bytes = [uint64]$controlled.workspace.release_transcript_bytes
            transcript_sha256 = [string]$controlled.workspace.release_transcript_sha256
        }
    }
    non_authority_statement = 'This manifest proves only deterministic synthetic-fixture-only source reacquisition, strict predecessor observation, same-parent durable current-registry replacement, successor selection, and typed partial-effect refusal. It proves no externally governed activation, no live repository contact, no boot validation, no rollback execution, no provider or model contact, no process or network authority, no Git or remote effect, no cleanup authority, no Windows durability success, no FPGA authority, and no Minecraft authority.'
}

$manifestFull = Resolve-Output $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFull)) | Out-Null
$json = ($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestFull, "$json`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFull
