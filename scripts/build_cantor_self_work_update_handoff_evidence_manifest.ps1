[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/self_work_update_handoff_admission_p0/artifacts/self_work_update_handoff_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'unable to resolve source commit' }
$paths = @(
    'crates/cantor_core/src/self_work_lifecycle.rs',
    'crates/cantor_ecosystem/src/phase3_evidence.rs',
    'crates/cantor_ecosystem/src/workspace_admission.rs',
    'crates/cantor_ecosystem/src/workspace_admission/update_handoff.rs',
    'crates/cantor_ecosystem/src/workspace_admission/validation.rs',
    'crates/cantor_ecosystem/tests/self_work_update_handoff.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Self_Work_Update_Handoff_Admission_P0_Requirement_Matrix.sop',
    'narrative/Project_Narrative.sop',
    'narrative/file_changes/1787517300000_self_work_update_handoff_admission_p0_file_change.sop',
    'narrative/operational_faults/1787517300000_self_work_update_handoff_admission_p0_faults.sop',
    'narrative/reentry/Cantor_Self_Work_Update_Handoff_Admission_P0_Reentry.sop',
    'narrative/registries/Cantor_Self_Work_Update_Handoff_Admission_P0_Phase_Lock.sop',
    'narrative/research/Cantor_Self_Work_Update_Handoff_Admission_P0_Completion_Review_2026-08-23.sop',
    'narrative/research/Cantor_Self_Work_Update_Handoff_Admission_P0_SJS_Review_2026-08-23.sop',
    'narrative/turns/1787514000000_self_work_update_handoff_admission_p0_activation.sop',
    'narrative/turns/1787517300000_self_work_update_handoff_admission_p0_completion.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Self_Work_Update_Handoff_Admission_P0_Plan.sop',
    'proofs/Cantor_Self_Work_Lifecycle_Admission_P0_Proof.sop',
    'proofs/Cantor_Self_Work_Update_Handoff_Admission_P0_Proof.sop',
    'scripts/build_cantor_self_work_update_handoff_evidence_manifest.ps1',
    'scripts/test_cantor_self_work_update_handoff_evidence.ps1',
    'scripts/verify_cantor_self_work_update_handoff_evidence.ps1',
    'solutions/Cantor_Self_Work_Update_Handoff_Admission_P0_Solution.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/Cantor_SOP_Bootable_Self_Working_Agent_Target_Source.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/manifest.sop',
    'specifications/Cantor_Self_Work_Update_Handoff_Admission_P0.sop',
    'specifications/exploded/Cantor_Self_Work_Update_Handoff_Admission_P0.exploded.sop'
)
$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\/])\.\.([\/]|$)') { throw "nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    [ordered]@{ path = $relativePath.Replace('\', '/'); bytes = [uint64]$item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
}
$manifest = [ordered]@{
    profile = 'cantor-self-work-update-handoff-evidence-manifest/0.1'
    evidence_manifest_uuid = 'e742117d-15df-42fa-9be3-c8af9f2c4800'
    canonical_uuid = 'aeed3f2e-1169-43d6-8618-b2f7a8c48bad'
    source_uuid = '521e430b-1371-44ad-8364-f1420fd43c25'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest proves a pure supplied-form update handoff awaiting physical revalidation. It proves no authenticated or fresh workspace admission, process, mutation, verification, acceptance, rollback, cleanup, commit, push, provider call, persistence, external effect, SOP authorship, signature, activation, remote access, FPGA, or Minecraft authority.'
}
$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else { [IO.Path]::GetFullPath((Join-Path $root $OutputPath)) }
$parent = [IO.Path]::GetDirectoryName($outputFullPath)
if (-not [IO.Directory]::Exists($parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
[IO.File]::WriteAllText($outputFullPath, "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output $outputFullPath
