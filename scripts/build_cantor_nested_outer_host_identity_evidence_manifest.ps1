[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/nested_outer_host_identity_p0/artifacts/nested_outer_host_identity_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'unable to resolve the repository source commit'
}

$paths = @(
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/src/nested_host_identity.rs',
    'crates/cantor_core/tests/nested_host_identity.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Nested_Outer_Host_Identity_P0_Requirement_Matrix.sop',
    'narrative/Project_Narrative.sop',
    'narrative/file_changes/1787498200000_nested_outer_host_identity_p0_file_change.sop',
    'narrative/operational_faults/1787498200000_nested_outer_host_identity_p0_faults.sop',
    'narrative/reentry/Cantor_Nested_Outer_Host_Identity_P0_Reentry.sop',
    'narrative/registries/Cantor_Nested_Outer_Host_Identity_P0_Phase_Lock.sop',
    'narrative/research/Cantor_Nested_Outer_Host_Identity_P0_Completion_Review_2026-08-23.sop',
    'narrative/research/Cantor_Nested_Outer_Host_Identity_P0_SJS_Review_2026-08-23.sop',
    'narrative/turns/1787497000000_nested_outer_host_identity_p0_activation.sop',
    'narrative/turns/1787497200000_sop_bootable_self_working_cantor_target.sop',
    'narrative/turns/1787498200000_nested_outer_host_identity_p0_completion.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'plans/Cantor_Nested_Outer_Host_Identity_P0_Plan.sop',
    'proofs/Cantor_Nested_Outer_Host_Identity_P0_Proof.sop',
    'README.md',
    'scripts/build_cantor_nested_outer_host_identity_evidence_manifest.ps1',
    'scripts/test_cantor_nested_outer_host_identity_evidence.ps1',
    'scripts/verify_cantor_nested_outer_host_identity_evidence.ps1',
    'solutions/Cantor_Nested_Outer_Host_Identity_P0_Solution.sop',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/Cantor_Nested_LLM_Host_Vision_Source.sop',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/manifest.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/Cantor_SOP_Bootable_Self_Working_Agent_Target_Source.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/manifest.sop',
    'specifications/Cantor_Nested_Outer_Host_Identity_P0.sop',
    'specifications/exploded/Cantor_Nested_Outer_Host_Identity_P0.exploded.sop'
)

$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "nonportable evidence path: $relativePath"
    }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "manifest input is not one physical file: $relativePath"
    }
    [ordered]@{
        path = $relativePath.Replace('\\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

$manifest = [ordered]@{
    profile = 'cantor-nested-outer-host-identity-evidence-manifest/0.1'
    evidence_manifest_uuid = '665919b1-aa6d-4abc-b5ca-6f24820c0578'
    canonical_uuid = '762ca2d3-c279-4e73-ad1c-990f31950a28'
    source_uuid = '6fa07b14-4a49-495c-834f-be2b7dd0f7ea'
    current_target_source_uuid = '521e430b-1371-44ad-8364-f1420fd43c25'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest binds a pure proposed outer-host identity envelope and current SOP-bootable product planning. It proves no process observation or launch, model availability or load, provider contact, inner host, shared attention, workspace mutation, persistence, external effect, remote access, FPGA, or Minecraft authority.'
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}
$parent = [IO.Path]::GetDirectoryName($outputFullPath)
if (-not [IO.Directory]::Exists($parent)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
[IO.File]::WriteAllText(
    $outputFullPath,
    "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
