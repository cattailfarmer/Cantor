[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/development_state_supersession_audit/artifacts/development_state_supersession_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'unable to resolve the repository source commit'
}

$paths = @(
    'experiments/development_state_supersession_audit/artifacts/development_state_supersession_inventory_v1.json',
    'scripts/verify_cantor_development_state_supersession_audit.ps1',
    'scripts/test_cantor_development_state_supersession_audit.ps1',
    'scripts/build_cantor_development_state_supersession_evidence_manifest.ps1',
    'source_documents/2026-08-23_development_state_supersession_audit_p0/Cantor_Development_State_Supersession_Audit_P0_Source.sop',
    'source_documents/2026-08-23_development_state_supersession_audit_p0/manifest.sop',
    'specifications/Cantor_Development_State_Supersession_Audit_P0.sop',
    'specifications/exploded/Cantor_Development_State_Supersession_Audit_P0.exploded.sop',
    'narrative/research/Cantor_Development_State_Supersession_Audit_P0_SJS_Review_2026-08-23.sop',
    'plans/Cantor_Development_State_Supersession_Audit_P0_Plan.sop',
    'feature_support/Cantor_Development_State_Supersession_Audit_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_Development_State_Supersession_Audit_P0_Phase_Lock.sop',
    'narrative/turns/1787494300000_development_state_supersession_audit_p0_activation.sop',
    'solutions/Cantor_Development_State_Supersession_Audit_P0_Solution.sop',
    'proofs/Cantor_Development_State_Supersession_Audit_P0_Proof.sop',
    'narrative/research/Cantor_Development_State_Supersession_Audit_P0_Completion_Review_2026-08-23.sop',
    'narrative/reentry/Cantor_Development_State_Supersession_Audit_P0_Reentry.sop',
    'narrative/operational_faults/1787495000000_development_state_supersession_audit_p0_faults.sop',
    'narrative/file_changes/1787495000000_development_state_supersession_audit_p0_file_change.sop',
    'narrative/turns/1787495000000_development_state_supersession_audit_p0_completion.sop',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'README.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/Project_Narrative.sop',
    'feature_support/M2BSuppliedContentDigest_Requirement_Matrix.sop',
    'feature_support/M2BSuppliedDirectoryTopologyProjection_Requirement_Matrix.sop',
    'feature_support/M2BSuppliedRegularFileTopologyProjection_Requirement_Matrix.sop',
    'feature_support/M2BSuppliedRootTopologyProjection_Requirement_Matrix.sop',
    'feature_support/M2BSuppliedTopologyInventoryAssembly_Requirement_Matrix.sop',
    'feature_support/M2BWindowsSysCompileProbe_Requirement_Matrix.sop',
    'feature_support/slices/M2BSuppliedContentDigest.sop',
    'feature_support/slices/M2BSuppliedDirectoryTopologyProjection.sop',
    'feature_support/slices/M2BSuppliedOrderedTopologyInventoryDigest.sop',
    'feature_support/slices/M2BSuppliedRegularFileTopologyProjection.sop',
    'feature_support/slices/M2BSuppliedRootTopologyProjection.sop',
    'feature_support/slices/M2BSuppliedTopologyInventoryAssembly.sop',
    'feature_support/slices/M2BWindowsSysCompileProbe.sop',
    'narrative/registries/Cantor_M2B_Supplied_Content_Digest_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Directory_Topology_Projection_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Root_Topology_Projection_Registry.sop',
    'narrative/registries/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Registry.sop',
    'plans/Cantor_M2B_Windows_Sys_Compile_Probe_Plan.sop',
    'plans/Cantor_Phase3_M2B_Activation_Readiness.sop',
    'proofs/Cantor_M2B_Supplied_Content_Digest_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Directory_Topology_Projection_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop',
    'proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Proof.sop',
    'proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Proof.sop',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/Cantor_Nested_LLM_Host_Vision_Source.sop',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/manifest.sop',
    'narrative/turns/1787494600000_nested_cantor_llm_host_vision.sop'
)

if (@($paths | Sort-Object -Unique).Count -ne $paths.Count) {
    throw 'evidence path list contains a duplicate'
}

$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "nonportable evidence path: $relativePath"
    }
    $fullPath = Join-Path $root $relativePath
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "manifest input is not one physical file: $relativePath"
    }
    [ordered]@{
        path = $relativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

$manifest = [ordered]@{
    profile = 'cantor-development-state-supersession-evidence-manifest/0.1'
    evidence_manifest_uuid = '1d5b8397-c2a1-4fc8-b042-cefab741aa0d'
    source_uuid = 'b2ddb307-f3c9-4f4e-86bc-f22635324b37'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest binds an append-only proof-backed development-navigation reconciliation and current-thread source preservation. It grants no runtime provider model loading process launch shared-inference production trust delivery secret persistence effect remote FPGA or Minecraft authority.'
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
