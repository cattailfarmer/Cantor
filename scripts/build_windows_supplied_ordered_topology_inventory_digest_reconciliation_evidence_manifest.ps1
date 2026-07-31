param([string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_ordered_topology_inventory_digest_reconciliation_evidence_manifest.json")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$paths = @(
  ".gitattributes", "SOP_CORE_MAP.sop", "Cargo.toml", "Cargo.lock", "crates/cantor_ecosystem/Cargo.toml",
  "crates/cantor_ecosystem/src/lib.rs", "crates/cantor_ecosystem/src/topology_forms.rs",
  "crates/cantor_ecosystem/src/windows_supplied_topology_inventory_assembly.rs",
  "crates/cantor_ecosystem/src/windows_supplied_ordered_topology_inventory_digest.rs",
  "crates/cantor_ecosystem/src/windows_supplied_ordered_topology_inventory_digest_reconciliation.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_ordered_topology_inventory_digest_reconciliation_static.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_ordered_topology_inventory_digest_reconciliation_evidence.rs",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Source.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Root_Kind_Revision_Source.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/Source_Document_Manifest.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/Source_Revision_Manifest.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/SJS_Processing_Input_Manifest.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest_reconciliation/SJS_Reprocessing_Input_Manifest.sop",
  "narrative/research/Cantor_M2B_Post_Supplied_Ordered_Topology_Inventory_Digest_Architecture_Review_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_SJS_Input_Audit_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Root_Kind_Revision_SJS_Input_Audit_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Semantic_Refinement_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Constraint_Ledger_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Pruning_Growth_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Seven_Fold_Exhaustion_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Data_Design_2026-07-31.sop",
  "narrative/operational_faults/1785533105126_m2b_supplied_digest_reconciliation_root_kind_source_fault.sop",
  "narrative/operational_faults/1785535000001_m2b_supplied_digest_reconciliation_preclosure_evidence_fault.sop",
  "specifications/exploded/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation.exploded.sop",
  "specifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation.sop",
  "justifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Justification.sop",
  "plans/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Plan.sop",
  "narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Registry.sop",
  "narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Phase_Lock.sop",
  "feature_support/M2BSuppliedOrderedTopologyInventoryDigestReconciliation_Requirement_Matrix.sop",
  "feature_support/slices/M2BSuppliedOrderedTopologyInventoryDigestReconciliation.sop",
  "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
  "specifications/Cantor_M2B_Supplied_Topology_Inventory_Assembly.sop",
  "proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop",
  "specifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest.sop",
  "proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Proof.sop",
  "crates/cantor_ecosystem/evidence/windows_supplied_ordered_topology_inventory_digest_evidence_manifest.json",
  "solutions/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Solution.sop",
  "feature_support/reviews/M2BSuppliedOrderedTopologyInventoryDigestReconciliation_Completion_Review.sop",
  "narrative/turns/1785532052688_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_source_preservation.sop",
  "narrative/turns/1785532587961_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_partial_sjs.sop",
  "narrative/turns/1785532808384_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_exhaustion_data_design.sop",
  "narrative/turns/1785533489613_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_corrected_sjs_authority.sop",
  "narrative/turns/1785535000000_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_implementation.sop",
  "narrative/turns/1785535000001_cantor_m2b_supplied_ordered_inventory_digest_reconciliation_completion.sop",
  "narrative/file_changes/1785532052688_m2b_supplied_ordered_inventory_digest_reconciliation_source_file_change.sop",
  "narrative/file_changes/1785532587961_m2b_supplied_ordered_inventory_digest_reconciliation_partial_sjs_file_change.sop",
  "narrative/file_changes/1785532808384_m2b_supplied_ordered_inventory_digest_reconciliation_exhaustion_data_design_file_change.sop",
  "narrative/file_changes/1785533489613_m2b_supplied_ordered_inventory_digest_reconciliation_corrected_sjs_file_change.sop",
  "narrative/file_changes/1785535000000_m2b_supplied_ordered_inventory_digest_reconciliation_implementation_file_change.sop",
  "narrative/file_changes/1785535000001_m2b_supplied_ordered_inventory_digest_reconciliation_completion_file_change.sop",
  "plans/Cantor_Engine_Build_Plan.sop", "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
  "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop", "feature_support/Cantor_Engine_Build_Slice_Index.sop",
  "narrative/Project_Narrative.sop", "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
  "scripts/build_windows_supplied_ordered_topology_inventory_digest_reconciliation_evidence_manifest.ps1",
  "scripts/rehash_current_evidence_manifests.ps1"
)
$artifacts = foreach ($path in $paths) {
  if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) { throw "nonportable evidence path: $path" }
  $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
  [ordered]@{ path = $path; sha256 = (Get-FileHash -Algorithm SHA256 $item.FullName).Hash; bytes = $item.Length }
}
$manifest = [ordered]@{
  schema = "cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation-evidence-manifest/0.1"
  evidence_manifest_uuid = "b35763ec-0947-48ef-8bce-a51f9a4a3c7f"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  authority = [ordered]@{
    canonical_specification = "specifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation.sop"
    satisfaction_signature_uuid = "a763535f-3b13-4539-9aba-d74f09e3de5c"
    prerequisite_digest_signature_uuid = "63c58b74-0eb9-4ab8-9c95-4bfe3bb92af8"
    solution_uuid = "b5f07002-7beb-4107-a8b6-b1fa4e273d0b"
    implementation_commit = "15809a5ea18187f2ee0f38ae7da082c7dc81b61f"
  }
  scope = [ordered]@{
    profile = "cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation/0.1"
    focused_unit_tests = 11; focused_static_tests = 1; focused_evidence_tests = 1
    complete_output_operands = $true; current_rederivation = $true; exact_profile_scope = $true
    exact_complete_limits = $true; exact_root_scope = $true; closed_equal_or_different = $true
    complete_lineage_retained = $true; positional_non_temporal_operands = $true
    unsafe_blocks = 0; windows_api_calls = 0; cargo_delta = 0
    physical_origin_authority = $false; enumeration_authority = $false; temporal_authority = $false
    double_inventory_authority = $false; quiescence_authority = $false; receipt_authority = $false
    admission_authority = $false; mutation_authority = $false
  }
  verification = @(
    [ordered]@{command="focused debug";passed=12;status="passed"},
    [ordered]@{command="focused release";passed=12;status="passed"},
    [ordered]@{command="evidence debug and release";passed=2;status="passed"},
    [ordered]@{command="workspace debug";passed=395;ignored=1;status="passed"},
    [ordered]@{command="overflow-checked workspace release";passed=395;ignored=1;status="passed"},
    [ordered]@{command="format lint build docs audit";dependencies=113;advisories=1177;vulnerabilities=0;status="passed"}
  )
  artifacts = @($artifacts)
}
$full = if ([IO.Path]::IsPathRooted($OutputPath)) {[IO.Path]::GetFullPath($OutputPath)} else {[IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full)) | Out-Null
[IO.File]::WriteAllText($full,"$(($manifest|ConvertTo-Json -Depth 10).Replace("`r`n","`n"))`n",[Text.UTF8Encoding]::new($false))
Write-Output $full
