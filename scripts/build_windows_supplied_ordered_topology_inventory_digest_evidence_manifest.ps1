param([string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_ordered_topology_inventory_digest_evidence_manifest.json")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$paths = @(
  ".gitattributes", "SOP_CORE_MAP.sop", "Cargo.toml", "Cargo.lock", "crates/cantor_ecosystem/Cargo.toml",
  "crates/cantor_ecosystem/src/lib.rs", "crates/cantor_ecosystem/src/topology_forms.rs",
  "crates/cantor_ecosystem/src/windows_supplied_content_digest.rs",
  "crates/cantor_ecosystem/src/windows_supplied_topology_inventory_assembly.rs",
  "crates/cantor_ecosystem/src/windows_supplied_ordered_topology_inventory_digest.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_ordered_topology_inventory_digest_static.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_ordered_topology_inventory_digest_evidence.rs",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Source.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest/Source_Document_Manifest.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_ordered_topology_inventory_digest/SJS_Processing_Input_Manifest.sop",
  "narrative/research/Cantor_M2B_Post_Supplied_Topology_Inventory_Assembly_Architecture_Review_2026-07-31.sop",
  "feature_support/reviews/M2BSuppliedTopologyInventoryAssemblyProgramCheckpointReview.sop",
  "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
  "specifications/Cantor_M2B_Supplied_Content_Digest.sop",
  "proofs/Cantor_M2B_Supplied_Content_Digest_Proof.sop",
  "specifications/Cantor_M2B_Supplied_Topology_Inventory_Assembly.sop",
  "proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop",
  "specifications/exploded/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest.exploded.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Semantic_Refinement_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Constraint_Ledger_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Pruning_Growth_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Seven_Fold_Exhaustion_2026-07-31.sop",
  "narrative/research/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Data_Design_2026-07-31.sop",
  "justifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Justification.sop",
  "plans/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Plan.sop",
  "feature_support/M2BSuppliedOrderedTopologyInventoryDigest_Requirement_Matrix.sop",
  "feature_support/slices/M2BSuppliedOrderedTopologyInventoryDigest.sop",
  "narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Registry.sop",
  "narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Phase_Lock.sop",
  "specifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest.sop",
  "plans/Cantor_Engine_Build_Plan.sop", "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
  "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop", "feature_support/Cantor_Engine_Build_Slice_Index.sop",
  "solutions/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Solution.sop",
  "feature_support/reviews/M2BSuppliedOrderedTopologyInventoryDigest_Completion_Review.sop",
  "narrative/turns/1785529883451_cantor_m2b_supplied_ordered_topology_inventory_digest_exhaustion_data_design.sop",
  "narrative/turns/1785530323058_cantor_m2b_supplied_ordered_topology_inventory_digest_sjs_authority.sop",
  "narrative/turns/1785531050765_cantor_m2b_supplied_ordered_topology_inventory_digest_implementation.sop",
  "narrative/turns/1785531050766_cantor_m2b_supplied_ordered_topology_inventory_digest_completion.sop",
  "narrative/file_changes/1785530323058_m2b_supplied_ordered_topology_inventory_digest_sjs_file_change.sop",
  "narrative/file_changes/1785531050765_m2b_supplied_ordered_topology_inventory_digest_implementation_file_change.sop",
  "narrative/file_changes/1785531050766_m2b_supplied_ordered_topology_inventory_digest_completion_file_change.sop",
  "narrative/Project_Narrative.sop", "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
  "scripts/build_windows_supplied_ordered_topology_inventory_digest_evidence_manifest.ps1"
)
$artifacts = foreach ($path in $paths) {
  if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) { throw "nonportable evidence path: $path" }
  $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
  [ordered]@{ path = $path; sha256 = (Get-FileHash -Algorithm SHA256 $item.FullName).Hash; bytes = $item.Length }
}
$manifest = [ordered]@{
  schema = "cantor-windows-supplied-ordered-topology-inventory-digest-evidence-manifest/0.1"
  evidence_manifest_uuid = "1b564e58-031f-4904-a6ee-d1d38d33e36d"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  authority = [ordered]@{
    canonical_specification = "specifications/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest.sop"
    satisfaction_signature_uuid = "63c58b74-0eb9-4ab8-9c95-4bfe3bb92af8"
    topology_signature_uuid = "1edee945-9957-41d7-bd17-0765ec54f5cb"
    assembly_signature_uuid = "9c92f968-054a-42de-a27f-90925bb5081e"
    content_digest_signature_uuid = "44749466-30d8-44e9-85b8-e51f1bafea33"
    solution_uuid = "fba84020-edf1-436f-9a98-1f39ee715581"
    implementation_commit = "ce26deeda98f97d49829172cc0f6c6bff8cf3830"
  }
  scope = [ordered]@{
    profile = "cantor-windows-supplied-ordered-topology-inventory-digest/0.1"
    encoding_profile = "cantor-ordered-topology-observation-encoding/0.1"
    focused_unit_tests = 10; focused_static_tests = 1; focused_evidence_tests = 1
    known_vectors = 2; independent_reference_vectors = 1; semantic_field_classes = 13
    complete_assembly_input_only = $true; current_m2a_revalidation = $true; exact_assembly_correlations = $true
    fixed_big_endian = $true; explicit_tags = $true; explicit_option_presence = $true; exact_utf8 = $true
    fixed_hex_decode = $true; sequence_sensitive = $true; lineage_retained = $true; plan_and_carrier_lineage_excluded = $true
    whole_inventory_buffer = $false; unsafe_blocks = 0; windows_api_calls = 0; cargo_delta = 0
    physical_origin_authority = $false; enumeration_authority = $false; inventory_completeness_authority = $false
    traversal_authority = $false; git_authority = $false; double_inventory_authority = $false
    receipt_authority = $false; admission_authority = $false; mutation_authority = $false
  }
  verification = @(
    [ordered]@{command="focused debug";passed=11;status="passed"},
    [ordered]@{command="overflow-checked focused release metadata=cantor_m2b_sotid_impl";passed=11;status="passed"},
    [ordered]@{command="evidence debug and release";passed=2;status="passed"},
    [ordered]@{command="workspace debug";passed=382;ignored=1;status="passed"},
    [ordered]@{command="overflow-checked workspace release metadata=cantor_m2b_sotid_impl";passed=382;ignored=1;status="passed"},
    [ordered]@{command="format lint build docs audit";dependencies=113;advisories=1177;vulnerabilities=0;status="passed"}
  )
  artifacts = @($artifacts)
}
$full = if ([IO.Path]::IsPathRooted($OutputPath)) {[IO.Path]::GetFullPath($OutputPath)} else {[IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full)) | Out-Null
[IO.File]::WriteAllText($full,"$(($manifest|ConvertTo-Json -Depth 10).Replace("`r`n","`n"))`n",[Text.UTF8Encoding]::new($false))
Write-Output $full
