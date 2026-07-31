param([string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_topology_inventory_assembly_evidence_manifest.json")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$paths = @(
  ".gitattributes", "SOP_CORE_MAP.sop", "Cargo.toml", "Cargo.lock", "crates/cantor_ecosystem/Cargo.toml",
  "crates/cantor_ecosystem/src/lib.rs", "crates/cantor_ecosystem/src/topology_forms.rs",
  "crates/cantor_ecosystem/src/windows_supplied_root_topology_projection.rs",
  "crates/cantor_ecosystem/src/windows_supplied_directory_topology_projection.rs",
  "crates/cantor_ecosystem/src/windows_supplied_regular_file_topology_projection.rs",
  "crates/cantor_ecosystem/src/windows_supplied_topology_inventory_assembly.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_topology_inventory_assembly_static.rs",
  "crates/cantor_ecosystem/tests/windows_supplied_topology_inventory_assembly_evidence.rs",
  "source_documents/2026-07-31_cantor_m2b_supplied_topology_inventory_assembly/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Source.sop",
  "source_documents/2026-07-31_cantor_m2b_supplied_topology_inventory_assembly/Source_Document_Manifest.sop",
  "narrative/research/Cantor_M2B_Post_Supplied_Root_Topology_Projection_Architecture_Review_2026-07-31.sop",
  "feature_support/reviews/M2BSuppliedRootTopologyProjectionProgramCheckpointReview.sop",
  "specifications/Cantor_Phase3_Topology_Machine_Forms.sop", "proofs/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Proof.sop",
  "specifications/Cantor_M2B_Supplied_Root_Topology_Projection.sop", "proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop",
  "specifications/Cantor_M2B_Supplied_Directory_Topology_Projection.sop", "proofs/Cantor_M2B_Supplied_Directory_Topology_Projection_Proof.sop",
  "specifications/Cantor_M2B_Supplied_Regular_File_Topology_Projection.sop", "proofs/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Proof.sop",
  "specifications/exploded/Cantor_M2B_Supplied_Topology_Inventory_Assembly.exploded.sop",
  "specifications/Cantor_M2B_Supplied_Topology_Inventory_Assembly.sop",
  "justifications/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Justification.sop",
  "plans/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Plan.sop",
  "feature_support/M2BSuppliedTopologyInventoryAssembly_Requirement_Matrix.sop",
  "feature_support/slices/M2BSuppliedTopologyInventoryAssembly.sop",
  "narrative/registries/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Registry.sop",
  "plans/Cantor_Engine_Build_Plan.sop", "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
  "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop", "feature_support/Cantor_Engine_Build_Slice_Index.sop",
  "solutions/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Solution.sop",
  "feature_support/reviews/M2BSuppliedTopologyInventoryAssembly_Completion_Review.sop",
  "narrative/turns/1785519770000_cantor_m2b_supplied_topology_inventory_assembly_source_preservation.sop",
  "narrative/turns/1785520200000_cantor_m2b_supplied_topology_inventory_assembly_sjs_authority.sop",
  "narrative/turns/1785520700000_cantor_m2b_supplied_topology_inventory_assembly_implementation.sop",
  "narrative/turns/1785520710000_cantor_m2b_supplied_topology_inventory_assembly_completion.sop",
  "narrative/file_changes/1785519770000_m2b_supplied_topology_inventory_assembly_source_file_change.sop",
  "narrative/file_changes/1785520200000_m2b_supplied_topology_inventory_assembly_sjs_file_change.sop",
  "narrative/file_changes/1785520700000_m2b_supplied_topology_inventory_assembly_implementation_file_change.sop",
  "narrative/file_changes/1785520710000_m2b_supplied_topology_inventory_assembly_completion_file_change.sop",
  "narrative/operational_faults/1785520720000_m2b_supplied_topology_inventory_assembly_fixture_fault.sop",
  "narrative/Project_Narrative.sop", "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
  "scripts/build_windows_supplied_topology_inventory_assembly_evidence_manifest.ps1"
)
$artifacts = foreach ($path in $paths) {
  if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) { throw "nonportable evidence path: $path" }
  $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
  [ordered]@{ path = $path; sha256 = (Get-FileHash -Algorithm SHA256 $item.FullName).Hash; bytes = $item.Length }
}
$manifest = [ordered]@{
  schema = "cantor-windows-supplied-topology-inventory-assembly-evidence-manifest/0.1"
  evidence_manifest_uuid = "db540992-0108-428e-a19a-1183b4196571"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  authority = [ordered]@{
    canonical_specification = "specifications/Cantor_M2B_Supplied_Topology_Inventory_Assembly.sop"
    satisfaction_signature_uuid = "9c92f968-054a-42de-a27f-90925bb5081e"
    topology_signature_uuid = "0e2cfacb-8659-41c2-b804-0eb1b49ff5b2"
    root_signature_uuid = "6af7c461-07ed-426c-9684-819405223bf6"
    directory_signature_uuid = "2f24b78e-90ab-4413-9189-2c2bbcf65187"
    regular_file_signature_uuid = "dd8005c2-ae65-4b91-be87-88315a0334c2"
    solution_uuid = "748bcff5-70d4-4391-853e-98bf7bd584ce"
    implementation_commit = "166e478ef81fd7aa50cf757f43c04d4843ed8fa6"
  }
  scope = [ordered]@{
    profile = "cantor-windows-supplied-topology-inventory-assembly/0.1"
    focused_unit_tests = 10; focused_static_tests = 1; focused_evidence_tests = 1
    complete_carrier_inputs_only = $true; current_m2a_revalidation = $true; exact_duplicate_classes = 5
    parent_closure = $true; structural_utf8_order = $true; ordinal_repair = $false; checked_accounting = $true
    unsafe_blocks = 0; windows_api_calls = 0; cargo_delta = 0
    physical_origin_authority = $false; enumeration_authority = $false; inventory_completeness_authority = $false
    traversal_authority = $false; git_authority = $false; aggregate_digest_authority = $false
    double_inventory_authority = $false; receipt_authority = $false; admission_authority = $false; mutation_authority = $false
  }
  verification = @(
    [ordered]@{command="focused debug";passed=11;status="passed"},
    [ordered]@{command="overflow-checked focused release metadata=cantor_m2b_sstia_impl";passed=11;status="passed"},
    [ordered]@{command="evidence debug and release";passed=2;status="passed"},
    [ordered]@{command="workspace debug";passed=370;ignored=1;status="passed"},
    [ordered]@{command="overflow-checked workspace release metadata=cantor_m2b_sstia_impl";passed=370;ignored=1;status="passed"},
    [ordered]@{command="format lint build docs audit";dependencies=113;advisories=1177;vulnerabilities=0;status="passed"}
  )
  artifacts = @($artifacts)
}
$full = if ([IO.Path]::IsPathRooted($OutputPath)) {[IO.Path]::GetFullPath($OutputPath)} else {[IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full)) | Out-Null
[IO.File]::WriteAllText($full,"$(($manifest|ConvertTo-Json -Depth 10).Replace("`r`n","`n"))`n",[Text.UTF8Encoding]::new($false))
Write-Output $full
