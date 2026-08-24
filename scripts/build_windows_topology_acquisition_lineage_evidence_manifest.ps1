param([string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_topology_acquisition_lineage_evidence_manifest.json")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$paths = @(
  ".gitattributes",
  "SOP_CORE_MAP.sop",
  "Cargo.toml",
  "Cargo.lock",
  "crates/cantor_ecosystem/Cargo.toml",
  "crates/cantor_ecosystem/src/lib.rs",
  "crates/cantor_ecosystem/src/phase3_evidence.rs",
  "crates/cantor_ecosystem/src/topology_forms.rs",
  "crates/cantor_ecosystem/src/windows_supplied_topology_inventory_assembly.rs",
  "crates/cantor_ecosystem/src/windows_supplied_ordered_topology_inventory_digest.rs",
  "crates/cantor_ecosystem/src/windows_supplied_ordered_topology_inventory_digest_reconciliation.rs",
  "crates/cantor_ecosystem/src/windows_topology_acquisition_lineage.rs",
  "crates/cantor_ecosystem/tests/windows_topology_acquisition_lineage_static.rs",
  "crates/cantor_ecosystem/evidence/windows_supplied_topology_inventory_assembly_evidence_manifest.json",
  "crates/cantor_ecosystem/evidence/windows_supplied_ordered_topology_inventory_digest_evidence_manifest.json",
  "crates/cantor_ecosystem/evidence/windows_supplied_ordered_topology_inventory_digest_reconciliation_evidence_manifest.json",
  "source_documents/2026-08-23_cantor_phase3_topology_acquisition_lineage_serde_trait_correction/Cantor_Phase3_Topology_Acquisition_Lineage_Serde_Trait_Correction_Source.sop",
  "source_documents/2026-08-23_cantor_phase3_topology_acquisition_lineage_serde_trait_correction/Source_Document_Manifest.sop",
  "source_documents/2026-08-23_cantor_phase3_topology_acquisition_lineage_serde_trait_correction/SJS_Processing_Input_Manifest.sop",
  "narrative/operational_faults/1787520196836_phase3_topology_acquisition_lineage_serde_carrier_conflict.sop",
  "narrative/registries/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Satisfaction_Signature_Invalidation.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Serde_Trait_Correction_SJS_Input_Audit_2026-08-23.sop",
  "specifications/exploded/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2.exploded.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Semantic_Refinement_2026-08-23.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Constraint_Ledger_2026-08-23.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Pruning_Growth_Threat_Review_2026-08-23.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Seven_Fold_Exhaustion_2026-08-23.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Data_Design_2026-08-23.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Trait_Feasibility_Proof_2026-08-23.sop",
  "justifications/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Justification.sop",
  "plans/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Plan.sop",
  "narrative/registries/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Registry.sop",
  "feature_support/Phase3TopologyAcquisitionLineageFormsRevision02_Requirement_Matrix.sop",
  "feature_support/slices/Phase3TopologyAcquisitionLineageFormsRevision02.sop",
  "specifications/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2.sop",
  "narrative/research/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Artifact_Binding_Readiness_2026-08-23.sop",
  "narrative/registries/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Artifact_Phase_Lock.sop",
  "proofs/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Artifact_Phase_Lock_Proof.sop",
  "feature_support/reviews/Phase3TopologyAcquisitionLineageFormsRevision02SignatureReadinessReview.sop",
  "narrative/registries/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2_Satisfaction_Signature.sop",
  "scripts/build_windows_topology_acquisition_lineage_evidence_manifest.ps1",
  "scripts/rehash_current_evidence_manifests.ps1"
)
$artifacts = foreach ($path in $paths) {
  if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) {
    throw "nonportable evidence path: $path"
  }
  $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
  [ordered]@{
    path = $path
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
    bytes = $item.Length
  }
}
$manifest = [ordered]@{
  schema = "cantor-windows-topology-acquisition-lineage-evidence-manifest/0.2"
  evidence_manifest_uuid = "3925aeb0-e6a6-4f1e-91d1-393aef979568"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  authority = [ordered]@{
    canonical_specification = "specifications/Cantor_Phase3_Topology_Acquisition_Lineage_Forms_Revision_0_2.sop"
    canonical_uuid = "92f0d23d-dfb0-42d3-b354-de5b7f48426a"
    phase_lock_uuid = "c1f281ea-4b98-416c-81c1-a97994c698f7"
    satisfaction_signature_uuid = "ee5898fe-26cc-410c-b82b-f25f6738d77d"
  }
  scope = [ordered]@{
    profile = "cantor-phase3-topology-acquisition-lineage-forms/0.2"
    focused_unit_tests = 13
    focused_static_tests = 2
    metadata_deserialize_owned = $true
    carrier_graph_deserialize_owned = $false
    exact_two_carrier_roles = $true
    complete_scope_equality = $true
    exact_carrier_joins = $true
    current_rederivation = $true
    current_reconciliation = $true
    claim_only_equal_release = $true
    unsafe_blocks = 0
    cargo_delta = 0
    physical_acquisition_authority = $false
    causal_truth_authority = $false
    producer_authority = $false
    issuer_authority = $false
    consumer_authority = $false
    receipt_authority = $false
    admission_authority = $false
    mutation_authority = $false
    provider_authority = $false
    persistence_authority = $false
  }
  verification = @(
    [ordered]@{ command = "focused debug"; passed = 15; status = "passed" },
    [ordered]@{ command = "focused overflow-checked release"; passed = 15; status = "passed" },
    [ordered]@{ command = "warnings-denied package Clippy"; status = "passed" },
    [ordered]@{ command = "format and PowerShell parse"; status = "passed" }
  )
  artifacts = @($artifacts)
}
$full = if ([IO.Path]::IsPathRooted($OutputPath)) {
  [IO.Path]::GetFullPath($OutputPath)
} else {
  [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
$parent = [IO.Path]::GetDirectoryName($full)
if (-not [string]::IsNullOrEmpty($parent)) {
  [IO.Directory]::CreateDirectory($parent) | Out-Null
}
[IO.File]::WriteAllText(
  $full,
  "$(($manifest | ConvertTo-Json -Depth 12).Replace("`r`n", "`n"))`n",
  [Text.UTF8Encoding]::new($false)
)
Write-Output $full
