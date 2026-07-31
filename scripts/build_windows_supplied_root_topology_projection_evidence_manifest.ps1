param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_root_topology_projection_evidence_manifest.json"
)

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
    "crates/cantor_ecosystem/src/topology_forms.rs",
    "crates/cantor_ecosystem/src/platform_preflight_forms.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_observation.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_stability.rs",
    "crates/cantor_ecosystem/src/windows_supplied_root_topology_projection.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_root_topology_projection_static.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_root_topology_projection_evidence.rs",
    "source_documents/2026-07-31_cantor_m2b_supplied_root_topology_projection/Cantor_M2B_Supplied_Root_Topology_Projection_Source.sop",
    "source_documents/2026-07-31_cantor_m2b_supplied_root_topology_projection/Source_Document_Manifest.sop",
    "narrative/research/Cantor_M2B_Post_Supplied_Directory_Topology_Projection_Architecture_Review_2026-07-31.sop",
    "feature_support/reviews/M2BSuppliedDirectoryTopologyProjectionProgramCheckpointReview.sop",
    "specifications/Cantor_M2B_Platform_Location_Classification_Revision.sop",
    "proofs/Cantor_M2B_Platform_Location_Classification_Revision_Proof.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.sop",
    "proofs/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Proof.sop",
    "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
    "proofs/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Proof.sop",
    "specifications/exploded/Cantor_M2B_Supplied_Root_Topology_Projection.exploded.sop",
    "specifications/Cantor_M2B_Supplied_Root_Topology_Projection.sop",
    "justifications/Cantor_M2B_Supplied_Root_Topology_Projection_Justification.sop",
    "plans/Cantor_M2B_Supplied_Root_Topology_Projection_Plan.sop",
    "feature_support/M2BSuppliedRootTopologyProjection_Requirement_Matrix.sop",
    "feature_support/slices/M2BSuppliedRootTopologyProjection.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "solutions/Cantor_M2B_Supplied_Root_Topology_Projection_Solution.sop",
    "feature_support/reviews/M2BSuppliedRootTopologyProjection_Completion_Review.sop",
    "narrative/registries/Cantor_M2B_Supplied_Root_Topology_Projection_Registry.sop",
    "narrative/turns/1785517770000_cantor_m2b_supplied_root_topology_projection_source_preservation.sop",
    "narrative/turns/1785517930000_cantor_m2b_supplied_root_topology_projection_sjs_authority.sop",
    "narrative/turns/1785518700000_cantor_m2b_supplied_root_topology_projection_implementation.sop",
    "narrative/turns/1785518710000_cantor_m2b_supplied_root_topology_projection_completion.sop",
    "narrative/file_changes/1785517770000_m2b_supplied_root_topology_projection_source_file_change.sop",
    "narrative/file_changes/1785517930000_m2b_supplied_root_topology_projection_sjs_file_change.sop",
    "narrative/file_changes/1785518700000_m2b_supplied_root_topology_projection_implementation_file_change.sop",
    "narrative/file_changes/1785518710000_m2b_supplied_root_topology_projection_completion_file_change.sop",
    "narrative/operational_faults/1785518720000_m2b_supplied_root_topology_projection_evidence_invocation_fault.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "scripts/build_windows_supplied_root_topology_projection_evidence_manifest.ps1"
)

$artifacts = foreach ($path in $paths) {
    if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) {
        throw "evidence path is not clone-portable: $path"
    }
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{
        path = $path
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-windows-supplied-root-topology-projection-evidence-manifest/0.1"
    evidence_manifest_uuid = "311a8d59-54a5-42f3-9b0a-244e96c461ee"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Supplied_Root_Topology_Projection.sop"
        satisfaction_signature_uuid = "6af7c461-07ed-426c-9684-819405223bf6"
        platform_signature_uuid = "61c2b9cf-4608-4e7d-88ae-d674d52640e3"
        stability_signature_uuid = "cbeb4260-0db0-413c-89c6-2ca164775243"
        topology_forms_signature_uuid = "1edee945-9957-41d7-bd17-0765ec54f5cb"
        solution_uuid = "0689c40c-35c9-49f3-9f72-d76d7f9a0b05"
        implementation_commit = "6f7db5b24c805250c1646196857faefeb43af6e4"
    }
    scope = [ordered]@{
        profile = "cantor-windows-supplied-root-topology-projection/0.1"
        focused_unit_tests = 11
        focused_static_tests = 1
        focused_evidence_tests = 1
        plan_json_max_bytes = 4096
        mandatory_preflight_revalidation = $true
        mandatory_stability_revalidation = $true
        direct_preflight_fragment_input = $false
        direct_stable_pair_input = $false
        eligible_complete_local_only = $true
        exact_entry_reference_gate = $true
        exact_whole_identity_gate = $true
        exact_dual_component_gate = $true
        fixed_root_directory_shape = $true
        current_topology_form_validation = $true
        output_only_lineage_wrapper = $true
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        runtime_origin_authority = $false
        physical_root_authority = $false
        same_handle_authority = $false
        enumeration_authority = $false
        traversal_authority = $false
        inventory_authority = $false
        receipt_authority = $false
        admission_authority = $false
        mutation_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib windows_supplied_root_topology_projection --locked --offline"; passed = 11; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_root_topology_projection_static --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_root_topology_projection_evidence --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on -C metadata=cantor_m2b_srtpr_impl focused equivalents --release --locked --offline"; passed = 13; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 358; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on -C metadata=cantor_m2b_srtpr_impl cargo test --workspace --all-targets --release --locked --offline"; passed = 358; ignored = 1; status = "passed" },
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 113; advisories = 1177; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$manifestFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
} else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $manifestFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $manifestFullPath
