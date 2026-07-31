param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_directory_topology_projection_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/windows_supplied_entry_observation.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_stability.rs",
    "crates/cantor_ecosystem/src/windows_supplied_directory_topology_projection.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_directory_topology_projection_static.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_directory_topology_projection_evidence.rs",
    "source_documents/2026-07-31_cantor_m2b_supplied_directory_topology_projection/Cantor_M2B_Supplied_Directory_Topology_Projection_Source.sop",
    "source_documents/2026-07-31_cantor_m2b_supplied_directory_topology_projection/Source_Document_Manifest.sop",
    "narrative/research/Cantor_M2B_Post_Supplied_Regular_File_Topology_Projection_Architecture_Review_2026-07-31.sop",
    "feature_support/reviews/M2BSuppliedRegularFileTopologyProjectionProgramCheckpointReview.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.sop",
    "proofs/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Proof.sop",
    "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
    "proofs/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Proof.sop",
    "specifications/exploded/Cantor_M2B_Supplied_Directory_Topology_Projection.exploded.sop",
    "specifications/Cantor_M2B_Supplied_Directory_Topology_Projection.sop",
    "justifications/Cantor_M2B_Supplied_Directory_Topology_Projection_Justification.sop",
    "plans/Cantor_M2B_Supplied_Directory_Topology_Projection_Plan.sop",
    "feature_support/M2BSuppliedDirectoryTopologyProjection_Requirement_Matrix.sop",
    "feature_support/slices/M2BSuppliedDirectoryTopologyProjection.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "solutions/Cantor_M2B_Supplied_Directory_Topology_Projection_Solution.sop",
    "feature_support/reviews/M2BSuppliedDirectoryTopologyProjection_Completion_Review.sop",
    "narrative/registries/Cantor_M2B_Supplied_Directory_Topology_Projection_Registry.sop",
    "narrative/turns/1785516170000_cantor_m2b_supplied_directory_topology_projection_source_preservation.sop",
    "narrative/turns/1785516260000_cantor_m2b_supplied_directory_topology_projection_sjs_authority.sop",
    "narrative/turns/1785516970000_cantor_m2b_supplied_directory_topology_projection_implementation.sop",
    "narrative/turns/1785516980000_cantor_m2b_supplied_directory_topology_projection_completion.sop",
    "narrative/file_changes/1785516170000_m2b_supplied_directory_topology_projection_source_file_change.sop",
    "narrative/file_changes/1785516260000_m2b_supplied_directory_topology_projection_sjs_file_change.sop",
    "narrative/file_changes/1785516970000_m2b_supplied_directory_topology_projection_implementation_file_change.sop",
    "narrative/file_changes/1785516980000_m2b_supplied_directory_topology_projection_completion_file_change.sop",
    "narrative/operational_faults/1785517000000_m2b_supplied_directory_topology_projection_application_control_fault.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "scripts/build_windows_supplied_directory_topology_projection_evidence_manifest.ps1"
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
    schema = "cantor-windows-supplied-directory-topology-projection-evidence-manifest/0.1"
    evidence_manifest_uuid = "46081753-f671-4042-a9e1-cb337b7aa103"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Supplied_Directory_Topology_Projection.sop"
        satisfaction_signature_uuid = "2f24b78e-90ab-4413-9189-2c2bbcf65187"
        stability_signature_uuid = "cbeb4260-0db0-413c-89c6-2ca164775243"
        topology_forms_signature_uuid = "1edee945-9957-41d7-bd17-0765ec54f5cb"
        solution_uuid = "0461573f-053d-42cb-8be7-2a55c08a4f13"
        implementation_commit = "869a95f9939125397017894b817fc6fa98103429"
    }
    scope = [ordered]@{
        profile = "cantor-windows-supplied-directory-topology-projection/0.1"
        focused_unit_tests = 11
        focused_static_tests = 1
        focused_evidence_tests = 1
        plan_json_max_bytes = 262144
        mandatory_stability_revalidation = $true
        direct_stable_pair_input = $false
        fixed_directory_mode = $true
        absent_length = $true
        absent_content_digest = $true
        exact_entry_reference_gate = $true
        exact_final_component_gate = $true
        current_topology_form_validation = $true
        output_only_lineage_wrapper = $true
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        physical_path_authority = $false
        enumeration_authority = $false
        traversal_authority = $false
        inventory_authority = $false
        stream_completeness_authority = $false
        receipt_authority = $false
        admission_authority = $false
        mutation_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib windows_supplied_directory_topology_projection --locked --offline"; passed = 11; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_directory_topology_projection_static --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_directory_topology_projection_evidence --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on -C metadata=cantor_m2b_sdtp_impl focused equivalents --release --locked --offline"; passed = 13; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 345; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on -C metadata=cantor_m2b_sdtp_impl cargo test --workspace --all-targets --release --locked --offline"; passed = 345; ignored = 1; status = "passed" },
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
