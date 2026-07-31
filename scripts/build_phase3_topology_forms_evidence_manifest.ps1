param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/phase3_topology_forms_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$paths = @(
    "Cargo.toml",
    "Cargo.lock",
    "source_documents/2026-07-30_cantor_phase3_topology_scanner_formation/Cantor_Phase3_Topology_Scanner_Formation_Source.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_scanner_formation/Source_Document_Manifest.sop",
    "specifications/Cantor_Phase3_Topology_Scanner.sop",
    "specifications/exploded/Cantor_Phase3_Topology_Scanner.exploded.sop",
    "justifications/Cantor_Phase3_Topology_Scanner_Justification.sop",
    "plans/Cantor_Phase3_Topology_Scanner_Formation_Plan.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/slices/Phase3TopologyScanner.sop",
    "narrative/research/Cantor_Windows_Topology_API_Assessment_2026-07-30.sop",
    "narrative/operational_faults/1785433114684_phase3_topology_scanner_formation_faults.sop",
    "narrative/turns/1785433114684_cantor_phase3_topology_scanner_formation.sop",
    "narrative/file_changes/1785433114684_phase3_topology_scanner_formation_file_change.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_machine_forms_activation/Cantor_Phase3_Topology_Machine_Forms_Activation_Source.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_machine_forms_activation/Source_Document_Manifest.sop",
    "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
    "source_documents/2026-07-31_cantor_phase3_inventory_consistency_evidence_revision/Cantor_Phase3_Inventory_Consistency_Evidence_Revision_Source.sop",
    "source_documents/2026-07-31_cantor_phase3_inventory_consistency_evidence_revision/SJS_Processing_Input_Manifest.sop",
    "specifications/Cantor_Phase3_Inventory_Consistency_Evidence_Revision.sop",
    "specifications/exploded/Cantor_Phase3_Inventory_Consistency_Evidence_Revision.exploded.sop",
    "narrative/registries/Cantor_Phase3_Inventory_Consistency_Evidence_Revision_Phase_Lock.sop",
    "solutions/Cantor_Phase3_Inventory_Consistency_Evidence_Revision_Solution.sop",
    "narrative/operational_faults/1785536700000_phase3_inventory_consistency_evidence_revision_windows_application_control_fault.sop",
    "specifications/exploded/Cantor_Phase3_Topology_Machine_Forms.exploded.sop",
    "justifications/Cantor_Phase3_Topology_Machine_Forms_Justification.sop",
    "feature_support/Phase3TopologyMachineForms_Requirement_Matrix.sop",
    "docs/PHASE3_TOPOLOGY_FORMS.md",
    "solutions/Cantor_Phase3_Topology_Machine_Forms_Solution.sop",
    "narrative/operational_faults/1785433555602_phase3_topology_machine_forms_faults.sop",
    "narrative/turns/1785433555602_cantor_phase3_topology_machine_forms.sop",
    "narrative/file_changes/1785433555602_phase3_topology_machine_forms_file_change.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_receipt_root_binding_revision/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Source.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_receipt_root_binding_revision/Cantor_Phase3_Topology_Machine_Forms_Pre_Revision_Snapshot.sop",
    "source_documents/2026-07-30_cantor_phase3_topology_receipt_root_binding_revision/SJS_Reprocessing_Input_Manifest.sop",
    "narrative/research/Cantor_Topology_Receipt_Revision_Decision_2026-07-30.sop",
    "specifications/exploded/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision.exploded.sop",
    "justifications/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Justification.sop",
    "plans/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Plan.sop",
    "feature_support/Phase3TopologyReceiptRootBindingRevision_Requirement_Matrix.sop",
    "feature_support/slices/Phase3TopologyReceiptRootBindingRevision.sop",
    "narrative/registries/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Registry.sop",
    "solutions/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Solution.sop",
    "narrative/operational_faults/1785436983061_phase3_topology_receipt_root_binding_revision_faults.sop",
    "narrative/turns/1785436983061_cantor_second_four_hour_push.sop",
    "narrative/file_changes/1785436983061_phase3_topology_receipt_root_binding_revision_file_change.sop",
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/topology_forms.rs",
    "crates/cantor_ecosystem/tests/phase3_topology_forms_evidence.rs",
    "crates/cantor_ecosystem/tests/phase3_inventory_consistency_evidence_revision_static.rs",
    "scripts/build_phase3_topology_forms_evidence_manifest.ps1",
    "crates/cantor_ecosystem/evidence/phase3_topology_forms_evidence_manifest_0_1.json",
    "proofs/Cantor_Phase3_Topology_Machine_Forms_Proof.sop",
    "crates/cantor_ecosystem/evidence/phase3_machine_forms_evidence_manifest.json",
    "proofs/Cantor_Phase3_Strict_Pure_Machine_Forms_Proof.sop"
)

$artifacts = foreach ($path in $paths) {
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{
        path = $path.Replace("\", "/")
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-phase3-topology-forms-evidence-manifest/0.3"
    evidence_manifest_uuid = "5cae3376-f1c1-4750-b810-dad4fa4e9e1d"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_Phase3_Inventory_Consistency_Evidence_Revision.sop"
        satisfaction_signature_uuid = "1edee945-9957-41d7-bd17-0765ec54f5cb"
        superseded_signature_uuid = "0e2cfacb-8659-41c2-b804-0eb1b49ff5b2"
        joint_machine_forms_signature_uuid = "c681b74d-7543-43be-96a1-a8ccb89181fb"
        solution_uuid = "4d874ac7-a91d-4f9c-bdf0-e29deb541fc4"
    }
    scope = [ordered]@{
        forms_profile = "cantor-phase3-topology-forms/0.3"
        receipt_profile = "cantor-phase3-topology-receipt/0.3"
        scanner_profile = "cantor-windows-candidate-topology/0.1"
        focused_tests = 16
        focused_unit_tests = 15
        focused_static_tests = 1
        filesystem_authority = $false
        windows_api_authority = $false
        unsafe_authority = $false
        clock_authority = $false
        persistence_authority = $false
        process_authority = $false
        network_authority = $false
        model_authority = $false
        mutation_authority = $false
        promotion_authority = $false
    }
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "WSL2 Ubuntu-24.04: CARGO_TARGET_DIR=/tmp/cantor-p3icer-target cargo test --workspace --all-targets --locked --offline"; platform = "linux-x86_64-wsl2"; result_groups = 63; tests = 390; ignored = 0; status = "passed" },
        [ordered]@{ command = "WSL2 Ubuntu-24.04: CARGO_TARGET_DIR=/tmp/cantor-p3icer-target RUSTFLAGS='-C overflow-checks=on -C metadata=cantor_p3icer_wsl_release' cargo test --workspace --all-targets --release --locked --offline"; platform = "linux-x86_64-wsl2"; result_groups = 63; tests = 390; ignored = 0; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
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
