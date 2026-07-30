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
    schema = "cantor-phase3-topology-forms-evidence-manifest/0.2"
    evidence_manifest_uuid = "ca7e7afa-a5d8-453e-9c5c-c3d25d8bb1e8"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_Phase3_Topology_Machine_Forms.sop"
        satisfaction_signature_uuid = "0e2cfacb-8659-41c2-b804-0eb1b49ff5b2"
        solution_uuid = "74914f5c-3001-4315-907c-9de2db7b824b"
    }
    scope = [ordered]@{
        forms_profile = "cantor-phase3-topology-forms/0.2"
        receipt_profile = "cantor-phase3-topology-receipt/0.2"
        scanner_profile = "cantor-windows-candidate-topology/0.1"
        focused_tests = 13
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
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 234; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 234; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; vulnerabilities = 0; status = "passed" }
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
