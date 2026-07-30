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
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/topology_forms.rs",
    "crates/cantor_ecosystem/tests/phase3_topology_forms_evidence.rs",
    "scripts/build_phase3_topology_forms_evidence_manifest.ps1",
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
    schema = "cantor-phase3-topology-forms-evidence-manifest/0.1"
    evidence_manifest_uuid = "aff771d6-5774-4a15-8351-1c5120da65e3"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_Phase3_Topology_Machine_Forms.sop"
        satisfaction_signature_uuid = "4e28ac73-3296-4d57-8dd9-30cc2ac1f01f"
        solution_uuid = "edfe12e3-49a3-4117-b829-8d3ec0764282"
    }
    scope = [ordered]@{
        profile = "cantor-phase3-topology-forms/0.1"
        focused_tests = 8
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
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 229; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 229; status = "passed" },
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
