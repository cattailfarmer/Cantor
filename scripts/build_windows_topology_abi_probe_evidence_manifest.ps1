param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_topology_abi_probe_evidence_manifest.json"
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
    "crates/cantor_ecosystem/tests/windows_topology_abi_probe.rs",
    "source_documents/2026-07-30_cantor_m2b_windows_sys_compile_probe/Cantor_M2B_Windows_Sys_Compile_Probe_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_windows_sys_compile_probe/Source_Document_Manifest.sop",
    "specifications/Cantor_M2B_Windows_Sys_Compile_Probe.sop",
    "specifications/exploded/Cantor_M2B_Windows_Sys_Compile_Probe.exploded.sop",
    "source_documents/2026-07-30_cantor_m2b_windows_sys_compile_probe_lock_revision/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_windows_sys_compile_probe_lock_revision/Source_Document_Manifest.sop",
    "specifications/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision.sop",
    "specifications/exploded/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision.exploded.sop",
    "justifications/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Justification.sop",
    "plans/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Plan.sop",
    "feature_support/M2BWindowsSysCompileProbeLockRevision_Requirement_Matrix.sop",
    "feature_support/slices/M2BWindowsSysCompileProbeLockRevision.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/reviews/M2BWindowsSysCompileProbeLockRevision_Completion_Review.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "narrative/research/Cantor_Windows_Sys_Direct_Feature_ABI_Compile_Probe_Assessment_2026-07-30.sop",
    "narrative/research/Cantor_Cargo_Direct_Dependency_Lock_Edge_Model_2026-07-30.sop",
    "narrative/registries/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Registry.sop",
    "narrative/operational_faults/1785438389539_m2b_windows_sys_compile_probe_faults.sop",
    "narrative/turns/1785438389539_cantor_m2b_windows_sys_compile_probe.sop",
    "narrative/file_changes/1785438389539_m2b_windows_sys_compile_probe_file_change.sop",
    "solutions/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Solution.sop",
    "experiments/prepared_runtime_benchmark/artifacts/prepared_runtime_evidence_manifest.json",
    "proofs/Cantor_Prepared_Runtime_Proof.sop",
    "experiments/self_hosted_corpus_benchmark/artifacts/self_hosted_corpus_evidence_manifest.json",
    "proofs/Cantor_Self_Hosting_Ingestion_Proof.sop",
    "experiments/resident_service_benchmark/artifacts/resident_service_evidence_manifest.json",
    "proofs/Cantor_Resident_Service_Proof.sop",
    "crates/cantor_mcp/evidence/service_backed_mcp_evidence_manifest.json",
    "proofs/Cantor_Service_Backed_MCP_Proof.sop",
    "crates/cantor_service/evidence/supervised_lifecycle_evidence_manifest.json",
    "proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop",
    "crates/cantor_ecosystem/evidence/supervised_mock_loop_evidence_manifest.json",
    "proofs/Cantor_Supervised_Mock_Loop_Proof.sop",
    "crates/cantor_ecosystem/evidence/read_only_live_codex_evidence_manifest.json",
    "proofs/Cantor_Read_Only_Live_Codex_Adapter_Proof.sop",
    "crates/cantor_ecosystem/evidence/candidate_workspace_admission_evidence_manifest.json",
    "proofs/Cantor_Candidate_Workspace_Admission_Proof.sop",
    "crates/cantor_ecosystem/evidence/phase3_machine_forms_evidence_manifest.json",
    "proofs/Cantor_Phase3_Strict_Pure_Machine_Forms_Proof.sop",
    "crates/cantor_ecosystem/evidence/phase3_topology_forms_evidence_manifest.json",
    "proofs/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Proof.sop",
    "scripts/build_windows_topology_abi_probe_evidence_manifest.ps1"
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
    schema = "cantor-windows-topology-abi-probe-evidence-manifest/0.2"
    evidence_manifest_uuid = "eb58adf0-00ec-4320-a266-ad8611f8016d"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision.sop"
        satisfaction_signature_uuid = "56f266db-46db-4d8c-8078-8b9f926f3e63"
        solution_uuid = "6d7ea45c-99a0-4744-8e27-b1e98d0cb422"
        implementation_commit = "499e733"
        evidence_chain_commit = "572f4e8"
    }
    scope = [ordered]@{
        profile = "cantor-windows-topology-abi-probe/0.2"
        focused_tests = 4
        function_items = 5
        structure_layouts = 6
        information_classes = 6
        policy_values = 14
        imported_function_calls = 0
        production_rust_delta = 0
        filesystem_authority = $false
        windows_api_invocation_authority = $false
        scanner_authority = $false
        mutation_authority = $false
    }
    lock_contract = [ordered]@{
        before_sha256 = "7B2E1E879E387CCFF1CF1E04DE4ACE1D72EB006D1443192AB26629F0C3A884A5"
        after_sha256 = "FF20148AA6FF3C2774D07D454BC900F4F81D5594BD8F8E49AF2A43217B7EE73A"
        package_count = 112
        diff_hunks = 1
        added_lines = 1
        removed_lines = 0
        registry_identity_delta = 0
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_topology_abi_probe --locked --offline"; tests = 4; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test -p cantor_ecosystem --test windows_topology_abi_probe --release --locked --offline"; tests = 4; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 238; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test --workspace --all-targets --release --locked --offline"; tests = 238; status = "passed" },
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; advisories = 1174; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$manifestFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $manifestFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $manifestFullPath
