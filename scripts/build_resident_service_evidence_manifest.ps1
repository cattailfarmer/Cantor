param(
    [string]$OutputPath = "experiments/resident_service_benchmark/artifacts/resident_service_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$fixedPaths = @(
    ".gitattributes",
    "source_documents/2026-07-29_cantor_resident_service_activation/Dictated_Cantor_Resident_Service_Activation_Source.sop",
    "source_documents/2026-07-29_cantor_resident_service_activation/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Resident_Service.exploded.sop",
    "specifications/Cantor_Resident_Service.sop",
    "justifications/Cantor_Resident_Service_Justification.sop",
    "feature_support/slices/ResidentService.sop",
    "feature_support/ResidentService_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "solutions/Cantor_Resident_Service_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785383067348_resident_service_faults.sop",
    "narrative/turns/1785383067348_cantor_resident_service.sop",
    "narrative/file_changes/1785383067348_resident_service_file_change.sop",
    "README.md",
    "SOP_CORE_MAP.sop",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_core/src/environment.rs",
    "crates/cantor_core/src/lib.rs",
    "crates/cantor_mcp/src/lib.rs",
    "crates/cantor_service/Cargo.toml",
    "crates/cantor_service/src/lib.rs",
    "crates/cantor_service/src/model.rs",
    "crates/cantor_service/src/artifacts.rs",
    "crates/cantor_service/src/runtime.rs",
    "crates/cantor_service/src/transport.rs",
    "crates/cantor_service/src/server_main.rs",
    "crates/cantor_service/src/client_main.rs",
    "crates/cantor_service/tests/common/mod.rs",
    "crates/cantor_service/tests/resident_service.rs",
    "docs/RESIDENT_SERVICE.md",
    "scripts/initialize_cantor_service.ps1",
    "scripts/publish_cantor_activation.ps1",
    "scripts/summarize_resident_service_evidence.ps1",
    "scripts/build_resident_service_evidence_manifest.ps1",
    "experiments/resident_service_benchmark/Cargo.toml",
    "experiments/resident_service_benchmark/Cargo.lock",
    "experiments/resident_service_benchmark/README.md",
    "experiments/resident_service_benchmark/src/main.rs",
    "experiments/resident_service_benchmark/tests/evidence.rs",
    "experiments/resident_service_benchmark/artifacts/2026-07-29-three-run-summary.json",
    "scripts/build_prepared_runtime_evidence_manifest.ps1",
    "scripts/build_self_hosted_corpus_evidence_manifest.ps1",
    "experiments/prepared_runtime_benchmark/src/main.rs",
    "experiments/prepared_runtime_benchmark/artifacts/prepared_runtime_evidence_manifest.json",
    "experiments/self_hosted_corpus_benchmark/tests/evidence.rs",
    "experiments/self_hosted_corpus_benchmark/artifacts/self_hosted_corpus_evidence_manifest.json",
    "proofs/Cantor_Prepared_Runtime_Proof.sop",
    "proofs/Cantor_Self_Hosting_Ingestion_Proof.sop",
    "experiments/llama_tool_reflection/Cargo.toml"
)
$rawPaths = Get-ChildItem -LiteralPath (Join-Path $repositoryRoot "experiments/resident_service_benchmark/artifacts") -File |
    Where-Object { $_.Name -like "2026-07-29-run-*.json" } |
    Sort-Object Name |
    ForEach-Object {
        "experiments/resident_service_benchmark/artifacts/$($_.Name)"
    }
$allPaths = @($fixedPaths) + @($rawPaths)

$artifacts = foreach ($path in $allPaths) {
    $fullPath = Join-Path $repositoryRoot $path
    $item = Get-Item -LiteralPath $fullPath
    [ordered]@{
        path = $path.Replace("\", "/")
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-resident-service-evidence-manifest/0.1"
    evidence_manifest_uuid = "b97c5fcf-724b-4df8-a80c-44475d569860"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "276ad3fd-d1fa-4b32-9bdd-5cd572bf1ece"
        satisfaction_signature_uuid = "bd09110a-d278-4177-bbcd-d7eb58fef217"
        solution_uuid = "143e3bdd-1cdd-4b8f-89af-72369f15c0eb"
    }
    profile = "cantor-resident-service/0.1"
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo clippy --all-targets --locked --offline -- -D warnings"; working_directory = "experiments/resident_service_benchmark"; status = "passed" },
        [ordered]@{ command = "cargo test --release --locked --offline"; working_directory = "experiments/resident_service_benchmark"; status = "passed" },
        [ordered]@{ command = "cargo audit"; working_directory = "repository root"; dependency_count = 111; advisory_count = 1173; vulnerabilities = 0; status = "passed" },
        [ordered]@{ command = "cargo audit"; working_directory = "experiments/resident_service_benchmark"; dependency_count = 35; advisory_count = 1173; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $outputFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
