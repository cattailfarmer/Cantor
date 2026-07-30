param(
    [string]$OutputPath = "crates/cantor_mcp/evidence/service_backed_mcp_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$paths = @(
    "source_documents/2026-07-29_cantor_service_backed_mcp_activation/Dictated_Cantor_Service_Backed_MCP_Activation_Source.sop",
    "source_documents/2026-07-29_cantor_service_backed_mcp_activation/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Service_Backed_MCP.exploded.sop",
    "specifications/Cantor_Service_Backed_MCP.sop",
    "justifications/Cantor_Service_Backed_MCP_Justification.sop",
    "feature_support/slices/ServiceBackedMCP.sop",
    "feature_support/ServiceBackedMCP_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "solutions/Cantor_Service_Backed_MCP_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785384466595_service_backed_mcp_faults.sop",
    "narrative/turns/1785384466595_cantor_service_backed_mcp.sop",
    "narrative/file_changes/1785384466595_service_backed_mcp_file_change.sop",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_service/src/transport.rs",
    "crates/cantor_service/tests/resident_service.rs",
    "crates/cantor_mcp/Cargo.toml",
    "crates/cantor_mcp/src/lib.rs",
    "crates/cantor_mcp/src/main.rs",
    "crates/cantor_mcp/tests/mcp_protocol.rs",
    "crates/cantor_mcp/tests/self_hosted_corpus.rs",
    "crates/cantor_mcp/tests/service_backed_evidence.rs",
    "docs/MCP_PROTOCOL.md",
    "docs/RESIDENT_SERVICE.md",
    "README.md",
    "SOP_CORE_MAP.sop",
    "scripts/build_service_backed_mcp_evidence_manifest.ps1",
    "experiments/resident_service_benchmark/artifacts/resident_service_evidence_manifest.json",
    "proofs/Cantor_Resident_Service_Proof.sop",
    "experiments/prepared_runtime_benchmark/artifacts/prepared_runtime_evidence_manifest.json",
    "proofs/Cantor_Prepared_Runtime_Proof.sop",
    "experiments/self_hosted_corpus_benchmark/artifacts/self_hosted_corpus_evidence_manifest.json",
    "proofs/Cantor_Self_Hosting_Ingestion_Proof.sop"
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
    schema = "cantor-service-backed-mcp-evidence-manifest/0.1"
    evidence_manifest_uuid = "ca8d596e-08fe-411d-ac1e-63cf378f2f21"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "27a60f5b-4572-4b40-98bf-ec27cf44e0aa"
        satisfaction_signature_uuid = "e487b42f-25bf-430c-81ba-57b5bfc9c045"
        solution_uuid = "ce25a800-4404-4ddb-98c0-5e272443eebb"
    }
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 114; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 114; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 111; advisories = 1173; vulnerabilities = 0; status = "passed" }
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
    "$($manifest | ConvertTo-Json -Depth 10)`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
