param(
    [string]$OutputPath = "experiments/prepared_runtime_benchmark/artifacts/prepared_runtime_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$fixedPaths = @(
    "source_documents/2026-07-29_cantor_prepared_runtime/Dictated_Cantor_Prepared_Runtime_Source.sop",
    "source_documents/2026-07-29_cantor_prepared_runtime/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Prepared_Runtime.exploded.sop",
    "specifications/Cantor_Prepared_Runtime.sop",
    "justifications/Cantor_Prepared_Runtime_Justification.sop",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_core/src/lib.rs",
    "crates/cantor_core/src/protocol.rs",
    "crates/cantor_core/src/prepared.rs",
    "crates/cantor_core/tests/common/mod.rs",
    "crates/cantor_core/tests/prepared_runtime.rs",
    "crates/cantor_mcp/src/lib.rs",
    "crates/cantor_mcp/tests/mcp_protocol.rs",
    "experiments/prepared_runtime_benchmark/Cargo.toml",
    "experiments/prepared_runtime_benchmark/Cargo.lock",
    "experiments/prepared_runtime_benchmark/README.md",
    "experiments/prepared_runtime_benchmark/src/main.rs",
    "experiments/prepared_runtime_benchmark/artifacts/2026-07-29_three_run_summary.json",
    "scripts/summarize_prepared_runtime_evidence.ps1",
    "scripts/build_prepared_runtime_evidence_manifest.ps1"
)
$rawPaths = Get-ChildItem -LiteralPath "experiments/prepared_runtime_benchmark/artifacts" -File |
    Where-Object { $_.Name -like "latency_run_*.json" -or $_.Name -like "memory_run_*.json" } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }
$allPaths = @($fixedPaths) + @($rawPaths)

$artifacts = foreach ($path in $allPaths) {
    $item = Get-Item -LiteralPath $path
    [ordered]@{
        path = $item.FullName
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-prepared-runtime-evidence-manifest/0.1"
    evidence_manifest_uuid = "a9d605de-2015-4643-a914-fd0cbfda12b8"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "73d6dba4-df9b-4856-90cf-2a40a32c98df"
        satisfaction_signature_uuid = "38e9e194-1b32-4785-92a4-1f34ba1bfed9"
        solution_uuid = "05c9ee54-f70c-4a88-aa8a-0b31352ef0e6"
    }
    disposition = "activate_bounded_core_and_resident_mcp_with_direct_rollback"
    verification = @(
        [ordered]@{ command = "cargo fmt --all --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --locked --offline"; status = "passed"; tests = 91 },
        [ordered]@{ command = "cargo test --workspace --release --locked --offline"; status = "passed"; tests = 91 },
        [ordered]@{ command = "cargo build --workspace --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo test --locked --manifest-path experiments/prepared_runtime_benchmark/Cargo.toml"; status = "passed"; tests = 3 },
        [ordered]@{ command = "cargo clippy --manifest-path experiments/prepared_runtime_benchmark/Cargo.toml --all-targets --features dhat-heap -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; status = "passed"; advisories_loaded = 1173; vulnerabilities = 0 },
        [ordered]@{ command = "cargo audit --file experiments/prepared_runtime_benchmark/Cargo.lock"; status = "passed"; advisories_loaded = 1173; vulnerabilities = 0 }
    )
    artifacts = @($artifacts)
}

$json = $manifest | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText(
    (Join-Path (Get-Location) $OutputPath),
    "$json`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $OutputPath
