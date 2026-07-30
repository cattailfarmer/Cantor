param(
    [string]$OutputPath = "experiments/self_hosted_corpus_benchmark/artifacts/self_hosted_corpus_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$fixedPaths = @(
    ".gitattributes",
    "source_documents/2026-07-29_cantor_self_hosting_ingestion/Dictated_Cantor_Self_Hosting_Ingestion_Source.sop",
    "source_documents/2026-07-29_cantor_self_hosting_ingestion/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Self_Hosting_Ingestion.exploded.sop",
    "specifications/Cantor_Self_Hosting_Ingestion.sop",
    "justifications/Cantor_Self_Hosting_Ingestion_Justification.sop",
    "feature_support/slices/SelfHostingIngestion.sop",
    "feature_support/SelfHostingIngestion_Requirement_Matrix.sop",
    "corpus/self_hosted/corpus.json",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_core/src/lib.rs",
    "crates/cantor_core/src/sop.rs",
    "crates/cantor_core/tests/sop_ingestion.rs",
    "crates/cantor_cli/Cargo.toml",
    "crates/cantor_cli/src/corpus_main.rs",
    "crates/cantor_cli/tests/corpus_cli.rs",
    "crates/cantor_mcp/tests/self_hosted_corpus.rs",
    "docs/SELF_HOSTED_CORPUS.md",
    "experiments/self_hosted_corpus_benchmark/Cargo.toml",
    "experiments/self_hosted_corpus_benchmark/Cargo.lock",
    "experiments/self_hosted_corpus_benchmark/src/main.rs",
    "experiments/self_hosted_corpus_benchmark/tests/evidence.rs",
    "experiments/self_hosted_corpus_benchmark/artifacts/2026-07-29-three-run-summary.json",
    "scripts/summarize_self_hosted_corpus_evidence.ps1",
    "scripts/build_self_hosted_corpus_evidence_manifest.ps1"
)
$rawPaths = Get-ChildItem -LiteralPath (Join-Path $repositoryRoot "experiments/self_hosted_corpus_benchmark/artifacts") -File |
    Where-Object { $_.Name -like "2026-07-29-run-*.json" } |
    Sort-Object Name |
    ForEach-Object { "experiments/self_hosted_corpus_benchmark/artifacts/$($_.Name)" }
$allPaths = @($fixedPaths) + @($rawPaths)

$artifacts = foreach ($path in $allPaths) {
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{
        path = $path.Replace("\", "/")
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-self-hosted-corpus-evidence-manifest/0.1"
    evidence_manifest_uuid = "31b4c578-ec1d-4604-978d-9420341ee7e0"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "470b328b-0b4c-432b-9e7b-b7d84a1cca0e"
        satisfaction_signature_uuid = "74f2cb02-84e4-45b2-98ca-1883c9e5d54d"
        solution_uuid = "bb88172a-e70e-4a1a-aba3-20dfa572ec40"
    }
    corpus = [ordered]@{
        source_count = 3
        unit_count = 417
        relation_count = 360
        package_id = "package:sha256:4e6e4b14d13c022b60643b77ced08081b8b5efc6a75152953c3d97f83b0ade30"
        evidence_environment_digest = "e59ea0ba39303627a7fad47a9c2892173e2f75e17bf91bc14dac5ffb00e7545b"
        generated_runtime_artifacts_tracked = $false
    }
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; status = "passed"; tests = 101 },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; status = "passed"; tests = 101 },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo clippy --all-targets --locked --offline -- -D warnings"; working_directory = "experiments/self_hosted_corpus_benchmark"; status = "passed" },
        [ordered]@{ command = "cargo test --release --locked --offline"; working_directory = "experiments/self_hosted_corpus_benchmark"; status = "passed" },
        [ordered]@{ command = "cargo audit"; working_directory = "repository root"; status = "passed"; dependencies = 110; advisories_loaded = 1173; vulnerabilities = 0 },
        [ordered]@{ command = "cargo audit"; working_directory = "experiments/self_hosted_corpus_benchmark"; status = "passed"; dependencies = 34; advisories_loaded = 1173; vulnerabilities = 0 }
    )
    artifacts = @($artifacts)
}

$json = ($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")
$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
$outputDirectory = [IO.Path]::GetDirectoryName($outputFullPath)
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
[IO.File]::WriteAllText(
    $outputFullPath,
    "$json`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
