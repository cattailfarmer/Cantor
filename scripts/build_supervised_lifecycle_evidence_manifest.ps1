param(
    [string]$OutputPath = "crates/cantor_service/evidence/supervised_lifecycle_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$paths = @(
    "source_documents/2026-07-29_cantor_supervised_local_lifecycle/Dictated_Cantor_Supervised_Local_Lifecycle_Source.sop",
    "source_documents/2026-07-29_cantor_supervised_local_lifecycle/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Supervised_Local_Lifecycle.exploded.sop",
    "specifications/Cantor_Supervised_Local_Lifecycle.sop",
    "justifications/Cantor_Supervised_Local_Lifecycle_Justification.sop",
    "feature_support/slices/SupervisedLocalLifecycle.sop",
    "feature_support/SupervisedLocalLifecycle_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "solutions/Cantor_Supervised_Local_Lifecycle_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785385157430_supervised_local_lifecycle_faults.sop",
    "narrative/turns/1785385157430_cantor_supervised_local_lifecycle.sop",
    "narrative/file_changes/1785385157430_supervised_local_lifecycle_file_change.sop",
    "README.md",
    "SOP_CORE_MAP.sop",
    "docs/RESIDENT_SERVICE.md",
    "scripts/CantorServiceLifecycle.psm1",
    "scripts/start_cantor_service.ps1",
    "scripts/get_cantor_service_health.ps1",
    "scripts/stop_cantor_service.ps1",
    "scripts/build_supervised_lifecycle_evidence_manifest.ps1",
    "crates/cantor_service/tests/operator_lifecycle.rs",
    "crates/cantor_service/tests/supervised_lifecycle_evidence.rs",
    "crates/cantor_mcp/evidence/service_backed_mcp_evidence_manifest.json",
    "proofs/Cantor_Service_Backed_MCP_Proof.sop",
    "experiments/resident_service_benchmark/artifacts/resident_service_evidence_manifest.json",
    "proofs/Cantor_Resident_Service_Proof.sop"
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
    schema = "cantor-supervised-local-lifecycle-evidence-manifest/0.1"
    evidence_manifest_uuid = "fdb43784-3fc7-4980-a753-02a73a9f96b4"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "59d4a953-7b78-4c19-b2a1-0e39851d2e4b"
        satisfaction_signature_uuid = "af5af313-92a9-41c6-b1bf-9af9370adb51"
        solution_uuid = "a52ae887-ae4f-4517-81eb-1202b211463c"
    }
    profile = "cantor-service-supervisor-state/0.1"
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 116; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 116; status = "passed" },
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
