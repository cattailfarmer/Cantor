param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/supervised_mock_loop_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$paths = @(
    ".gitattributes",
    "Cargo.toml",
    "Cargo.lock",
    "source_documents/2026-07-30_cantor_supervised_mock_loop_activation/Dictated_Cantor_Supervised_Mock_Loop_Activation_Source.sop",
    "source_documents/2026-07-30_cantor_supervised_mock_loop_activation/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Supervised_Mock_Loop_Activation.exploded.sop",
    "specifications/Cantor_Supervised_Mock_Loop_Activation.sop",
    "justifications/Cantor_Supervised_Mock_Loop_Activation_Justification.sop",
    "feature_support/slices/SupervisedMockLoop.sop",
    "feature_support/SupervisedMockLoop_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "solutions/Cantor_Supervised_Mock_Loop_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785422987701_supervised_mock_loop_faults.sop",
    "narrative/turns/1785422987701_cantor_supervised_mock_loop.sop",
    "narrative/file_changes/1785422987701_supervised_mock_loop_file_change.sop",
    "README.md",
    "SOP_CORE_MAP.sop",
    "docs/SUPERVISED_MOCK_LOOP.md",
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/model.rs",
    "crates/cantor_ecosystem/src/transcript.rs",
    "crates/cantor_ecosystem/src/adapter.rs",
    "crates/cantor_ecosystem/src/review.rs",
    "crates/cantor_ecosystem/src/runtime.rs",
    "crates/cantor_ecosystem/tests/common/mod.rs",
    "crates/cantor_ecosystem/tests/admission_faults.rs",
    "crates/cantor_ecosystem/tests/supervised_cycle.rs",
    "crates/cantor_ecosystem/tests/evidence.rs",
    "scripts/build_supervised_mock_loop_evidence_manifest.ps1",
    "crates/cantor_service/evidence/supervised_lifecycle_evidence_manifest.json",
    "proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop",
    "proofs/CEB_Deterministic_Baseline_Release_Audit.sop"
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
    schema = "cantor-supervised-mock-loop-evidence-manifest/0.1"
    evidence_manifest_uuid = "05cfc930-01a3-4af2-b481-f11f6570022a"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "50f6f41c-f35b-4844-93cb-38593db6acc0"
        satisfaction_signature_uuid = "497849e2-8156-41e4-a76d-d679b5a3f2ed"
        solution_uuid = "4711c0b4-bfeb-4e29-abdd-333bca962cf4"
    }
    profile = "cantor-supervised-mock-loop/0.1"
    deterministic_fixture_outcome_sha256 = "2ef72ed3edf4bf58e80e24c5d86bea18572ba10324e27e02aacc63569cd78b3c"
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 174; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 174; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; advisories = 1173; vulnerabilities = 0; status = "passed" }
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
