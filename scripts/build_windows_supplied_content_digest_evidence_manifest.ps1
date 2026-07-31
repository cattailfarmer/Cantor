param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_content_digest_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_stability.rs",
    "crates/cantor_ecosystem/src/windows_supplied_content_digest.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_content_digest_static.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_content_digest_evidence.rs",
    "source_documents/2026-07-31_cantor_m2b_supplied_content_digest/Cantor_M2B_Supplied_Content_Digest_Source.sop",
    "source_documents/2026-07-31_cantor_m2b_supplied_content_digest/Source_Document_Manifest.sop",
    "narrative/research/Cantor_M2B_Post_Stability_Architecture_Review_2026-07-31.sop",
    "feature_support/reviews/M2BSuppliedEntryStabilityProgram_Checkpoint_Review.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.sop",
    "proofs/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Proof.sop",
    "specifications/exploded/Cantor_M2B_Supplied_Content_Digest.exploded.sop",
    "specifications/Cantor_M2B_Supplied_Content_Digest.sop",
    "justifications/Cantor_M2B_Supplied_Content_Digest_Justification.sop",
    "plans/Cantor_M2B_Supplied_Content_Digest_Plan.sop",
    "feature_support/M2BSuppliedContentDigest_Requirement_Matrix.sop",
    "feature_support/slices/M2BSuppliedContentDigest.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "solutions/Cantor_M2B_Supplied_Content_Digest_Solution.sop",
    "feature_support/reviews/M2BSuppliedContentDigest_Completion_Review.sop",
    "narrative/registries/Cantor_M2B_Supplied_Content_Digest_Registry.sop",
    "narrative/turns/1785511100000_cantor_m2b_supplied_content_digest_source_preservation.sop",
    "narrative/turns/1785512200000_cantor_m2b_supplied_content_digest_sjs_authority.sop",
    "narrative/turns/1785514200000_cantor_m2b_supplied_content_digest_implementation.sop",
    "narrative/turns/1785514200001_cantor_m2b_supplied_content_digest_completion.sop",
    "narrative/file_changes/1785511100000_m2b_supplied_content_digest_source_file_change.sop",
    "narrative/file_changes/1785512200000_m2b_supplied_content_digest_sjs_file_change.sop",
    "narrative/file_changes/1785514200000_m2b_supplied_content_digest_implementation_file_change.sop",
    "narrative/file_changes/1785514200001_m2b_supplied_content_digest_completion_file_change.sop",
    "narrative/operational_faults/1785514200001_m2b_supplied_content_digest_application_control_fault.sop",
    "narrative/operational_faults/1785514200002_m2b_supplied_content_digest_static_vocabulary_fault.sop",
    "narrative/operational_faults/1785514200003_m2b_supplied_content_digest_lint_fault.sop",
    "narrative/operational_faults/1785514200004_m2b_supplied_content_digest_evidence_maintenance_fault.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "scripts/build_windows_supplied_content_digest_evidence_manifest.ps1"
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
    schema = "cantor-windows-supplied-content-digest-evidence-manifest/0.1"
    evidence_manifest_uuid = "818ee9be-cc73-465e-9659-8b5e547e4678"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Supplied_Content_Digest.sop"
        satisfaction_signature_uuid = "44749466-30d8-44e9-85b8-e51f1bafea33"
        stability_signature_uuid = "cbeb4260-0db0-413c-89c6-2ca164775243"
        solution_uuid = "e93871fe-2ab3-42ef-bd25-37dcdcbece78"
        implementation_commit = "21f98fabc4dd3dfa6c66450486ad5b29229339f2"
    }
    scope = [ordered]@{
        profile = "cantor-windows-supplied-content-digest/0.1"
        algorithm = "sha256"
        focused_unit_tests = 11
        focused_static_tests = 1
        focused_evidence_tests = 1
        known_sha256_vectors = 3
        plan_json_max_bytes = 4096
        maximum_content_bytes = 1099511627776
        maximum_chunks = 1048576
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        physical_byte_origin_authority = $false
        physical_read_authority = $false
        temporal_order_authority = $false
        same_handle_authority = $false
        filesystem_authority = $false
        path_authority = $false
        traversal_authority = $false
        receipt_authority = $false
        admission_authority = $false
        mutation_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib windows_supplied_content_digest --locked --offline"; passed = 11; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_content_digest_static --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_content_digest_evidence --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on focused equivalents --release --locked --offline"; passed = 13; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 319; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on -C metadata=cantor_m2b_scd_proof cargo test --workspace --all-targets --release --locked --offline"; passed = 319; ignored = 1; status = "passed" },
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 113; advisories = 1175; vulnerabilities = 0; status = "passed" }
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
