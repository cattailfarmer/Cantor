param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_entry_stability_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/windows_entry_policy.rs",
    "crates/cantor_ecosystem/src/windows_stream_info_parser.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_observation.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_stability.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_entry_stability_static.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_entry_stability_evidence.rs",
    "source_documents/2026-07-31_cantor_m2b_supplied_entry_stability_reconciliation/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Source.sop",
    "source_documents/2026-07-31_cantor_m2b_supplied_entry_stability_reconciliation/Source_Document_Manifest.sop",
    "narrative/research/Cantor_M2B_Post_Supplied_Assembly_Architecture_Review_2026-07-31.sop",
    "feature_support/reviews/M2BSuppliedEntryObservationProgram_Checkpoint_Review.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Observation_Assembly.sop",
    "specifications/exploded/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.exploded.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.sop",
    "justifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Justification.sop",
    "plans/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Plan.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "feature_support/M2BSuppliedEntryStabilityReconciliation_Requirement_Matrix.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "feature_support/slices/M2BSuppliedEntryStabilityReconciliation.sop",
    "feature_support/reviews/M2BSuppliedEntryStabilityReconciliation_Completion_Review.sop",
    "solutions/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Solution.sop",
    "narrative/registries/Cantor_M2B_Supplied_Entry_Stability_Reconciliation_Registry.sop",
    "narrative/turns/1785508766699_cantor_m2b_stability_sjs_authority.sop",
    "narrative/turns/1785509660000_cantor_m2b_supplied_entry_stability_implementation.sop",
    "narrative/turns/1785509660001_cantor_m2b_supplied_entry_stability_completion.sop",
    "narrative/file_changes/1785508766699_m2b_stability_sjs_authority_file_change.sop",
    "narrative/file_changes/1785509660000_m2b_supplied_entry_stability_implementation_file_change.sop",
    "narrative/file_changes/1785509660001_m2b_supplied_entry_stability_completion_file_change.sop",
    "narrative/operational_faults/1785509180996_m2b_stability_sjs_binding_verifier_command_fault.sop",
    "narrative/operational_faults/1785509660002_m2b_stability_preclosure_evidence_fault.sop",
    "narrative/operational_faults/1785509660003_m2b_stability_application_control_fault.sop",
    "narrative/operational_faults/1785509660004_m2b_stability_manifest_execution_policy_fault.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "scripts/build_windows_supplied_entry_stability_evidence_manifest.ps1"
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
    schema = "cantor-windows-supplied-entry-stability-evidence-manifest/0.1"
    evidence_manifest_uuid = "7c52a0e7-fda0-48d6-8daf-bf9f0e59fad8"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Supplied_Entry_Stability_Reconciliation.sop"
        satisfaction_signature_uuid = "cbeb4260-0db0-413c-89c6-2ca164775243"
        assembly_signature_uuid = "4b2bf473-b10e-4ca6-a39b-f68c3a7f3719"
        solution_uuid = "c58dfcb7-2a0b-494c-9ba3-0bb9a09a86d0"
        implementation_commit = "96c45fb8e804fb8c55905687ff1cfd13c8ae5b17"
    }
    scope = [ordered]@{
        profile = "cantor-windows-supplied-entry-stability/0.1"
        compared_fields = 8
        focused_unit_tests = 11
        focused_static_tests = 1
        focused_evidence_tests = 1
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        physical_query_authority = $false
        temporal_order_authority = $false
        same_handle_authority = $false
        filesystem_authority = $false
        content_read_authority = $false
        traversal_authority = $false
        receipt_authority = $false
        admission_authority = $false
        mutation_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib windows_supplied_entry_stability --locked --offline"; passed = 11; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_entry_stability_static --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_entry_stability_evidence --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on focused equivalents --release --locked --offline"; passed = 13; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 306; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test --workspace --all-targets --release --locked --offline"; passed = 306; ignored = 1; status = "passed" },
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
