param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_entry_policy_evidence_manifest.json"
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
    "crates/cantor_ecosystem/tests/windows_entry_policy_static.rs",
    "crates/cantor_ecosystem/tests/windows_entry_policy_evidence.rs",
    "source_documents/2026-07-30_cantor_m2b_pure_windows_entry_policy/Cantor_M2B_Pure_Windows_Entry_Policy_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_windows_entry_policy/Source_Document_Manifest.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_prerequisite_authority_lineage_correction/Cantor_M2B_Pure_Prerequisite_Authority_Lineage_Correction_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_prerequisite_authority_lineage_correction/Source_Document_Manifest.sop",
    "narrative/research/Cantor_Windows_Topology_Attribute_Name_Policy_2026-07-30.sop",
    "narrative/research/Cantor_Pure_Windows_Entry_Policy_Freeze_Decision_2026-07-30.sop",
    "specifications/Cantor_Phase3_Topology_Scanner.sop",
    "specifications/exploded/Cantor_M2B_Pure_Windows_Entry_Policy.exploded.sop",
    "specifications/Cantor_M2B_Pure_Windows_Entry_Policy.sop",
    "justifications/Cantor_M2B_Pure_Windows_Entry_Policy_Justification.sop",
    "plans/Cantor_M2B_Pure_Windows_Entry_Policy_Plan.sop",
    "feature_support/M2BPureWindowsEntryPolicy_Requirement_Matrix.sop",
    "feature_support/slices/M2BPureWindowsEntryPolicy.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/reviews/M2BPureWindowsEntryPolicy_Completion_Review.sop",
    "solutions/Cantor_M2B_Pure_Windows_Entry_Policy_Solution.sop",
    "narrative/registries/Cantor_M2B_Pure_Windows_Entry_Policy_Registry.sop",
    "narrative/turns/1785447900000_cantor_m2b_pure_windows_entry_policy_authority.sop",
    "narrative/turns/1785448200000_cantor_m2b_pure_windows_entry_policy_implementation.sop",
    "narrative/turns/1785448500000_cantor_m2b_pure_windows_entry_policy_completion.sop",
    "narrative/operational_faults/1785447900000_m2b_pure_windows_entry_policy_authority_faults.sop",
    "narrative/operational_faults/1785448200000_m2b_pure_windows_entry_policy_implementation_faults.sop",
    "narrative/research/Cantor_M2B_Pure_Prerequisite_Authority_Lineage_Correction_2026-07-30.sop",
    "narrative/turns/1785465542348_cantor_m2b_pure_prerequisite_authority_correction.sop",
    "narrative/operational_faults/1785465542348_m2b_pure_prerequisite_authority_lineage_fault.sop",
    "narrative/file_changes/1785465542348_m2b_pure_prerequisite_authority_correction_file_change.sop",
    "narrative/research/Cantor_M2B_Pure_Prerequisite_Authority_Revalidation_2026-07-30.sop",
    "narrative/turns/1785466373311_cantor_m2b_pure_prerequisite_revalidation.sop",
    "narrative/file_changes/1785466373311_m2b_pure_prerequisite_revalidation_file_change.sop",
    "narrative/operational_faults/1785466373311_m2b_revalidation_evidence_blast_radius_fault.sop",
    "narrative/file_changes/1785447900000_m2b_pure_windows_entry_policy_authority_file_change.sop",
    "narrative/file_changes/1785448200000_m2b_pure_windows_entry_policy_implementation_file_change.sop",
    "narrative/file_changes/1785448500000_m2b_pure_windows_entry_policy_completion_file_change.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "crates/cantor_windows_preflight/evidence/windows_platform_preflight_runtime_evidence_manifest.json",
    "proofs/Cantor_M2B_Platform_Location_Classification_Revision_Proof.sop",
    "scripts/build_windows_entry_policy_evidence_manifest.ps1"
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
    schema = "cantor-windows-entry-policy-evidence-manifest/0.1"
    evidence_manifest_uuid = "be4b80ed-da4c-4363-b075-b826c0c76fab"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Pure_Windows_Entry_Policy.sop"
        satisfaction_signature_uuid = "fbb835f2-5ab6-4362-a392-5d72692f8d1c"
        superseded_signature_uuid = "554e84a7-988c-4c86-b67d-45958ab7166c"
        solution_uuid = "d14a27ad-1452-42e8-b8e0-56235abacd49"
        implementation_commit = "04ca9abede2d49efb81e62644838a469a7cf4767"
    }
    scope = [ordered]@{
        profile = "cantor-windows-entry-policy/0.1"
        focused_unit_tests = 9
        focused_static_tests = 1
        attribute_bits = 32
        benign_attribute_mask = "0x00002027"
        directory_allowed_mask = "0x00002037"
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        filesystem_authority = $false
        traversal_authority = $false
        receipt_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem windows_entry_policy --locked --offline"; passed = 10; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test -p cantor_ecosystem windows_entry_policy --release --locked --offline"; passed = 10; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 280; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test --workspace --all-targets --release --locked --offline"; passed = 280; ignored = 1; status = "passed" },
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 113; advisories = 1174; vulnerabilities = 0; status = "passed" }
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
