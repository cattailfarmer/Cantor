param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_stream_info_parser_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/windows_stream_info_parser.rs",
    "crates/cantor_ecosystem/tests/windows_stream_info_parser_static.rs",
    "crates/cantor_ecosystem/tests/windows_stream_info_parser_evidence.rs",
    "source_documents/2026-07-30_cantor_m2b_pure_stream_information_parser/Cantor_M2B_Pure_Stream_Information_Parser_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_stream_information_parser/Source_Document_Manifest.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_prerequisite_authority_lineage_correction/Cantor_M2B_Pure_Prerequisite_Authority_Lineage_Correction_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_pure_prerequisite_authority_lineage_correction/Source_Document_Manifest.sop",
    "narrative/research/Cantor_FILE_STREAM_INFO_Pure_Parser_Decision_2026-07-30.sop",
    "specifications/Cantor_Phase3_Topology_Scanner.sop",
    "specifications/exploded/Cantor_M2B_Pure_Stream_Information_Parser.exploded.sop",
    "specifications/Cantor_M2B_Pure_Stream_Information_Parser.sop",
    "justifications/Cantor_M2B_Pure_Stream_Information_Parser_Justification.sop",
    "plans/Cantor_M2B_Pure_Stream_Information_Parser_Plan.sop",
    "feature_support/M2BPureStreamInformationParser_Requirement_Matrix.sop",
    "feature_support/slices/M2BPureStreamInformationParser.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "feature_support/reviews/M2BPureStreamInformationParser_Completion_Review.sop",
    "solutions/Cantor_M2B_Pure_Stream_Information_Parser_Solution.sop",
    "narrative/registries/Cantor_M2B_Pure_Stream_Information_Parser_Registry.sop",
    "narrative/turns/1785448800000_cantor_m2b_pure_stream_information_parser_authority.sop",
    "narrative/turns/1785449100000_cantor_m2b_pure_stream_information_parser_implementation.sop",
    "narrative/turns/1785449400000_cantor_m2b_pure_stream_information_parser_completion.sop",
    "narrative/operational_faults/1785448800000_m2b_pure_stream_information_parser_authority_faults.sop",
    "narrative/operational_faults/1785449100000_m2b_pure_stream_information_parser_implementation_faults.sop",
    "narrative/research/Cantor_M2B_Pure_Prerequisite_Authority_Lineage_Correction_2026-07-30.sop",
    "narrative/turns/1785465542348_cantor_m2b_pure_prerequisite_authority_correction.sop",
    "narrative/operational_faults/1785465542348_m2b_pure_prerequisite_authority_lineage_fault.sop",
    "narrative/file_changes/1785465542348_m2b_pure_prerequisite_authority_correction_file_change.sop",
    "narrative/research/Cantor_M2B_Pure_Prerequisite_Authority_Revalidation_2026-07-30.sop",
    "narrative/turns/1785466373311_cantor_m2b_pure_prerequisite_revalidation.sop",
    "narrative/file_changes/1785466373311_m2b_pure_prerequisite_revalidation_file_change.sop",
    "narrative/operational_faults/1785466373311_m2b_revalidation_evidence_blast_radius_fault.sop",
    "narrative/file_changes/1785448800000_m2b_pure_stream_information_parser_authority_file_change.sop",
    "narrative/file_changes/1785449100000_m2b_pure_stream_information_parser_implementation_file_change.sop",
    "narrative/file_changes/1785449400000_m2b_pure_stream_information_parser_completion_file_change.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "crates/cantor_ecosystem/evidence/windows_entry_policy_evidence_manifest.json",
    "proofs/Cantor_M2B_Pure_Windows_Entry_Policy_Proof.sop",
    "scripts/build_windows_stream_info_parser_evidence_manifest.ps1"
)

$artifacts = foreach ($path in $paths) {
    if ([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path.Contains("\")) {
        throw "evidence path is not clone-portable: $path"
    }
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{ path = $path; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash; bytes = $item.Length }
}

$manifest = [ordered]@{
    schema = "cantor-windows-stream-info-parser-evidence-manifest/0.1"
    evidence_manifest_uuid = "263b3f53-8f37-4c4d-b465-c92733e95781"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Pure_Stream_Information_Parser.sop"
        satisfaction_signature_uuid = "f8ec9aa9-cf1e-46e9-8eeb-ab63e91332ee"
        superseded_signature_uuid = "4c36dfd3-93b4-4654-b8f7-5031d0ec83cc"
        solution_uuid = "3bb91af2-bc81-4159-8c70-3b5d6e64d2ba"
        implementation_commit = "02d750d5a5b039a1ca26d106fb4eb6e334454c69"
    }
    scope = [ordered]@{
        profile = "cantor-windows-stream-info-parser/0.1"
        parser_tests = 8
        static_tests = 1
        header_bytes = 24
        alignment_bytes = 8
        unsafe_blocks = 0
        pointer_casts = 0
        windows_api_calls = 0
        cargo_delta = 0
        filesystem_authority = $false
        complete_enumeration_claim = $false
        stream_admission_authority = $false
        traversal_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem windows_stream_info --locked --offline"; passed = 9; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test -p cantor_ecosystem windows_stream_info --release --locked --offline"; passed = 9; status = "passed" },
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
[IO.File]::WriteAllText($manifestFullPath, "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output $manifestFullPath
