param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_supplied_entry_observation_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/topology_forms.rs",
    "crates/cantor_ecosystem/src/windows_entry_policy.rs",
    "crates/cantor_ecosystem/src/windows_stream_info_parser.rs",
    "crates/cantor_ecosystem/src/windows_supplied_entry_observation.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_entry_observation_static.rs",
    "crates/cantor_ecosystem/tests/windows_supplied_entry_observation_evidence.rs",
    "source_documents/2026-07-30_cantor_m2b_supplied_entry_observation_assembly/Cantor_M2B_Supplied_Entry_Observation_Assembly_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_supplied_entry_observation_assembly/Source_Document_Manifest.sop",
    "narrative/research/Cantor_M2B_Post_Pure_Prerequisite_Readiness_Review_2026-07-30.sop",
    "narrative/research/Cantor_M2B_Supplied_Entry_Observation_Assembly_Design_Decision_2026-07-30.sop",
    "specifications/Cantor_Phase3_Topology_Machine_Forms.sop",
    "specifications/Cantor_M2B_Pure_Windows_Entry_Policy.sop",
    "specifications/Cantor_M2B_Pure_Stream_Information_Parser.sop",
    "specifications/exploded/Cantor_M2B_Supplied_Entry_Observation_Assembly.exploded.sop",
    "specifications/Cantor_M2B_Supplied_Entry_Observation_Assembly.sop",
    "justifications/Cantor_M2B_Supplied_Entry_Observation_Assembly_Justification.sop",
    "plans/Cantor_M2B_Supplied_Entry_Observation_Assembly_Plan.sop",
    "feature_support/M2BSuppliedEntryObservationAssembly_Requirement_Matrix.sop",
    "feature_support/slices/M2BSuppliedEntryObservationAssembly.sop",
    "feature_support/reviews/M2BSuppliedEntryObservationAssembly_Completion_Review.sop",
    "solutions/Cantor_M2B_Supplied_Entry_Observation_Assembly_Solution.sop",
    "narrative/registries/Cantor_M2B_Supplied_Entry_Observation_Assembly_Registry.sop",
    "narrative/turns/1785467390297_cantor_m2b_supplied_entry_observation_assembly_authority.sop",
    "narrative/turns/1785468044694_cantor_m2b_supplied_entry_observation_implementation.sop",
    "narrative/turns/1785468044698_cantor_m2b_supplied_entry_observation_completion.sop",
    "narrative/file_changes/1785467390297_m2b_supplied_entry_observation_assembly_authority_file_change.sop",
    "narrative/file_changes/1785468044694_m2b_supplied_entry_observation_implementation_file_change.sop",
    "narrative/file_changes/1785468044698_m2b_supplied_entry_observation_completion_file_change.sop",
    "narrative/operational_faults/1785468044694_m2b_supplied_entry_observation_test_oracle_fault.sop",
    "narrative/operational_faults/1785468044695_m2b_supplied_entry_observation_application_control_fault.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "scripts/build_windows_supplied_entry_observation_evidence_manifest.ps1"
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
    schema = "cantor-windows-supplied-entry-observation-evidence-manifest/0.1"
    evidence_manifest_uuid = "2973edde-d2dc-4d74-86ce-7e337ba7e614"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Supplied_Entry_Observation_Assembly.sop"
        satisfaction_signature_uuid = "4b2bf473-b10e-4ca6-a39b-f68c3a7f3719"
        entry_policy_signature_uuid = "fbb835f2-5ab6-4362-a392-5d72692f8d1c"
        stream_parser_signature_uuid = "f8ec9aa9-cf1e-46e9-8eeb-ab63e91332ee"
        solution_uuid = "1dd7d09c-8416-46dd-a70b-0902b5de799d"
        implementation_commit = "3383448529fc1e98365ee02ad8bd1dea3f08d376"
    }
    scope = [ordered]@{
        profile = "cantor-windows-supplied-entry-observation/0.1"
        required_record_classes = 5
        focused_unit_tests = 11
        focused_static_tests = 1
        maximum_streams = 1024
        maximum_stream_name_utf16_units = 32767
        unsafe_blocks = 0
        windows_api_calls = 0
        cargo_delta = 0
        physical_query_authority = $false
        filesystem_authority = $false
        traversal_authority = $false
        receipt_authority = $false
        mutation_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib windows_supplied --locked --offline"; passed = 11; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_entry_observation_static --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --test windows_supplied_entry_observation_evidence --locked --offline"; passed = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on focused equivalents --release --locked --offline"; passed = 13; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 293; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test --workspace --all-targets --release --locked --offline"; passed = 293; ignored = 1; status = "passed" },
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
