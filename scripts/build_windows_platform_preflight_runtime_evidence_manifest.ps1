param(
    [string]$OutputPath = "crates/cantor_windows_preflight/evidence/windows_platform_preflight_runtime_evidence_manifest.json"
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
    "crates/cantor_ecosystem/src/platform_preflight_forms.rs",
    "crates/cantor_ecosystem/tests/windows_platform_preflight_forms_evidence.rs",
    "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest_0_1.json",
    "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest_0_2.json",
    "proofs/Cantor_M2B_Platform_Preflight_Forms_Proof.sop",
    "proofs/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Proof.sop",
    "crates/cantor_ecosystem/evidence/windows_topology_abi_probe_evidence_manifest.json",
    "proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop",
    "source_documents/2026-07-30_cantor_m2b_windows_platform_preflight_runtime/Cantor_M2B_Windows_Platform_Preflight_Runtime_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_windows_platform_preflight_runtime/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_M2B_Windows_Platform_Preflight_Runtime.exploded.sop",
    "specifications/Cantor_M2B_Windows_Platform_Preflight_Runtime.sop",
    "justifications/Cantor_M2B_Windows_Platform_Preflight_Runtime_Justification.sop",
    "plans/Cantor_M2B_Windows_Platform_Preflight_Runtime_Plan.sop",
    "feature_support/M2BWindowsPlatformPreflightRuntime_Requirement_Matrix.sop",
    "feature_support/slices/M2BWindowsPlatformPreflightRuntime.sop",
    "narrative/registries/Cantor_M2B_Windows_Platform_Preflight_Runtime_Registry.sop",
    "narrative/research/Cantor_Windows_Platform_Preflight_Runtime_Closure_Assessment_2026-07-30.sop",
    "narrative/operational_faults/1785444647333_m2b_windows_platform_preflight_runtime_authority_faults.sop",
    "narrative/operational_faults/1785445529246_m2b_windows_platform_preflight_runtime_implementation_faults.sop",
    "narrative/turns/1785444647333_cantor_m2b_windows_platform_preflight_runtime_authority.sop",
    "narrative/turns/1785445529246_cantor_m2b_windows_platform_preflight_runtime_implementation.sop",
    "narrative/file_changes/1785444647333_m2b_windows_platform_preflight_runtime_authority_file_change.sop",
    "narrative/file_changes/1785445529246_m2b_windows_platform_preflight_runtime_implementation_file_change.sop",
    "source_documents/2026-07-30_cantor_m2b_platform_location_classification_revision/Cantor_M2B_Platform_Location_Classification_Revision_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_platform_location_classification_revision/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_M2B_Platform_Location_Classification_Revision.exploded.sop",
    "specifications/Cantor_M2B_Platform_Location_Classification_Revision.sop",
    "justifications/Cantor_M2B_Platform_Location_Classification_Revision_Justification.sop",
    "plans/Cantor_M2B_Platform_Location_Classification_Revision_Plan.sop",
    "feature_support/M2BPlatformLocationClassificationRevision_Requirement_Matrix.sop",
    "feature_support/slices/M2BPlatformLocationClassificationRevision.sop",
    "feature_support/reviews/M2BPlatformLocationClassificationRevision_Completion_Review.sop",
    "solutions/Cantor_M2B_Platform_Location_Classification_Revision_Solution.sop",
    "narrative/registries/Cantor_M2B_Platform_Location_Classification_Revision_Registry.sop",
    "narrative/research/Cantor_Windows_Platform_Preflight_Physical_Remote_Query_Finding_2026-07-30.sop",
    "narrative/research/Cantor_Platform_Preflight_Request_Profile_Versioning_Decision_2026-07-30.sop",
    "narrative/operational_faults/1785446152873_m2b_platform_location_classification_revision_authority_faults.sop",
    "narrative/operational_faults/1785446419762_m2b_platform_location_classification_revision_implementation_faults.sop",
    "narrative/turns/1785446152873_cantor_m2b_platform_location_classification_revision_authority.sop",
    "narrative/turns/1785446419762_cantor_m2b_platform_location_classification_revision_implementation.sop",
    "narrative/turns/1785446500000_cantor_m2b_platform_location_classification_physical_completion.sop",
    "narrative/file_changes/1785446152873_m2b_platform_location_classification_revision_authority_file_change.sop",
    "narrative/file_changes/1785446419762_m2b_platform_location_classification_revision_implementation_file_change.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "crates/cantor_windows_preflight/Cargo.toml",
    "crates/cantor_windows_preflight/src/lib.rs",
    "crates/cantor_windows_preflight/tests/runtime_contract.rs",
    "crates/cantor_windows_preflight/tests/runtime_evidence.rs",
    "crates/cantor_windows_preflight/evidence/windows_platform_preflight_physical_observation_0_1_blocked.json",
    "crates/cantor_windows_preflight/evidence/windows_platform_preflight_physical_observation.json",
    "scripts/run_windows_platform_preflight_fixture.ps1",
    "scripts/build_windows_platform_preflight_runtime_evidence_manifest.ps1"
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
    schema = "cantor-windows-platform-preflight-runtime-evidence-manifest/0.1"
    evidence_manifest_uuid = "aec65378-786a-4aeb-96a4-6d7b13ca6a58"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Platform_Location_Classification_Revision.sop"
        satisfaction_signature_uuid = "61c2b9cf-4608-4e7d-88ae-d674d52640e3"
        solution_uuid = "b4879cd8-24ef-43bf-bdf6-7b3d28164aff"
        implementation_commit = "216cf92224aec12759cbff209e973fa239c5526b"
    }
    scope = [ordered]@{
        request_profile = "cantor-windows-platform-preflight-request/0.2"
        result_profile = "cantor-windows-platform-preflight/0.3"
        runtime_profile = "cantor-windows-platform-preflight-runtime/0.2"
        focused_form_tests = 12
        focused_runtime_tests = 8
        physical_tests_ignored_by_default = 1
        unsafe_blocks = 6
        safety_comments = 6
        owner_types = 1
        physical_local_claim = $true
        physical_remote_claim = $false
        scanner_authority = $false
        receipt_authority = $false
    }
    physical = [ordered]@{
        blocked_observation_sha256 = "67832AA3573707257E8B4A2144AF177E352BD7AE64BCEC12577837F8E2D075B8"
        complete_local_observation_sha256 = "3B52E87929AC4C42D640C7C29F70BA88D43A6417C31CEB361F59172803924D46"
        complete_local_disposition = "eligible_local_ntfs"
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib platform_preflight_forms --locked --offline"; tests = 12; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_windows_preflight --all-targets --locked --offline"; passed = 7; ignored = 1; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; passed = 259; ignored = 1; status = "passed" },
        [ordered]@{ command = "RUSTFLAGS=-C overflow-checks=on cargo test --workspace --all-targets --release --locked --offline"; passed = 259; ignored = 1; status = "passed" },
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
