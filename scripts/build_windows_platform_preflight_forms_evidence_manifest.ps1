param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest.json"
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
    "source_documents/2026-07-30_cantor_m2b_platform_preflight_forms/Cantor_M2B_Platform_Preflight_Forms_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_platform_preflight_forms/Source_Document_Manifest.sop",
    "narrative/research/Cantor_Windows_Platform_Preflight_Forms_Assessment_2026-07-30.sop",
    "specifications/exploded/Cantor_M2B_Platform_Preflight_Forms.exploded.sop",
    "specifications/Cantor_M2B_Platform_Preflight_Forms.sop",
    "justifications/Cantor_M2B_Platform_Preflight_Forms_Justification.sop",
    "plans/Cantor_M2B_Platform_Preflight_Forms_Plan.sop",
    "feature_support/M2BPlatformPreflightForms_Requirement_Matrix.sop",
    "feature_support/slices/M2BPlatformPreflightForms.sop",
    "narrative/registries/Cantor_M2B_Platform_Preflight_Forms_Registry.sop",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/topology_forms.rs",
    "crates/cantor_ecosystem/src/platform_preflight_forms.rs",
    "crates/cantor_ecosystem/tests/windows_platform_preflight_forms_evidence.rs",
    "solutions/Cantor_M2B_Platform_Preflight_Forms_Solution.sop",
    "feature_support/reviews/M2BPlatformPreflightForms_Completion_Review.sop",
    "feature_support/Phase3TopologyScanner_Requirement_Matrix.sop",
    "plans/Cantor_Phase3_M2B_Activation_Readiness.sop",
    "narrative/Project_Narrative.sop",
    "narrative/reentry/Cantor_M2B_Current_Reentry.sop",
    "narrative/operational_faults/1785441000000_m2b_platform_preflight_forms_faults.sop",
    "narrative/turns/1785441000000_cantor_m2b_platform_preflight_forms.sop",
    "narrative/file_changes/1785441000000_m2b_platform_preflight_forms_file_change.sop",
    "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest_0_1.json",
    "proofs/Cantor_M2B_Platform_Preflight_Forms_Proof.sop",
    "source_documents/2026-07-30_cantor_m2b_platform_preflight_fault_provenance_revision/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Source.sop",
    "source_documents/2026-07-30_cantor_m2b_platform_preflight_fault_provenance_revision/Source_Document_Manifest.sop",
    "narrative/research/Cantor_Windows_Platform_Preflight_Unsafe_Seam_Gap_Assessment_2026-07-30.sop",
    "specifications/exploded/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision.exploded.sop",
    "specifications/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision.sop",
    "justifications/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Justification.sop",
    "plans/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Plan.sop",
    "feature_support/M2BPlatformPreflightFaultProvenanceRevision_Requirement_Matrix.sop",
    "feature_support/slices/M2BPlatformPreflightFaultProvenanceRevision.sop",
    "narrative/registries/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Registry.sop",
    "narrative/operational_faults/1785442827989_m2b_platform_preflight_fault_provenance_revision_faults.sop",
    "narrative/turns/1785442827989_cantor_m2b_platform_preflight_fault_provenance_revision.sop",
    "narrative/file_changes/1785442827989_m2b_platform_preflight_fault_provenance_revision_file_change.sop",
    "solutions/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision_Solution.sop",
    "feature_support/reviews/M2BPlatformPreflightFaultProvenanceRevision_Completion_Review.sop",
    "crates/cantor_ecosystem/evidence/windows_topology_abi_probe_evidence_manifest.json",
    "proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop",
    "crates/cantor_ecosystem/evidence/phase3_topology_forms_evidence_manifest.json",
    "proofs/Cantor_Phase3_Topology_Receipt_Root_Binding_Revision_Proof.sop",
    "scripts/build_windows_platform_preflight_forms_evidence_manifest.ps1"
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
    schema = "cantor-windows-platform-preflight-forms-evidence-manifest/0.2"
    evidence_manifest_uuid = "e28c0fd9-2fca-4d9e-8f2c-c9556101fc66"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Platform_Preflight_Fault_Provenance_Revision.sop"
        satisfaction_signature_uuid = "43ac3353-ea22-4f02-894e-59302e6ef4a5"
        solution_uuid = "7d7180f0-1ac6-4b3d-8854-3f854f38ad85"
        implementation_commit = "d7dfe40"
    }
    scope = [ordered]@{
        request_profile = "cantor-windows-platform-preflight-request/0.1"
        result_profile = "cantor-windows-platform-preflight/0.2"
        target = "x86_64-pc-windows-msvc"
        outcomes = 4
        observation_fault_classes = 3
        query_stages = 4
        dispositions = 3
        focused_tests = 12
        windows_api_calls = 0
        unsafe_blocks = 0
        cargo_delta = 0
        filesystem_authority = $false
        scanner_authority = $false
        receipt_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib platform_preflight_forms --locked --offline"; tests = 12; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --lib --release platform_preflight_forms --locked --offline"; tests = 12; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 251; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 251; status = "passed" },
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; advisories = 1174; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$manifestFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $manifestFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $manifestFullPath
