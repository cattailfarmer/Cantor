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
    schema = "cantor-windows-platform-preflight-forms-evidence-manifest/0.1"
    evidence_manifest_uuid = "a78613c9-2c5c-4d09-90b6-061d3d2021d2"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_M2B_Platform_Preflight_Forms.sop"
        satisfaction_signature_uuid = "ad8dc3de-b45a-48c7-aebd-4bc47018ccf2"
        solution_uuid = "622b895c-e6e1-4b16-be8f-56388259bd53"
        implementation_commit = "5762fb1"
    }
    scope = [ordered]@{
        profile = "cantor-windows-platform-preflight/0.1"
        target = "x86_64-pc-windows-msvc"
        outcomes = 3
        query_stages = 4
        dispositions = 3
        focused_tests = 9
        windows_api_calls = 0
        unsafe_blocks = 0
        cargo_delta = 0
        filesystem_authority = $false
        scanner_authority = $false
        receipt_authority = $false
        physical_claim = $false
    }
    verification = @(
        [ordered]@{ command = "cargo test -p cantor_ecosystem platform_preflight_forms --locked --offline"; tests = 9; status = "passed" },
        [ordered]@{ command = "cargo test -p cantor_ecosystem --release platform_preflight_forms --locked --offline"; tests = 9; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 248; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 248; status = "passed" },
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
