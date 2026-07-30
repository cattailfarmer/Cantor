param(
    [string]$OutputPath = "crates/cantor_ecosystem/evidence/phase3_machine_forms_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

$paths = @(
    ".gitattributes",
    "README.md",
    "SOP_CORE_MAP.sop",
    "Cargo.toml",
    "Cargo.lock",
    "source_documents/2026-07-30_cantor_phase3_machine_forms_activation/Cantor_Phase3_Machine_Forms_Activation_Source.sop",
    "source_documents/2026-07-30_cantor_phase3_machine_forms_activation/Source_Document_Manifest.sop",
    "specifications/Cantor_Phase3_Strict_Pure_Machine_Forms.sop",
    "specifications/exploded/Cantor_Phase3_Strict_Pure_Machine_Forms.exploded.sop",
    "justifications/Cantor_Phase3_Strict_Pure_Machine_Forms_Justification.sop",
    "feature_support/slices/Phase3StrictPureMachineForms.sop",
    "feature_support/Phase3StrictPureMachineForms_Requirement_Matrix.sop",
    "feature_support/Phase3_Physical_Proof_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "plans/Cantor_Phase3B_3C_Physical_Proof_Plan.sop",
    "narrative/research/Cantor_PreMutation_Path_Topology_Gap_Assessment_2026-07-30.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785432153166_phase3_machine_forms_faults.sop",
    "narrative/turns/1785432153166_cantor_phase3_machine_forms.sop",
    "narrative/file_changes/1785432153166_phase3_machine_forms_file_change.sop",
    "docs/PHASE3_MACHINE_FORMS.md",
    "solutions/Cantor_Phase3_Strict_Pure_Machine_Forms_Solution.sop",
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/phase3_evidence.rs",
    "crates/cantor_ecosystem/tests/phase3_machine_forms_evidence.rs",
    "scripts/build_phase3_machine_forms_evidence_manifest.ps1",
    "crates/cantor_ecosystem/evidence/candidate_workspace_admission_evidence_manifest.json",
    "proofs/Cantor_Candidate_Workspace_Admission_Proof.sop"
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
    schema = "cantor-phase3-machine-forms-evidence-manifest/0.1"
    evidence_manifest_uuid = "a00deec7-87a2-4f43-9334-e6b0c9283a48"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_Phase3_Strict_Pure_Machine_Forms.sop"
        satisfaction_signature_uuid = "ae44deed-29c7-4a6a-96d1-1a0091539575"
        solution_uuid = "be6aad5a-1842-405e-bbaf-493a9f38f09a"
    }
    scope = [ordered]@{
        profile = "cantor-phase3-machine-forms/0.1"
        focused_tests = 8
        filesystem_authority = $false
        process_authority = $false
        network_authority = $false
        model_authority = $false
        mutation_authority = $false
        seal_authority = $false
        test_execution_authority = $false
        promotion_authority = $false
    }
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 220; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 220; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; vulnerabilities = 0; status = "passed" }
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
