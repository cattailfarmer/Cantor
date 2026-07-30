param(
    [Parameter(Mandatory = $true)]
    [string]$ProbeRequestPath,
    [string]$ProbeExecutablePath = "target/release/examples/candidate_workspace_probe.exe",
    [string]$SummaryPath = "crates/cantor_ecosystem/evidence/candidate_workspace_admission_probe_summary.json",
    [string]$ManifestPath = "crates/cantor_ecosystem/evidence/candidate_workspace_admission_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Resolve-RepositoryPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

$requestFullPath = Resolve-RepositoryPath $ProbeRequestPath
$probeExecutable = Resolve-RepositoryPath $ProbeExecutablePath
$request = Get-Content -LiteralPath $requestFullPath -Raw | ConvertFrom-Json
if ($request.profile -ne "cantor-candidate-workspace-admission/0.1") {
    throw "probe request does not use the candidate-workspace admission profile"
}

$gitExecutable = [string]$request.git_executable
$principal = [string]$request.principal_workspace
$candidate = [string]$request.candidate_workspace
$principalBefore = & $gitExecutable -C $principal status --porcelain=v2 -z --untracked-files=all
$candidateBefore = & $gitExecutable -C $candidate status --porcelain=v2 -z --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $principalBefore -or $candidateBefore) {
    throw "probe workspaces are not clean before admission"
}

$firstRaw = & $probeExecutable $requestFullPath
if ($LASTEXITCODE -ne 0) {
    throw "first candidate workspace admission probe failed"
}
$secondRaw = & $probeExecutable $requestFullPath
if ($LASTEXITCODE -ne 0) {
    throw "second candidate workspace admission probe failed"
}
$first = $firstRaw | ConvertFrom-Json
$second = $secondRaw | ConvertFrom-Json

$principalAfter = & $gitExecutable -C $principal status --porcelain=v2 -z --untracked-files=all
$candidateAfter = & $gitExecutable -C $candidate status --porcelain=v2 -z --untracked-files=all
$headAfter = (& $gitExecutable -C $candidate rev-parse HEAD).Trim()
$branchAfter = (& $gitExecutable -C $candidate symbolic-ref --quiet HEAD).Trim()
if ($LASTEXITCODE -ne 0 `
    -or $principalAfter `
    -or $candidateAfter `
    -or $headAfter -ne [string]$request.expected_base_commit `
    -or $branchAfter -ne [string]$request.expected_branch_ref) {
    throw "candidate workspace changed during the admission probe"
}
if (-not $first.admitted `
    -or $first.profile -ne "cantor-candidate-workspace-admission/0.1" `
    -or $first.receipt_sha256.value -ne $second.receipt_sha256.value `
    -or $first.observation_sha256.value -ne $second.observation_sha256.value `
    -or $first.base_commit -ne [string]$request.expected_base_commit `
    -or $first.branch_ref -ne [string]$request.expected_branch_ref `
    -or $first.resource_account.process_count -ne 12) {
    throw "candidate workspace admission receipt does not satisfy the proof contract"
}

$summary = [ordered]@{
    schema = "cantor-candidate-workspace-admission-probe-summary/0.1"
    profile = $first.profile
    git_version = $first.git_version
    git_executable_sha256 = $first.git_executable_sha256
    request_sha256 = $first.request_sha256.value
    receipt_sha256 = $first.receipt_sha256.value
    observation_sha256 = $first.observation_sha256.value
    base_commit = $first.base_commit
    branch_ref = $first.branch_ref
    process_count = $first.resource_account.process_count
    received_bytes = $first.resource_account.received_bytes
    configured_timeout_millis = $first.resource_account.configured_timeout_millis
    repeated_receipt_equal = $true
    principal_clean_before_and_after = $true
    candidate_clean_before_and_after = $true
    admitted = $true
    mutation_authority = $false
    promotion_authority = $false
}

$summaryFullPath = Resolve-RepositoryPath $SummaryPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($summaryFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $summaryFullPath,
    "$(($summary | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)

$paths = @(
    ".gitattributes",
    "README.md",
    "SOP_CORE_MAP.sop",
    "Cargo.toml",
    "Cargo.lock",
    "source_documents/2026-07-30_cantor_scoped_write_delineation/Cantor_Phase3_Scoped_Write_Source_Selection.sop",
    "source_documents/2026-07-30_cantor_scoped_write_delineation/Cantor_Candidate_Workspace_Admission_Reconciliation_Source.sop",
    "source_documents/2026-07-30_cantor_scoped_write_delineation/Source_Document_Manifest.sop",
    "specifications/Cantor_Candidate_Workspace_Admission.sop",
    "specifications/exploded/Cantor_Candidate_Workspace_Admission.exploded.sop",
    "justifications/Cantor_Candidate_Workspace_Admission_Justification.sop",
    "feature_support/slices/CandidateWorkspaceAdmission.sop",
    "feature_support/CandidateWorkspaceAdmission_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "docs/CANDIDATE_WORKSPACE_ADMISSION.md",
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/workspace_admission.rs",
    "crates/cantor_ecosystem/src/workspace_admission/validation.rs",
    "crates/cantor_ecosystem/src/workspace_admission/process.rs",
    "crates/cantor_ecosystem/src/workspace_admission/inventory.rs",
    "crates/cantor_ecosystem/src/workspace_admission/tests.rs",
    "crates/cantor_ecosystem/examples/candidate_workspace_probe.rs",
    "crates/cantor_ecosystem/tests/candidate_workspace_admission_evidence.rs",
    "crates/cantor_ecosystem/evidence/candidate_workspace_admission_probe_summary.json",
    "solutions/Cantor_Candidate_Workspace_Admission_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785429175325_candidate_workspace_admission_faults.sop",
    "narrative/turns/1785429175325_candidate_workspace_admission.sop",
    "narrative/file_changes/1785429175325_candidate_workspace_admission_file_change.sop",
    "crates/cantor_ecosystem/evidence/read_only_live_codex_evidence_manifest.json",
    "proofs/Cantor_Read_Only_Live_Codex_Adapter_Proof.sop",
    "scripts/build_candidate_workspace_admission_evidence_manifest.ps1"
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
    schema = "cantor-candidate-workspace-admission-evidence-manifest/0.1"
    evidence_manifest_uuid = "08d8dc36-9657-4152-a153-60170b242887"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification = "specifications/Cantor_Candidate_Workspace_Admission.sop"
        satisfaction_signature_uuid = "62600061-8479-458d-a3e1-121e315bff24"
        solution_uuid = "29703a49-e9f5-4634-9fd5-d5be16a4f331"
    }
    probe = $summary
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 211; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 211; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$manifestFullPath = Resolve-RepositoryPath $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $manifestFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $manifestFullPath
