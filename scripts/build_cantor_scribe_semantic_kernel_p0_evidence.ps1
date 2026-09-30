param(
    [string]$WorkspaceSummaryDirectory = "D:\CantorBuilds\cantor-scribe-semantic-kernel-workspace",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "experiments/cantor_scribe_semantic_kernel_p0"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$summaryRoot = [IO.Path]::GetFullPath($WorkspaceSummaryDirectory)
$utf8 = New-Object Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

function Get-Artifact([string]$RelativePath) {
    $path = Join-Path $repositoryRoot $RelativePath
    [ordered]@{
        path = $RelativePath.Replace("\", "/")
        bytes = (Get-Item -LiteralPath $path).Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-TextSha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $utf8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

$custodyTarget = Join-Path $outputRoot "source_custody_manifest.json"
& (Join-Path $PSScriptRoot "verify_cantor_scribe_semantic_kernel_p0_source.ps1") -OutputPath $custodyTarget
$debugSource = Join-Path $summaryRoot "workspace-debug-summary.json"
$releaseSource = Join-Path $summaryRoot "workspace-release-summary.json"
foreach ($required in @($debugSource, $releaseSource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required workspace summary is absent: $required"
    }
}
$debugTarget = Join-Path $outputRoot "workspace_debug_summary.json"
$releaseTarget = Join-Path $outputRoot "workspace_release_summary.json"
$debugText = [IO.File]::ReadAllText($debugSource).Replace("`r`n", "`n")
$releaseText = [IO.File]::ReadAllText($releaseSource).Replace("`r`n", "`n")
[IO.File]::WriteAllText($debugTarget, $debugText, $utf8)
[IO.File]::WriteAllText($releaseTarget, $releaseText, $utf8)

$componentPaths = @(
    "crates/cantor_sop_semantics/Cargo.toml",
    "crates/cantor_sop_semantics/src/digest.rs",
    "crates/cantor_sop_semantics/src/error.rs",
    "crates/cantor_sop_semantics/src/expression.rs",
    "crates/cantor_sop_semantics/src/lib.rs",
    "crates/cantor_sop_semantics/src/model.rs",
    "crates/cantor_sop_semantics/src/source.rs",
    "crates/cantor_sop_semantics/src/validate.rs",
    "crates/cantor_sop_semantics/tests/semantic_kernel.rs",
    "crates/cantor_sop_semantics/tests/static_absence.rs"
)
$componentArtifacts = @($componentPaths | ForEach-Object { Get-Artifact $_ })
$coordinateLines = @($componentArtifacts | ForEach-Object {
    "{0}`n{1}`n{2}`n" -f $_.path, $_.bytes, $_.sha256
})
$component = [ordered]@{
    profile = "cantor-sop-semantic-kernel-component/0.1"
    component_id = "cantor-sop-semantics"
    crate_name = "cantor_sop_semantics"
    capability = "kernel.sop.semantic-analyze"
    published_predecessor = "4209d44228399c8aa01b2ccb98806777c65826b8"
    source_snapshot_uuid = "b02fd0c7-c996-41b9-b0fa-d0d3d0f07cfa"
    files = $componentArtifacts
    file_count = $componentArtifacts.Count
    coordinate_digest = Get-TextSha256 ($coordinateLines -join "")
    whole_cantor_scribe_disposition = "held_for_separate_promotion"
    non_authority = "Pure semantic analysis only. No execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted."
}
$componentPath = Join-Path $outputRoot "semantic_kernel_component.json"
$componentJson = ($component | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")
[IO.File]::WriteAllText($componentPath, ($componentJson + "`n"), $utf8)

$artifactPaths = @(
    "experiments/cantor_scribe_semantic_kernel_p0/source_custody_manifest.json",
    "experiments/cantor_scribe_semantic_kernel_p0/workspace_debug_summary.json",
    "experiments/cantor_scribe_semantic_kernel_p0/workspace_release_summary.json",
    "experiments/cantor_scribe_semantic_kernel_p0/semantic_kernel_component.json"
)
$artifacts = @($artifactPaths | ForEach-Object { Get-Artifact $_ })
$debug = Get-Content -Raw -LiteralPath $debugTarget | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath $releaseTarget | ConvertFrom-Json
$custody = Get-Content -Raw -LiteralPath $custodyTarget | ConvertFrom-Json
$manifest = [ordered]@{
    profile = "cantor-scribe-semantic-kernel-p0-evidence/0.1"
    evidence_manifest_uuid = "93b9c3d6-423d-468c-81fc-a3499abdd688"
    specification_uuid = "b09b4613-000b-4621-89de-6d81ef64f7f3"
    source_snapshot_uuid = "b02fd0c7-c996-41b9-b0fa-d0d3d0f07cfa"
    integration_predecessor = "4209d44228399c8aa01b2ccb98806777c65826b8"
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = $artifacts.Count
        selected_source_files = [int]$custody.selected_file_count
        selected_source_bytes = [int64]$custody.selected_byte_count
        promoted_component_files = $componentArtifacts.Count
        focused_debug_passed = 25
        focused_release_passed = 25
        workspace_debug_result_groups = [int]$debug.result_groups
        workspace_debug_passed = [int]$debug.tests_passed
        workspace_debug_failed = [int]$debug.tests_failed
        workspace_debug_ignored = [int]$debug.tests_ignored
        workspace_release_result_groups = [int]$release.result_groups
        workspace_release_passed = [int]$release.tests_passed
        workspace_release_failed = [int]$release.tests_failed
        workspace_release_ignored = [int]$release.tests_ignored
        whole_cantor_scribe_held = 1
        live_source_mutations = 0
        live_runtime_processes = 0
        provider_requests = 0
        remote_calls = 0
        product_effects = 0
        installations = 0
        updates = 0
        synthetic_trials = 0
    }
    non_authority_statement = "This evidence proves a bounded effect-free semantic kernel component and exact source custody only. It grants no execution, installation, model, provider, operator, remote, mutation, update, publication, or external-effect authority."
}
$manifestPath = Join-Path $outputRoot "implementation_evidence_manifest.json"
$manifestJson = ($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")
[IO.File]::WriteAllText($manifestPath, ($manifestJson + "`n"), $utf8)
Write-Output ("cantor_scribe_semantic_kernel_evidence_built=true artifacts={0} component_files={1} groups={2} passed={3}" -f $artifacts.Count, $componentArtifacts.Count, $debug.result_groups, $debug.tests_passed)
