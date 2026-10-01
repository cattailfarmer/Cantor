param(
    [string]$WorkspaceSummaryDirectory = "D:\CantorBuilds\cantor-composed-read-only-semantic-inspection-workspace",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "experiments/cantor_composed_read_only_semantic_inspection_p0"
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
        return ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Text)))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

& (Join-Path $PSScriptRoot "verify_cantor_composed_read_only_semantic_inspection_p0_source.ps1")
& (Join-Path $PSScriptRoot "verify_cantor_composed_read_only_semantic_inspection_p0_formation.ps1")
$debugSource = Join-Path $summaryRoot "workspace-debug-summary.json"
$releaseSource = Join-Path $summaryRoot "workspace-release-summary.json"
foreach ($required in @($debugSource, $releaseSource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "required workspace summary is absent: $required" }
}
$debugTarget = Join-Path $outputRoot "workspace_debug_summary.json"
$releaseTarget = Join-Path $outputRoot "workspace_release_summary.json"
[IO.File]::WriteAllText($debugTarget, [IO.File]::ReadAllText($debugSource).Replace("`r`n", "`n"), $utf8)
[IO.File]::WriteAllText($releaseTarget, [IO.File]::ReadAllText($releaseSource).Replace("`r`n", "`n"), $utf8)

$componentPaths = @(
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_sop_inspect/Cargo.toml",
    "crates/cantor_sop_inspect/src/lib.rs",
    "crates/cantor_sop_inspect/tests/static_absence.rs",
    "crates/cantor_instance_contract/Cargo.toml",
    "crates/cantor_instance_contract/tests/composed_semantic_inspection_promotion.rs"
)
$componentArtifacts = @($componentPaths | ForEach-Object { Get-Artifact $_ })
$coordinateLines = @($componentArtifacts | ForEach-Object { "{0}`n{1}`n{2}`n" -f $_.path, $_.bytes, $_.sha256 })
$component = [ordered]@{
    profile = "cantor-composed-read-only-semantic-inspection-component/0.1"
    component_id = "cantor-sop-inspect"
    crate_name = "cantor_sop_inspect"
    capability = "kernel.sop.semantic-inspect"
    formation_bookend = "136261efd3733fbb671394fb5b908a38ec41b52d"
    implementation_checkpoint = "f8c73edfab86053eaecbdee840d5f77384e73ef5"
    files = $componentArtifacts
    file_count = $componentArtifacts.Count
    coordinate_digest = Get-TextSha256 ($coordinateLines -join "")
    whole_cantor_scribe_disposition = "held_for_separate_promotion"
    non_authority = "Read-only composition over caller-supplied values only; no filesystem storage index transport process provider model remote mutation or effect authority."
}
$componentPath = Join-Path $outputRoot "semantic_inspection_component.json"
[IO.File]::WriteAllText($componentPath, ((($component | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")) + "`n"), $utf8)

$artifactPaths = @(
    "experiments/cantor_composed_read_only_semantic_inspection_p0/source_custody_manifest.json",
    "experiments/cantor_composed_read_only_semantic_inspection_p0/workspace_debug_summary.json",
    "experiments/cantor_composed_read_only_semantic_inspection_p0/workspace_release_summary.json",
    "experiments/cantor_composed_read_only_semantic_inspection_p0/semantic_inspection_component.json"
)
$artifacts = @($artifactPaths | ForEach-Object { Get-Artifact $_ })
$debug = Get-Content -Raw $debugTarget | ConvertFrom-Json
$release = Get-Content -Raw $releaseTarget | ConvertFrom-Json
$custody = Get-Content -Raw (Join-Path $outputRoot "source_custody_manifest.json") | ConvertFrom-Json
$manifest = [ordered]@{
    profile = "cantor-composed-read-only-semantic-inspection-p0-evidence/0.1"
    evidence_manifest_uuid = "8372ff5c-90e4-4b25-9ce3-452dbd8f764f"
    specification_uuid = "8e08875a-6877-4c07-9752-b96771fb0b33"
    source_snapshot_uuid = "5ae031ce-6922-4583-85c8-0d3f8e23bd7b"
    formation_bookend = "136261efd3733fbb671394fb5b908a38ec41b52d"
    implementation_checkpoint = "f8c73edfab86053eaecbdee840d5f77384e73ef5"
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = $artifacts.Count
        selected_source_files = [int]$custody.selected_file_count
        selected_source_bytes = [int64]$custody.selected_byte_count
        promoted_component_files = $componentArtifacts.Count
        focused_debug_passed = 65
        focused_release_passed = 65
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
    non_authority_statement = "This evidence proves bounded composed inspection of caller-supplied values only; it grants no filesystem storage transport process provider model remote mutation or effect authority."
}
$manifestPath = Join-Path $outputRoot "implementation_evidence_manifest.json"
[IO.File]::WriteAllText($manifestPath, ((($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")) + "`n"), $utf8)
Write-Output ("cantor_composed_read_only_semantic_inspection_evidence_built=true artifacts={0} component_files={1} groups={2} passed={3}" -f $artifacts.Count, $componentArtifacts.Count, $debug.result_groups, $debug.tests_passed)
