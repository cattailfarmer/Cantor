param(
    [string]$WorkspaceSummaryDirectory = "D:\CantorBuilds\cantor-semantic-inspection-stdio-host-workspace",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repositoryRoot "experiments/cantor_semantic_inspection_stdio_host_p0" }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$summaryRoot = [IO.Path]::GetFullPath($WorkspaceSummaryDirectory)
$utf8 = New-Object Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

function Get-Artifact([string]$RelativePath) {
    $path = Join-Path $repositoryRoot $RelativePath
    [ordered]@{ path = $RelativePath.Replace("\", "/"); bytes = (Get-Item -LiteralPath $path).Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
function Get-TextSha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Text)))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
}

& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_source.ps1")
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_formation.ps1")
$debugSource = Join-Path $summaryRoot "workspace-debug-summary.json"
$releaseSource = Join-Path $summaryRoot "workspace-release-summary.json"
foreach ($required in @($debugSource, $releaseSource)) { if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "required workspace summary is absent: $required" } }
$debugTarget = Join-Path $outputRoot "workspace_debug_summary.json"
$releaseTarget = Join-Path $outputRoot "workspace_release_summary.json"
[IO.File]::WriteAllText($debugTarget, [IO.File]::ReadAllText($debugSource).Replace("`r`n", "`n"), $utf8)
[IO.File]::WriteAllText($releaseTarget, [IO.File]::ReadAllText($releaseSource).Replace("`r`n", "`n"), $utf8)

$componentPaths = @(
    "crates/cantor_sop_inspect_wire/Cargo.toml",
    "crates/cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs",
    "crates/cantor_sop_inspect_wire/tests/stdio_host.rs",
    "crates/cantor_sop_inspect_wire/tests/stdio_host_static.rs"
)
$componentArtifacts = @($componentPaths | ForEach-Object { Get-Artifact $_ })
$coordinateLines = @($componentArtifacts | ForEach-Object { "{0}`n{1}`n{2}`n" -f $_.path, $_.bytes, $_.sha256 })
$component = [ordered]@{
    profile = "cantor-semantic-inspection-stdio-host-component/0.1"
    component_id = "cantor-sop-inspect-stdio"
    binary_name = "cantor-sop-inspect-stdio"
    formation_bookend = "a540faf4c75e8101b2dc5ac49691cbce1ac73f14"
    files = $componentArtifacts
    file_count = $componentArtifacts.Count
    coordinate_digest = Get-TextSha256 ($coordinateLines -join "")
    public_fault = "cantor_stdio_host_refused"
    refused_exit = 2
    non_authority = "One-shot bounded stdio host only; no paths filesystem sockets services provider model shell update remote merge or non-stdio effect authority."
}
$componentPath = Join-Path $outputRoot "semantic_inspection_stdio_host_component.json"
[IO.File]::WriteAllText($componentPath, ((($component | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")) + "`n"), $utf8)

$artifactPaths = @(
    "experiments/cantor_semantic_inspection_stdio_host_p0/source_custody_manifest.json",
    "experiments/cantor_semantic_inspection_stdio_host_p0/formation_evidence_manifest.json",
    "experiments/cantor_semantic_inspection_stdio_host_p0/workspace_debug_summary.json",
    "experiments/cantor_semantic_inspection_stdio_host_p0/workspace_release_summary.json",
    "experiments/cantor_semantic_inspection_stdio_host_p0/semantic_inspection_stdio_host_component.json"
)
$artifacts = @($artifactPaths | ForEach-Object { Get-Artifact $_ })
$debug = Get-Content -Raw $debugTarget | ConvertFrom-Json
$release = Get-Content -Raw $releaseTarget | ConvertFrom-Json
foreach ($summary in @($debug, $release)) {
    if ([int]$summary.result_groups -ne 356 -or [int]$summary.tests_passed -ne 2068 -or [int]$summary.tests_failed -ne 0 -or [int]$summary.tests_ignored -ne 22) { throw "workspace summary counts differ" }
    if ([int]$summary.component_host_process_trials -ne 15 -or [int]$summary.component_stdin_sessions -ne 14 -or [int]$summary.component_complete_stdout_responses -ne 6 -or [int]$summary.component_public_stderr_faults -ne 8 -or [int]$summary.component_closed_stdout_failures -ne 1) { throw "host effect account differs" }
}
$manifest = [ordered]@{
    profile = "cantor-semantic-inspection-stdio-host-p0-evidence/0.1"
    evidence_manifest_uuid = "27fb07f9-f9ae-492f-826a-54a0b00bce40"
    specification_uuid = "4ee53d21-ed53-4f35-bbaf-06cab3a34085"
    formation_bookend = "a540faf4c75e8101b2dc5ac49691cbce1ac73f14"
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = 5; promoted_component_files = 4; focused_debug_passed = 21; focused_release_passed = 21
        workspace_debug_result_groups = 356; workspace_debug_passed = 2068; workspace_debug_failed = 0; workspace_debug_ignored = 22
        workspace_release_result_groups = 356; workspace_release_passed = 2068; workspace_release_failed = 0; workspace_release_ignored = 22
        per_profile_host_process_trials = 15; per_profile_stdin_sessions = 14; per_profile_complete_stdout_responses = 6
        per_profile_public_stderr_faults = 8; per_profile_closed_stdout_failures = 1
        filesystem_effects = 0; network_effects = 0; service_effects = 0; provider_requests = 0; model_requests = 0; remote_calls = 0; installations = 0; updates = 0; synthetic_trials = 0
    }
}
$manifestPath = Join-Path $outputRoot "implementation_evidence_manifest.json"
[IO.File]::WriteAllText($manifestPath, ((($manifest | ConvertTo-Json -Depth 12).Replace("`r`n", "`n")) + "`n"), $utf8)
Write-Output "cantor_semantic_inspection_stdio_host_evidence_built=true artifacts=5 component_files=4 groups=356 passed=2068 host_trials=15"
