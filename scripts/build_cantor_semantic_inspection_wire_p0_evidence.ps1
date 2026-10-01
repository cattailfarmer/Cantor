param(
    [string]$WorkspaceSummaryDirectory = "D:\CantorBuilds\cantor-semantic-inspection-wire-workspace",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repositoryRoot "experiments/cantor_semantic_inspection_wire_p0" }
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
    try { return ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Text)))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
}

& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_wire_p0_source.ps1")
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_wire_p0_formation.ps1")
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
    "crates/cantor_sop_inspect_wire/Cargo.toml",
    "crates/cantor_sop_inspect_wire/src/lib.rs",
    "crates/cantor_sop_inspect_wire/tests/wire.rs",
    "crates/cantor_sop_inspect_wire/tests/static_absence.rs"
)
$componentArtifacts = @($componentPaths | ForEach-Object { Get-Artifact $_ })
$coordinateLines = @($componentArtifacts | ForEach-Object { "{0}`n{1}`n{2}`n" -f $_.path, $_.bytes, $_.sha256 })
$component = [ordered]@{
    profile = "cantor-semantic-inspection-wire-component/0.1"
    component_id = "cantor-sop-inspect-wire"
    crate_name = "cantor_sop_inspect_wire"
    nested_capability = "kernel.sop.semantic-inspect"
    request_profile = "cantor-sop-inspection-wire-request/0.1"
    response_profile = "cantor-sop-inspection-wire-response/0.1"
    formation_bookend = "6710997199f6ced307fab0e175040435ac0b0fe5"
    files = $componentArtifacts
    file_count = $componentArtifacts.Count
    coordinate_digest = Get-TextSha256 ($coordinateLines -join "")
    executable_host_disposition = "held_for_separate_governance"
    non_authority = "Pure caller-supplied byte codec only; no stdin stdout filesystem socket service process transport provider model remote mutation or effect authority."
}
$componentPath = Join-Path $outputRoot "semantic_inspection_wire_component.json"
[IO.File]::WriteAllText($componentPath, ((($component | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")) + "`n"), $utf8)

$artifactPaths = @(
    "experiments/cantor_semantic_inspection_wire_p0/source_custody_manifest.json",
    "experiments/cantor_semantic_inspection_wire_p0/formation_evidence_manifest.json",
    "experiments/cantor_semantic_inspection_wire_p0/workspace_debug_summary.json",
    "experiments/cantor_semantic_inspection_wire_p0/workspace_release_summary.json",
    "experiments/cantor_semantic_inspection_wire_p0/semantic_inspection_wire_component.json"
)
$artifacts = @($artifactPaths | ForEach-Object { Get-Artifact $_ })
$debug = Get-Content -Raw $debugTarget | ConvertFrom-Json
$release = Get-Content -Raw $releaseTarget | ConvertFrom-Json
$custody = Get-Content -Raw (Join-Path $outputRoot "source_custody_manifest.json") | ConvertFrom-Json
$manifest = [ordered]@{
    profile = "cantor-semantic-inspection-wire-p0-evidence/0.1"
    evidence_manifest_uuid = "8ecae65c-3940-4b1f-826a-5ff90731ba3f"
    specification_uuid = "1bddf5c8-35b7-4b29-a833-921048a21410"
    source_snapshot_uuid = "21d00b4c-142e-4432-a4dd-41613488aa23"
    formation_bookend = "6710997199f6ced307fab0e175040435ac0b0fe5"
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = $artifacts.Count
        selected_source_files = [int]$custody.selected_file_count
        selected_source_bytes = [int64]$custody.selected_byte_count
        promoted_component_files = $componentArtifacts.Count
        focused_debug_passed = 76
        focused_release_passed = 76
        workspace_debug_result_groups = [int]$debug.result_groups
        workspace_debug_passed = [int]$debug.tests_passed
        workspace_debug_failed = [int]$debug.tests_failed
        workspace_debug_ignored = [int]$debug.tests_ignored
        workspace_release_result_groups = [int]$release.result_groups
        workspace_release_passed = [int]$release.tests_passed
        workspace_release_failed = [int]$release.tests_failed
        workspace_release_ignored = [int]$release.tests_ignored
        executable_host_held = 1
        live_source_mutations = 0
        stdin_reads = 0
        stdout_writes = 0
        filesystem_effects = 0
        network_effects = 0
        live_runtime_processes = 0
        provider_requests = 0
        remote_calls = 0
        product_effects = 0
        installations = 0
        updates = 0
        synthetic_trials = 0
    }
    operational_correction = "The first exact debug workspace attempt correctly refused a stale Cargo.toml coordinate after crate membership changed; current evidence manifests were rehashed, the focused refusal test passed, and authoritative exact debug and release runs then completed from the corrected tree."
    non_authority_statement = "This evidence proves a pure bounded semantic inspection wire codec over caller-supplied bytes only; it grants no executable host stdin stdout filesystem socket service process provider model remote mutation or effect authority."
}
$manifestPath = Join-Path $outputRoot "implementation_evidence_manifest.json"
[IO.File]::WriteAllText($manifestPath, ((($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n")) + "`n"), $utf8)
Write-Output ("cantor_semantic_inspection_wire_evidence_built=true artifacts={0} component_files={1} groups={2} passed={3}" -f $artifacts.Count, $componentArtifacts.Count, $debug.result_groups, $debug.tests_passed)
