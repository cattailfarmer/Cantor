param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [switch]$SkipFocusedReplay
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) { $EvidenceDirectory = Join-Path $repositoryRoot "experiments/cantor_supplied_project_assembly_p0" }
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$manifest = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "implementation_evidence_manifest.json") | ConvertFrom-Json
if ($manifest.profile -cne "cantor-supplied-project-assembly-p0-evidence/0.1" -or $manifest.evidence_manifest_uuid -cne "c17fb49d-b4b0-499c-9809-5bfbdd7943a5" -or
    $manifest.specification_uuid -cne "8c5ea4a3-1399-4651-96fa-3be17c56147b" -or $manifest.source_snapshot_uuid -cne "62cc9a0e-635b-4c96-8587-9a5cfc663fc2" -or
    $manifest.integration_predecessor -cne "f9dcaebdcd97ece5ada0ba54648fdae7e5a61ea9") { throw "supplied project evidence identity differs" }

$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    if ($relative.Contains("\") -or $relative.StartsWith("/") -or $relative.Contains("..") -or $seen.ContainsKey($relative)) { throw "invalid or duplicate evidence artifact path: $relative" }
    $seen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "evidence artifact absent: $relative" }
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes) { throw "evidence artifact byte count differs: $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256) { throw "evidence artifact digest differs: $relative" }
}
if ($seen.Count -ne 4 -or [int]$manifest.verification.artifact_count -ne 4) { throw "evidence artifact membership differs" }

& (Join-Path $PSScriptRoot "verify_cantor_supplied_project_assembly_p0_source.ps1")
$custody = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "source_custody_manifest.json") | ConvertFrom-Json
if ($custody.profile -cne "cantor-supplied-project-assembly-source-custody/0.1" -or [int]$custody.selected_file_count -ne 5 -or [int64]$custody.selected_byte_count -ne 17254 -or
    [int]$custody.live_source_mutations -ne 0 -or [int]$custody.promoted_external_effects -ne 0) { throw "source custody evidence differs" }

$debug = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if ($debug.cargo_profile -cne "debug" -or [bool]$debug.overflow_checks -or [int]$debug.result_groups -ne 339 -or [int]$debug.tests_passed -ne 2018 -or [int]$debug.tests_failed -ne 0 -or [int]$debug.tests_ignored -ne 22) { throw "debug workspace evidence differs" }
if ($release.cargo_profile -cne "release" -or -not [bool]$release.overflow_checks -or [int]$release.result_groups -ne 339 -or [int]$release.tests_passed -ne 2018 -or [int]$release.tests_failed -ne 0 -or [int]$release.tests_ignored -ne 22) { throw "release workspace evidence differs" }
foreach ($summary in @($debug, $release)) {
    if (-not [bool]$summary.locked -or -not [bool]$summary.offline -or -not [bool]$summary.all_features -or -not [bool]$summary.all_targets -or [int]$summary.serialized_test_threads -ne 1 -or
        [int]$summary.process_spawns -ne 0 -or [int]$summary.provider_requests -ne 0 -or [int]$summary.remote_calls -ne 0 -or [int]$summary.product_effects -ne 0 -or
        [int]$summary.installations -ne 0 -or [int]$summary.updates -ne 0 -or [int]$summary.synthetic_trials -ne 0) { throw "workspace non-effect account differs" }
}

$component = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "supplied_project_component.json") | ConvertFrom-Json
if ($component.profile -cne "cantor-supplied-project-component/0.1" -or $component.component_id -cne "cantor-sop-project" -or $component.crate_name -cne "cantor_sop_project" -or
    $component.capability -cne "kernel.sop.project-assemble" -or $component.published_predecessor -cne "f9dcaebdcd97ece5ada0ba54648fdae7e5a61ea9" -or
    $component.source_snapshot_uuid -cne "62cc9a0e-635b-4c96-8587-9a5cfc663fc2" -or $component.whole_cantor_scribe_disposition -cne "held_for_separate_promotion" -or [int]$component.file_count -ne 5) { throw "supplied project component identity differs" }
$componentSeen = @{}; $coordinateLines = @()
foreach ($artifact in @($component.files)) {
    $relative = [string]$artifact.path
    if ((-not $relative.StartsWith("crates/cantor_sop_project/")) -and $relative -cne "crates/cantor_instance_contract/tests/supplied_project_assembly_promotion.rs") { throw "invalid component file: $relative" }
    if ($relative.Contains("..") -or $componentSeen.ContainsKey($relative)) { throw "invalid or duplicate component file: $relative" }
    $componentSeen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes) { throw "component byte count differs: $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256) { throw "component digest differs: $relative" }
    $coordinateLines += ("{0}`n{1}`n{2}`n" -f $relative, $artifact.bytes, $artifact.sha256)
}
$utf8 = New-Object Text.UTF8Encoding($false); $sha = [Security.Cryptography.SHA256]::Create()
try { $coordinateDigest = ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes(($coordinateLines -join ""))))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
if ($coordinateDigest -cne [string]$component.coordinate_digest) { throw "component coordinate digest differs" }

$verification = $manifest.verification
if ([int]$verification.selected_source_files -ne 5 -or [int64]$verification.selected_source_bytes -ne 17254 -or [int]$verification.promoted_component_files -ne 5 -or
    [int]$verification.focused_debug_passed -ne 36 -or [int]$verification.focused_release_passed -ne 36 -or [int]$verification.workspace_debug_result_groups -ne 339 -or
    [int]$verification.workspace_debug_passed -ne 2018 -or [int]$verification.workspace_debug_failed -ne 0 -or [int]$verification.workspace_debug_ignored -ne 22 -or
    [int]$verification.workspace_release_result_groups -ne 339 -or [int]$verification.workspace_release_passed -ne 2018 -or [int]$verification.workspace_release_failed -ne 0 -or
    [int]$verification.workspace_release_ignored -ne 22 -or [int]$verification.whole_cantor_scribe_held -ne 1 -or [int]$verification.live_source_mutations -ne 0 -or
    [int]$verification.live_runtime_processes -ne 0 -or [int]$verification.provider_requests -ne 0 -or [int]$verification.remote_calls -ne 0 -or [int]$verification.product_effects -ne 0 -or
    [int]$verification.installations -ne 0 -or [int]$verification.updates -ne 0 -or [int]$verification.synthetic_trials -ne 0) { throw "supplied project verification counters differ" }

if (-not $SkipFocusedReplay) {
    $focused = @(& (Join-Path $PSScriptRoot "test_cantor_supplied_project_assembly_p0.ps1") -TargetDirectory $TargetDirectory)
    if ($focused.Count -eq 0 -or $focused[-1] -cne "cantor_supplied_project_tests_passed=true debug=36 release=36 custody_files=5 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0") { throw "focused supplied project replay differs" }
}
Write-Output "cantor_supplied_project_evidence_verified=true artifacts=4 component_files=5 focused=36 groups=339 passed=2018 failed=0 ignored=22 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
