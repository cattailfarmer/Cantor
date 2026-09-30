param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [switch]$SkipFocusedReplay
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) { $EvidenceDirectory = Join-Path $repositoryRoot "experiments/cantor_in_memory_semantic_find_p0" }
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$manifest = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "implementation_evidence_manifest.json") | ConvertFrom-Json
if ($manifest.profile -cne "cantor-in-memory-semantic-find-p0-evidence/0.1" -or $manifest.evidence_manifest_uuid -cne "353aafd9-cb10-4e4d-89bd-c945fc279f37" -or
    $manifest.specification_uuid -cne "2d678732-1b28-4df5-bc4c-00d6d428bc94" -or $manifest.source_snapshot_uuid -cne "d9a12c9a-2c94-4fd8-8734-a897c4ae8d2a" -or
    $manifest.integration_predecessor -cne "b31ee13cd4246f5be73d64bdaa68baf5357a601c") { throw "semantic find evidence identity differs" }

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

& (Join-Path $PSScriptRoot "verify_cantor_in_memory_semantic_find_p0_source.ps1")
$custody = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "source_custody_manifest.json") | ConvertFrom-Json
if ($custody.profile -cne "cantor-in-memory-semantic-find-source-custody/0.1" -or [int]$custody.selected_file_count -ne 5 -or [int64]$custody.selected_byte_count -ne 67592 -or
    [int]$custody.live_source_mutations -ne 0 -or [int]$custody.promoted_external_effects -ne 0) { throw "source custody evidence differs" }

$debug = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if ($debug.cargo_profile -cne "debug" -or [bool]$debug.overflow_checks -or [int]$debug.result_groups -ne 343 -or [int]$debug.tests_passed -ne 2028 -or [int]$debug.tests_failed -ne 0 -or [int]$debug.tests_ignored -ne 22) { throw "debug workspace evidence differs" }
if ($release.cargo_profile -cne "release" -or -not [bool]$release.overflow_checks -or [int]$release.result_groups -ne 343 -or [int]$release.tests_passed -ne 2028 -or [int]$release.tests_failed -ne 0 -or [int]$release.tests_ignored -ne 22) { throw "release workspace evidence differs" }
foreach ($summary in @($debug, $release)) {
    if (-not [bool]$summary.locked -or -not [bool]$summary.offline -or -not [bool]$summary.all_features -or -not [bool]$summary.all_targets -or [int]$summary.serialized_test_threads -ne 1 -or
        [int]$summary.process_spawns -ne 0 -or [int]$summary.provider_requests -ne 0 -or [int]$summary.remote_calls -ne 0 -or [int]$summary.product_effects -ne 0 -or
        [int]$summary.installations -ne 0 -or [int]$summary.updates -ne 0 -or [int]$summary.synthetic_trials -ne 0) { throw "workspace non-effect account differs" }
}

$component = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "semantic_find_component.json") | ConvertFrom-Json
if ($component.profile -cne "cantor-in-memory-semantic-find-component/0.1" -or $component.component_id -cne "cantor-sop-query" -or $component.crate_name -cne "cantor_sop_query" -or
    $component.capability -cne "kernel.sop.semantic-find" -or $component.published_predecessor -cne "b31ee13cd4246f5be73d64bdaa68baf5357a601c" -or
    $component.source_snapshot_uuid -cne "d9a12c9a-2c94-4fd8-8734-a897c4ae8d2a" -or $component.whole_cantor_scribe_disposition -cne "held_for_separate_promotion" -or [int]$component.file_count -ne 7) { throw "semantic find component identity differs" }
$componentSeen = @{}; $coordinateLines = @()
foreach ($artifact in @($component.files)) {
    $relative = [string]$artifact.path
    $allowed = $relative.StartsWith("crates/cantor_sop_query/") -or $relative -ceq "crates/cantor_sop_project/src/lib.rs" -or
        $relative -ceq "crates/cantor_instance_contract/Cargo.toml" -or $relative -ceq "crates/cantor_instance_contract/tests/in_memory_semantic_find_promotion.rs"
    if (-not $allowed -or $relative.Contains("..") -or $componentSeen.ContainsKey($relative)) { throw "invalid or duplicate component file: $relative" }
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
if ([int]$verification.selected_source_files -ne 5 -or [int64]$verification.selected_source_bytes -ne 67592 -or [int]$verification.promoted_component_files -ne 7 -or
    [int]$verification.focused_debug_passed -ne 46 -or [int]$verification.focused_release_passed -ne 46 -or [int]$verification.workspace_debug_result_groups -ne 343 -or
    [int]$verification.workspace_debug_passed -ne 2028 -or [int]$verification.workspace_debug_failed -ne 0 -or [int]$verification.workspace_debug_ignored -ne 22 -or
    [int]$verification.workspace_release_result_groups -ne 343 -or [int]$verification.workspace_release_passed -ne 2028 -or [int]$verification.workspace_release_failed -ne 0 -or
    [int]$verification.workspace_release_ignored -ne 22 -or [int]$verification.whole_cantor_scribe_held -ne 1 -or [int]$verification.live_source_mutations -ne 0 -or
    [int]$verification.live_runtime_processes -ne 0 -or [int]$verification.provider_requests -ne 0 -or [int]$verification.remote_calls -ne 0 -or [int]$verification.product_effects -ne 0 -or
    [int]$verification.installations -ne 0 -or [int]$verification.updates -ne 0 -or [int]$verification.synthetic_trials -ne 0) { throw "semantic find verification counters differ" }

if (-not $SkipFocusedReplay) {
    $focused = @(& (Join-Path $PSScriptRoot "test_cantor_in_memory_semantic_find_p0.ps1") -TargetDirectory $TargetDirectory)
    if ($focused.Count -eq 0 -or $focused[-1] -cne "cantor_in_memory_semantic_find_tests_passed=true debug=46 release=46 custody_files=5 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0") { throw "focused semantic find replay differs" }
}
Write-Output "cantor_in_memory_semantic_find_evidence_verified=true artifacts=4 component_files=7 focused=46 groups=343 passed=2028 failed=0 ignored=22 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
