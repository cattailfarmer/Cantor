param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [switch]$SkipFocusedReplay
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot "experiments/cantor_scribe_semantic_kernel_p0"
}
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$manifestPath = Join-Path $evidenceRoot "implementation_evidence_manifest.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.profile -cne "cantor-scribe-semantic-kernel-p0-evidence/0.1" -or
    $manifest.evidence_manifest_uuid -cne "93b9c3d6-423d-468c-81fc-a3499abdd688" -or
    $manifest.specification_uuid -cne "b09b4613-000b-4621-89de-6d81ef64f7f3" -or
    $manifest.source_snapshot_uuid -cne "b02fd0c7-c996-41b9-b0fa-d0d3d0f07cfa" -or
    $manifest.integration_predecessor -cne "4209d44228399c8aa01b2ccb98806777c65826b8") {
    throw "semantic kernel evidence identity differs"
}

$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    if ($relative.Contains("\") -or $relative.StartsWith("/") -or $relative.Contains("..") -or $seen.ContainsKey($relative)) {
        throw "invalid or duplicate evidence artifact path: $relative"
    }
    $seen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "evidence artifact absent: $relative" }
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes) { throw "evidence artifact byte count differs: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne [string]$artifact.sha256) { throw "evidence artifact digest differs: $relative" }
}
if ($seen.Count -ne 4 -or [int]$manifest.verification.artifact_count -ne 4) {
    throw "evidence artifact membership differs"
}

& (Join-Path $PSScriptRoot "verify_cantor_scribe_semantic_kernel_p0_source.ps1")
$custody = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "source_custody_manifest.json") | ConvertFrom-Json
if ($custody.profile -cne "cantor-scribe-semantic-kernel-source-custody/0.1" -or
    [int]$custody.selected_file_count -ne 6 -or [int64]$custody.selected_byte_count -ne 55374 -or
    [int]$custody.live_source_mutations -ne 0 -or [int]$custody.promoted_external_effects -ne 0) {
    throw "source custody evidence differs"
}

$debug = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if ($debug.cargo_profile -cne "debug" -or [bool]$debug.overflow_checks -or
    [int]$debug.result_groups -ne 335 -or [int]$debug.tests_passed -ne 2007 -or [int]$debug.tests_failed -ne 0 -or [int]$debug.tests_ignored -ne 22) {
    throw "debug workspace evidence differs"
}
if ($release.cargo_profile -cne "release" -or -not [bool]$release.overflow_checks -or
    [int]$release.result_groups -ne 335 -or [int]$release.tests_passed -ne 2007 -or [int]$release.tests_failed -ne 0 -or [int]$release.tests_ignored -ne 22) {
    throw "release workspace evidence differs"
}
foreach ($summary in @($debug, $release)) {
    if (-not [bool]$summary.locked -or -not [bool]$summary.offline -or
        -not [bool]$summary.all_features -or -not [bool]$summary.all_targets -or
        [int]$summary.serialized_test_threads -ne 1 -or [int]$summary.process_spawns -ne 0 -or
        [int]$summary.provider_requests -ne 0 -or [int]$summary.remote_calls -ne 0 -or
        [int]$summary.product_effects -ne 0 -or [int]$summary.installations -ne 0 -or
        [int]$summary.updates -ne 0 -or [int]$summary.synthetic_trials -ne 0) {
        throw "workspace non-effect account differs"
    }
}

$component = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "semantic_kernel_component.json") | ConvertFrom-Json
if ($component.profile -cne "cantor-sop-semantic-kernel-component/0.1" -or
    $component.component_id -cne "cantor-sop-semantics" -or
    $component.crate_name -cne "cantor_sop_semantics" -or
    $component.capability -cne "kernel.sop.semantic-analyze" -or
    $component.published_predecessor -cne "4209d44228399c8aa01b2ccb98806777c65826b8" -or
    $component.source_snapshot_uuid -cne "b02fd0c7-c996-41b9-b0fa-d0d3d0f07cfa" -or
    $component.whole_cantor_scribe_disposition -cne "held_for_separate_promotion" -or
    [int]$component.file_count -ne 10) {
    throw "semantic component identity differs"
}
$componentSeen = @{}
$coordinateLines = @()
foreach ($artifact in @($component.files)) {
    $relative = [string]$artifact.path
    if (-not $relative.StartsWith("crates/cantor_sop_semantics/") -or $relative.Contains("..") -or $componentSeen.ContainsKey($relative)) {
        throw "invalid or duplicate component file: $relative"
    }
    $componentSeen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes) { throw "component byte count differs: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne [string]$artifact.sha256) { throw "component digest differs: $relative" }
    $coordinateLines += ("{0}`n{1}`n{2}`n" -f $relative, $artifact.bytes, $artifact.sha256)
}
$utf8 = New-Object Text.UTF8Encoding($false)
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $coordinateDigest = ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes(($coordinateLines -join ""))))).Replace("-", "").ToLowerInvariant()
} finally {
    $sha.Dispose()
}
if ($coordinateDigest -cne [string]$component.coordinate_digest) {
    throw "component coordinate digest differs"
}

$verification = $manifest.verification
if ([int]$verification.selected_source_files -ne 6 -or [int64]$verification.selected_source_bytes -ne 55374 -or
    [int]$verification.promoted_component_files -ne 10 -or [int]$verification.focused_debug_passed -ne 25 -or
    [int]$verification.focused_release_passed -ne 25 -or [int]$verification.workspace_debug_result_groups -ne 335 -or
    [int]$verification.workspace_debug_passed -ne 2007 -or [int]$verification.workspace_debug_failed -ne 0 -or
    [int]$verification.workspace_debug_ignored -ne 22 -or [int]$verification.workspace_release_result_groups -ne 335 -or
    [int]$verification.workspace_release_passed -ne 2007 -or [int]$verification.workspace_release_failed -ne 0 -or
    [int]$verification.workspace_release_ignored -ne 22 -or [int]$verification.whole_cantor_scribe_held -ne 1 -or
    [int]$verification.live_source_mutations -ne 0 -or [int]$verification.live_runtime_processes -ne 0 -or
    [int]$verification.provider_requests -ne 0 -or [int]$verification.remote_calls -ne 0 -or
    [int]$verification.product_effects -ne 0 -or [int]$verification.installations -ne 0 -or
    [int]$verification.updates -ne 0 -or [int]$verification.synthetic_trials -ne 0) {
    throw "semantic kernel verification counters differ"
}

if (-not $SkipFocusedReplay) {
    $focused = @(& (Join-Path $PSScriptRoot "test_cantor_scribe_semantic_kernel_p0.ps1") -TargetDirectory $TargetDirectory)
    if ($focused.Count -eq 0 -or $focused[-1] -cne "cantor_scribe_semantic_kernel_tests_passed=true debug=25 release=25 custody_files=6 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0") {
        throw "focused semantic kernel replay differs"
    }
}

Write-Output "cantor_scribe_semantic_kernel_evidence_verified=true artifacts=4 component_files=10 focused=25 groups=335 passed=2007 failed=0 ignored=22 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
