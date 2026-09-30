param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [switch]$SkipFocusedReplay
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) { $EvidenceDirectory = Join-Path $repositoryRoot "experiments/cantor_in_memory_source_excerpt_p0" }
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory); $manifest = Get-Content -Raw (Join-Path $evidenceRoot "implementation_evidence_manifest.json") | ConvertFrom-Json
if ($manifest.profile -cne "cantor-in-memory-source-excerpt-p0-evidence/0.1" -or $manifest.evidence_manifest_uuid -cne "69510a0c-5f1e-4dba-aa08-a476b1a99b6e" -or $manifest.specification_uuid -cne "adbc4a74-c340-4e39-bec6-f199285052b9" -or $manifest.source_snapshot_uuid -cne "b8349a92-5828-4012-bb53-84025774c15a" -or $manifest.integration_predecessor -cne "abc8734e01f8c3b591db4b84e4d545951f6075b2") { throw "source excerpt evidence identity differs" }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    if ($relative.Contains("\") -or $relative.StartsWith("/") -or $relative.Contains("..") -or $seen.ContainsKey($relative)) { throw "invalid evidence path: $relative" }
    $seen[$relative] = $true; $path = Join-Path $repositoryRoot $relative
    if ((Get-Item $path).Length -ne [int64]$artifact.bytes -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256) { throw "evidence artifact differs: $relative" }
}
if ($seen.Count -ne 4 -or [int]$manifest.verification.artifact_count -ne 4) { throw "evidence membership differs" }
& (Join-Path $PSScriptRoot "verify_cantor_in_memory_source_excerpt_p0_source.ps1")
$custody = Get-Content -Raw (Join-Path $evidenceRoot "source_custody_manifest.json") | ConvertFrom-Json
if ($custody.profile -cne "cantor-in-memory-source-excerpt-source-custody/0.1" -or [int]$custody.selected_file_count -ne 6 -or [int64]$custody.selected_byte_count -ne 81936 -or [int]$custody.live_source_mutations -ne 0) { throw "source custody differs" }
$debug = Get-Content -Raw (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json; $release = Get-Content -Raw (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if ($debug.cargo_profile -cne "debug" -or [bool]$debug.overflow_checks -or [int]$debug.result_groups -ne 347 -or [int]$debug.tests_passed -ne 2036 -or [int]$debug.tests_failed -ne 0 -or [int]$debug.tests_ignored -ne 22) { throw "debug workspace evidence differs" }
if ($release.cargo_profile -cne "release" -or -not [bool]$release.overflow_checks -or [int]$release.result_groups -ne 347 -or [int]$release.tests_passed -ne 2036 -or [int]$release.tests_failed -ne 0 -or [int]$release.tests_ignored -ne 22) { throw "release workspace evidence differs" }
foreach ($summary in @($debug, $release)) { if (-not [bool]$summary.locked -or -not [bool]$summary.offline -or -not [bool]$summary.all_features -or -not [bool]$summary.all_targets -or [int]$summary.serialized_test_threads -ne 1 -or [int]$summary.process_spawns -ne 0 -or [int]$summary.provider_requests -ne 0 -or [int]$summary.remote_calls -ne 0 -or [int]$summary.product_effects -ne 0 -or [int]$summary.installations -ne 0 -or [int]$summary.updates -ne 0 -or [int]$summary.synthetic_trials -ne 0) { throw "workspace non-effect account differs" } }
$component = Get-Content -Raw (Join-Path $evidenceRoot "source_excerpt_component.json") | ConvertFrom-Json
if ($component.profile -cne "cantor-in-memory-source-excerpt-component/0.1" -or $component.component_id -cne "cantor-sop-excerpt" -or $component.capability -cne "kernel.sop.source-excerpt" -or [int]$component.file_count -ne 8 -or $component.whole_cantor_scribe_disposition -cne "held_for_separate_promotion") { throw "component identity differs" }
$componentSeen = @{}; $coordinateLines = @()
foreach ($artifact in @($component.files)) { $relative = [string]$artifact.path; if ($relative.Contains("..") -or $componentSeen.ContainsKey($relative)) { throw "invalid component path" }; $componentSeen[$relative] = $true; $path = Join-Path $repositoryRoot $relative; if ((Get-Item $path).Length -ne [int64]$artifact.bytes -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256) { throw "component differs: $relative" }; $coordinateLines += ("{0}`n{1}`n{2}`n" -f $relative, $artifact.bytes, $artifact.sha256) }
$utf8 = New-Object Text.UTF8Encoding($false); $sha = [Security.Cryptography.SHA256]::Create(); try { $coordinateDigest = ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes(($coordinateLines -join ""))))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
if ($coordinateDigest -cne [string]$component.coordinate_digest) { throw "component coordinate differs" }
$v = $manifest.verification
if ([int]$v.selected_source_files -ne 6 -or [int64]$v.selected_source_bytes -ne 81936 -or [int]$v.promoted_component_files -ne 8 -or [int]$v.focused_debug_passed -ne 54 -or [int]$v.focused_release_passed -ne 54 -or [int]$v.workspace_debug_result_groups -ne 347 -or [int]$v.workspace_debug_passed -ne 2036 -or [int]$v.workspace_release_result_groups -ne 347 -or [int]$v.workspace_release_passed -ne 2036 -or [int]$v.whole_cantor_scribe_held -ne 1 -or [int]$v.live_source_mutations -ne 0 -or [int]$v.live_runtime_processes -ne 0 -or [int]$v.provider_requests -ne 0 -or [int]$v.remote_calls -ne 0 -or [int]$v.product_effects -ne 0 -or [int]$v.installations -ne 0 -or [int]$v.updates -ne 0 -or [int]$v.synthetic_trials -ne 0) { throw "verification counters differ" }
if (-not $SkipFocusedReplay) { $focused = @(& (Join-Path $PSScriptRoot "test_cantor_in_memory_source_excerpt_p0.ps1") -TargetDirectory $TargetDirectory); if ($focused.Count -eq 0 -or $focused[-1] -cne "cantor_in_memory_source_excerpt_tests_passed=true debug=54 release=54 custody_files=6 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0") { throw "focused replay differs" } }
Write-Output "cantor_in_memory_source_excerpt_evidence_verified=true artifacts=4 component_files=8 focused=54 groups=347 passed=2036 failed=0 ignored=22 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
