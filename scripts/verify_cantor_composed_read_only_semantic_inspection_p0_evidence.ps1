param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [switch]$SkipFocusedReplay
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot "experiments/cantor_composed_read_only_semantic_inspection_p0"
}
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$manifest = Get-Content -Raw (Join-Path $evidenceRoot "implementation_evidence_manifest.json") | ConvertFrom-Json
if (
    $manifest.profile -cne "cantor-composed-read-only-semantic-inspection-p0-evidence/0.1" -or
    $manifest.evidence_manifest_uuid -cne "8372ff5c-90e4-4b25-9ce3-452dbd8f764f" -or
    $manifest.specification_uuid -cne "8e08875a-6877-4c07-9752-b96771fb0b33" -or
    $manifest.source_snapshot_uuid -cne "5ae031ce-6922-4583-85c8-0d3f8e23bd7b" -or
    $manifest.formation_bookend -cne "136261efd3733fbb671394fb5b908a38ec41b52d" -or
    $manifest.implementation_checkpoint -cne "f8c73edfab86053eaecbdee840d5f77384e73ef5"
) { throw "composed semantic inspection evidence identity differs" }

$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    if ($relative.Contains("\") -or $relative.StartsWith("/") -or $relative.Contains("..") -or $seen.ContainsKey($relative)) {
        throw "invalid evidence path: $relative"
    }
    $seen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if (
        (Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256
    ) { throw "evidence artifact differs: $relative" }
}
if ($seen.Count -ne 4 -or [int]$manifest.verification.artifact_count -ne 4) { throw "evidence membership differs" }

& (Join-Path $PSScriptRoot "verify_cantor_composed_read_only_semantic_inspection_p0_source.ps1")
& (Join-Path $PSScriptRoot "verify_cantor_composed_read_only_semantic_inspection_p0_formation.ps1")
$custody = Get-Content -Raw (Join-Path $evidenceRoot "source_custody_manifest.json") | ConvertFrom-Json
if (
    $custody.profile -cne "cantor-composed-read-only-semantic-inspection-source-custody/0.1" -or
    [int]$custody.selected_file_count -ne 4 -or
    [int64]$custody.selected_byte_count -ne 57333 -or
    [int]$custody.live_source_mutations -ne 0
) { throw "source custody differs" }

$debug = Get-Content -Raw (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json
$release = Get-Content -Raw (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if (
    $debug.profile -cne "cantor-composed-read-only-semantic-inspection-workspace-test-summary/0.1" -or
    $debug.cargo_profile -cne "debug" -or
    [bool]$debug.overflow_checks -or
    [int]$debug.result_groups -ne 350 -or
    [int]$debug.tests_passed -ne 2047 -or
    [int]$debug.tests_failed -ne 0 -or
    [int]$debug.tests_ignored -ne 22
) { throw "debug workspace evidence differs" }
if (
    $release.profile -cne "cantor-composed-read-only-semantic-inspection-workspace-test-summary/0.1" -or
    $release.cargo_profile -cne "release" -or
    -not [bool]$release.overflow_checks -or
    [int]$release.result_groups -ne 350 -or
    [int]$release.tests_passed -ne 2047 -or
    [int]$release.tests_failed -ne 0 -or
    [int]$release.tests_ignored -ne 22
) { throw "release workspace evidence differs" }
foreach ($summary in @($debug, $release)) {
    if (
        -not [bool]$summary.locked -or
        -not [bool]$summary.offline -or
        -not [bool]$summary.all_features -or
        -not [bool]$summary.all_targets -or
        [int]$summary.serialized_test_threads -ne 1 -or
        [int]$summary.process_spawns -ne 0 -or
        [int]$summary.provider_requests -ne 0 -or
        [int]$summary.remote_calls -ne 0 -or
        [int]$summary.product_effects -ne 0 -or
        [int]$summary.installations -ne 0 -or
        [int]$summary.updates -ne 0 -or
        [int]$summary.synthetic_trials -ne 0
    ) { throw "workspace non-effect account differs" }
}

$component = Get-Content -Raw (Join-Path $evidenceRoot "semantic_inspection_component.json") | ConvertFrom-Json
if (
    $component.profile -cne "cantor-composed-read-only-semantic-inspection-component/0.1" -or
    $component.component_id -cne "cantor-sop-inspect" -or
    $component.capability -cne "kernel.sop.semantic-inspect" -or
    $component.formation_bookend -cne "136261efd3733fbb671394fb5b908a38ec41b52d" -or
    $component.implementation_checkpoint -cne "f8c73edfab86053eaecbdee840d5f77384e73ef5" -or
    [int]$component.file_count -ne 7 -or
    $component.whole_cantor_scribe_disposition -cne "held_for_separate_promotion"
) { throw "component identity differs" }
$componentSeen = @{}
$coordinateLines = @()
$expectedComponentPaths = @(
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_sop_inspect/Cargo.toml",
    "crates/cantor_sop_inspect/src/lib.rs",
    "crates/cantor_sop_inspect/tests/static_absence.rs",
    "crates/cantor_instance_contract/Cargo.toml",
    "crates/cantor_instance_contract/tests/composed_semantic_inspection_promotion.rs"
)
$componentFiles = @($component.files)
if ($componentFiles.Count -ne $expectedComponentPaths.Count) { throw "component membership count differs" }
for ($index = 0; $index -lt $componentFiles.Count; $index++) {
    $artifact = $componentFiles[$index]
    $relative = [string]$artifact.path
    if ($relative.Contains("..") -or $componentSeen.ContainsKey($relative)) { throw "invalid component path" }
    if ($relative -cne $expectedComponentPaths[$index]) { throw "component membership differs at index $index" }
    $componentSeen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if (
        (Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256
    ) { throw "component differs: $relative" }
    $coordinateLines += ("{0}`n{1}`n{2}`n" -f $relative, $artifact.bytes, $artifact.sha256)
}
$utf8 = New-Object Text.UTF8Encoding($false)
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $coordinateDigest = ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes(($coordinateLines -join ""))))).Replace("-", "").ToLowerInvariant()
} finally {
    $sha.Dispose()
}
if ($coordinateDigest -cne [string]$component.coordinate_digest) { throw "component coordinate differs" }

$v = $manifest.verification
if (
    [int]$v.selected_source_files -ne 4 -or
    [int64]$v.selected_source_bytes -ne 57333 -or
    [int]$v.promoted_component_files -ne 7 -or
    [int]$v.focused_debug_passed -ne 65 -or
    [int]$v.focused_release_passed -ne 65 -or
    [int]$v.workspace_debug_result_groups -ne 350 -or
    [int]$v.workspace_debug_passed -ne 2047 -or
    [int]$v.workspace_debug_failed -ne 0 -or
    [int]$v.workspace_debug_ignored -ne 22 -or
    [int]$v.workspace_release_result_groups -ne 350 -or
    [int]$v.workspace_release_passed -ne 2047 -or
    [int]$v.workspace_release_failed -ne 0 -or
    [int]$v.workspace_release_ignored -ne 22 -or
    [int]$v.whole_cantor_scribe_held -ne 1 -or
    [int]$v.live_source_mutations -ne 0 -or
    [int]$v.live_runtime_processes -ne 0 -or
    [int]$v.provider_requests -ne 0 -or
    [int]$v.remote_calls -ne 0 -or
    [int]$v.product_effects -ne 0 -or
    [int]$v.installations -ne 0 -or
    [int]$v.updates -ne 0 -or
    [int]$v.synthetic_trials -ne 0
) { throw "verification counters differ" }
if (-not $SkipFocusedReplay) {
    $focused = @(& (Join-Path $PSScriptRoot "test_cantor_composed_read_only_semantic_inspection_p0.ps1") -TargetDirectory $TargetDirectory)
    if (
        $focused.Count -eq 0 -or
        $focused[-1] -cne "cantor_composed_read_only_semantic_inspection_tests_passed=true debug=65 release=65 custody_files=4 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
    ) { throw "focused replay differs" }
}
$completionBindings = @(
    [ordered]@{ path = "proofs/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Implementation_Proof.sop"; bytes = 3785; sha256 = "1AA423739FF0954072B8120B1C4F45721412FA7897E3C6D8C2BDA5E990788C31" },
    [ordered]@{ path = "feature_support/reviews/CantorComposedReadOnlySemanticInspectionP0CompletionReview.sop"; bytes = 1727; sha256 = "F5C1A9657916991B6F1FB133F7AF936907AC2C701F7D89A4BFDEB2380FF51E9D" },
    [ordered]@{ path = "narrative/registries/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Implementation_Phase_Closure.sop"; bytes = 864; sha256 = "6CE86B00A0F0C0E636AB0465D6C6223289D5351982D932F28E6E5A254AA2C9EE" },
    [ordered]@{ path = "feature_support/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Requirement_Matrix.sop"; bytes = 1331; sha256 = "7C0A8FBE9EFF24DE09DA91EC266AEF68D8155283168FE8D380FFF6330A361997" },
    [ordered]@{ path = "plans/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Plan.sop"; bytes = 1300; sha256 = "9242CFCCBD05EF755ECFA0F37485E692EA7E5CD5A2A4FB86809FF5DFC0D91268" },
    [ordered]@{ path = "solutions/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Solution.sop"; bytes = 1747; sha256 = "289CBD697AACCB8DF44BA8AB078E8C0CEDC58F7AA6B6BC319D0936F70511E235" },
    [ordered]@{ path = "proofs/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Artifact_Phase_Lock_Proof.sop"; bytes = 1186; sha256 = "E929EBDF69D858C9120968EEFA08B66D6A05513E5FE88084CCA21D6B08C32690" },
    [ordered]@{ path = "experiments/cantor_composed_read_only_semantic_inspection_p0/implementation_evidence_manifest.json"; bytes = 2323; sha256 = "48435FC725E2B69A8E4F4F8E8B79EC57CBAEC2F09DBB463D69AB6E5FAAE6ADF1" }
)
$completionPath = Join-Path $repositoryRoot "narrative/registries/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Completion_Satisfaction_Signature.sop"
$completion = Get-Content -LiteralPath $completionPath -Raw
foreach ($needle in @("908a7cf5-2663-4d9c-92b0-f3881039d8dc", "ad10f10f-d506-48ef-a805-f8b0a133766c", "valid_for_exact_composed_semantic_inspection_branch_publication_only")) {
    if (-not $completion.Contains($needle)) { throw "completion signature identity differs: $needle" }
}
foreach ($binding in $completionBindings) {
    $path = Join-Path $repositoryRoot ([string]$binding.path)
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$binding.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string]$binding.sha256) {
        throw "completion-bound artifact differs: $($binding.path)"
    }
    $line = "+ [artifact_binding] $($binding.path) bytes$($binding.bytes) SHA256 $($binding.sha256)"
    if (-not $completion.Contains($line)) { throw "completion signature binding differs: $($binding.path)" }
}
Write-Output "cantor_composed_read_only_semantic_inspection_evidence_verified=true artifacts=4 component_files=7 focused=65 groups=350 passed=2047 failed=0 ignored=22 completion_bindings=8 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
