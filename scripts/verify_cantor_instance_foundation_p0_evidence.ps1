param(
    [string]$EvidenceDirectory = "",
    [string]$TargetDirectory = "D:\CantorBuilds\target"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot "experiments/eclipse_cantor_instance_foundation_p0"
}
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$manifestPath = Join-Path $evidenceRoot "implementation_evidence_manifest.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.profile -cne "cantor-instance-foundation-p0-evidence/0.1" -or
    $manifest.evidence_manifest_uuid -cne "148e48bd-58a3-4f6f-ac47-73f2843929c5" -or
    $manifest.specification_uuid -cne "d7e6055f-d40e-46c4-a757-2db3b77c7108" -or
    $manifest.integration_predecessor -cne "80f2ef9a8c1709e9e0dc12d70fc340a53919eec2") {
    throw "instance foundation evidence identity differs"
}

$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    if ($relative.Contains("\") -or $relative.StartsWith("/") -or $relative.Contains("..") -or $seen.ContainsKey($relative)) {
        throw "invalid or duplicate artifact path: $relative"
    }
    $seen[$relative] = $true
    $path = Join-Path $repositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "evidence artifact absent: $relative" }
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes) { throw "evidence artifact byte count differs: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne [string]$artifact.sha256) { throw "evidence artifact digest differs: $relative" }
}
if ($seen.Count -ne 8 -or [int]$manifest.verification.artifact_count -ne 8) { throw "evidence artifact membership differs" }

& (Join-Path $PSScriptRoot "verify_eclipse_cantor_semantic_custody.ps1") -ManifestPath (Join-Path $evidenceRoot "semantic_custody_manifest.json")

$debug = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_debug_summary.json") | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath (Join-Path $evidenceRoot "workspace_release_summary.json") | ConvertFrom-Json
if ($debug.profile -cne "cantor-instance-foundation-workspace-test-summary/0.1" -or $debug.cargo_profile -cne "debug" -or
    -not [bool]$debug.locked -or -not [bool]$debug.offline -or -not [bool]$debug.all_features -or -not [bool]$debug.all_targets -or
    [bool]$debug.overflow_checks -or [int]$debug.tests_failed -ne 0 -or [int]$debug.result_groups -le 0 -or [int]$debug.tests_passed -le 0) {
    throw "debug workspace evidence differs"
}
if ($release.profile -cne "cantor-instance-foundation-workspace-test-summary/0.1" -or $release.cargo_profile -cne "release" -or
    -not [bool]$release.locked -or -not [bool]$release.offline -or -not [bool]$release.all_features -or -not [bool]$release.all_targets -or
    -not [bool]$release.overflow_checks -or [int]$release.tests_failed -ne 0 -or [int]$release.result_groups -le 0 -or [int]$release.tests_passed -le 0) {
    throw "release workspace evidence differs"
}
if ([int]$debug.result_groups -ne [int]$release.result_groups -or [int]$debug.tests_passed -ne [int]$release.tests_passed -or [int]$debug.tests_ignored -ne [int]$release.tests_ignored) {
    throw "debug and release workspace totals differ"
}

$verification = $manifest.verification
if ([int]$verification.custody_selected_artifacts -ne 3772 -or [int]$verification.custody_untracked_paths -ne 609600 -or
    [string]$verification.custody_inventory_sha256 -cne "8a8ddec879accf954c188835757677c2f5cbae14f540d1663f9e4ea430bd766d" -or
    [int]$verification.debug_result_groups -ne [int]$debug.result_groups -or [int]$verification.debug_tests_passed -ne [int]$debug.tests_passed -or
    [int]$verification.debug_tests_failed -ne 0 -or [int]$verification.debug_tests_ignored -ne [int]$debug.tests_ignored -or
    [int]$verification.release_result_groups -ne [int]$release.result_groups -or [int]$verification.release_tests_passed -ne [int]$release.tests_passed -or
    [int]$verification.release_tests_failed -ne 0 -or [int]$verification.release_tests_ignored -ne [int]$release.tests_ignored -or
    [int]$verification.compatibility_admitted -ne 1 -or [int]$verification.compatibility_held -ne 1 -or
    [int]$verification.verifier_processes -ne 2 -or [int]$verification.live_runtime_processes -ne 0 -or
    [int]$verification.provider_requests -ne 0 -or [int]$verification.remote_calls -ne 0 -or [int]$verification.product_effects -ne 0 -or
    [int]$verification.installations -ne 0 -or [int]$verification.updates -ne 0 -or [int]$verification.synthetic_trials -ne 0) {
    throw "evidence verification counters differ"
}

$kernelPath = Join-Path $evidenceRoot "kernel_capabilities.json"
$instancePath = Join-Path $evidenceRoot "eclipse_instance_candidate.json"
$candidatePath = Join-Path $evidenceRoot "eclipse_kernel_candidate.json"
$expectedAdmitted = [IO.File]::ReadAllText((Join-Path $evidenceRoot "admitted_compatibility.json"))
$expectedHeld = [IO.File]::ReadAllText((Join-Path $evidenceRoot "held_compatibility.json"))
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
Push-Location $repositoryRoot
try {
    $admitted = (& cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --offline --quiet -- $kernelPath $instancePath) -join "`n"
    if ($LASTEXITCODE -ne 0 -or ($admitted + "`n") -cne $expectedAdmitted) { throw "admitted fresh replay differs" }
    $held = (& cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --offline --quiet -- $kernelPath $candidatePath) -join "`n"
    if ($LASTEXITCODE -ne 2 -or ($held + "`n") -cne $expectedHeld) { throw "held fresh replay differs" }
} finally {
    Pop-Location
}

Write-Output ("cantor_instance_foundation_evidence_verified=true artifacts=8 groups={0} passed={1} failed=0 ignored={2} admitted=1 held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0 synthetic_trials=0" -f $debug.result_groups, $debug.tests_passed, $debug.tests_ignored)
