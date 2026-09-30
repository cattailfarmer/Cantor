param(
    [string]$WorkspaceSummaryDirectory = "D:\CantorBuilds\cantor-instance-foundation-workspace",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "experiments/eclipse_cantor_instance_foundation_p0"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$summaryRoot = [IO.Path]::GetFullPath($WorkspaceSummaryDirectory)
$custodyPath = Join-Path $outputRoot "semantic_custody_manifest.json"
$debugSource = Join-Path $summaryRoot "workspace-debug-summary.json"
$releaseSource = Join-Path $summaryRoot "workspace-release-summary.json"
foreach ($required in @($custodyPath, $debugSource, $releaseSource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "required evidence input is absent: $required" }
}

$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
$utf8 = New-Object Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

function Write-Utf8Lines([string]$Path, [object[]]$Lines) {
    [IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"), $utf8)
}
function Get-Artifact([string]$RelativePath) {
    $path = Join-Path $repositoryRoot $RelativePath
    [ordered]@{
        path = $RelativePath.Replace("\", "/")
        bytes = (Get-Item -LiteralPath $path).Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$debugTarget = Join-Path $outputRoot "workspace_debug_summary.json"
$releaseTarget = Join-Path $outputRoot "workspace_release_summary.json"
[IO.File]::Copy($debugSource, $debugTarget, $true)
[IO.File]::Copy($releaseSource, $releaseTarget, $true)

Push-Location $repositoryRoot
try {
    $kernel = & cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --offline --quiet -- kernel
    if ($LASTEXITCODE -ne 0) { throw "kernel fixture production failed" }
    $instance = & cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --offline --quiet -- eclipse
    if ($LASTEXITCODE -ne 0) { throw "Eclipse instance fixture production failed" }
    $candidate = & cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --offline --quiet -- eclipse-kernel-candidate
    if ($LASTEXITCODE -ne 0) { throw "Eclipse kernel candidate fixture production failed" }

    $kernelPath = Join-Path $outputRoot "kernel_capabilities.json"
    $instancePath = Join-Path $outputRoot "eclipse_instance_candidate.json"
    $candidatePath = Join-Path $outputRoot "eclipse_kernel_candidate.json"
    Write-Utf8Lines $kernelPath $kernel
    Write-Utf8Lines $instancePath $instance
    Write-Utf8Lines $candidatePath $candidate

    $admitted = & cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --offline --quiet -- $kernelPath $instancePath
    if ($LASTEXITCODE -ne 0) { throw "admitted compatibility replay failed" }
    $held = & cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --offline --quiet -- $kernelPath $candidatePath
    if ($LASTEXITCODE -ne 2) { throw "held compatibility replay did not return the governed held exit" }
    Write-Utf8Lines (Join-Path $outputRoot "admitted_compatibility.json") $admitted
    Write-Utf8Lines (Join-Path $outputRoot "held_compatibility.json") $held
} finally {
    Pop-Location
}

$artifactPaths = @(
    "experiments/eclipse_cantor_instance_foundation_p0/semantic_custody_manifest.json",
    "experiments/eclipse_cantor_instance_foundation_p0/workspace_debug_summary.json",
    "experiments/eclipse_cantor_instance_foundation_p0/workspace_release_summary.json",
    "experiments/eclipse_cantor_instance_foundation_p0/kernel_capabilities.json",
    "experiments/eclipse_cantor_instance_foundation_p0/eclipse_instance_candidate.json",
    "experiments/eclipse_cantor_instance_foundation_p0/eclipse_kernel_candidate.json",
    "experiments/eclipse_cantor_instance_foundation_p0/admitted_compatibility.json",
    "experiments/eclipse_cantor_instance_foundation_p0/held_compatibility.json"
)
$artifacts = @($artifactPaths | ForEach-Object { Get-Artifact $_ })
$debug = Get-Content -Raw -LiteralPath $debugTarget | ConvertFrom-Json
$release = Get-Content -Raw -LiteralPath $releaseTarget | ConvertFrom-Json
$custody = Get-Content -Raw -LiteralPath $custodyPath | ConvertFrom-Json
$manifest = [ordered]@{
    profile = "cantor-instance-foundation-p0-evidence/0.1"
    evidence_manifest_uuid = "148e48bd-58a3-4f6f-ac47-73f2843929c5"
    specification_uuid = "d7e6055f-d40e-46c4-a757-2db3b77c7108"
    integration_predecessor = "80f2ef9a8c1709e9e0dc12d70fc340a53919eec2"
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count = $artifacts.Count
        custody_selected_artifacts = [int]$custody.artifact_count
        custody_untracked_paths = [int]$custody.source_status.untracked_path_count
        custody_inventory_sha256 = [string]$custody.artifact_inventory_sha256
        debug_result_groups = [int]$debug.result_groups
        debug_tests_passed = [int]$debug.tests_passed
        debug_tests_failed = [int]$debug.tests_failed
        debug_tests_ignored = [int]$debug.tests_ignored
        release_result_groups = [int]$release.result_groups
        release_tests_passed = [int]$release.tests_passed
        release_tests_failed = [int]$release.tests_failed
        release_tests_ignored = [int]$release.tests_ignored
        compatibility_admitted = 1
        compatibility_held = 1
        verifier_processes = 2
        live_runtime_processes = 0
        provider_requests = 0
        remote_calls = 0
        product_effects = 0
        installations = 0
        updates = 0
        synthetic_trials = 0
    }
    non_authority_statement = "This evidence proves deterministic structural custody and instance compatibility only. It grants no execution, installation, model, provider, operator, kernel, remote, mutation, update, publication, or effect authority."
}
$manifestPath = Join-Path $outputRoot "implementation_evidence_manifest.json"
[IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 10) + "`n"), $utf8)
Write-Output ("cantor_instance_foundation_evidence_built=true artifacts={0} debug_passed={1} release_passed={2}" -f $artifacts.Count, $debug.tests_passed, $release.tests_passed)
