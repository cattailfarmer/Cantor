param(
    [ValidateSet("debug", "release")][string]$Profile = "debug",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [string]$EvidenceDirectory = "D:\CantorBuilds\cantor-semantic-inspection-wire-workspace"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
$targetRoot = [IO.Path]::GetFullPath($TargetDirectory)
$logPath = Join-Path $evidenceRoot ("workspace-{0}.log" -f $Profile)
$summaryPath = Join-Path $evidenceRoot ("workspace-{0}-summary.json" -f $Profile)
$utf8 = New-Object Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null
$env:CARGO_TARGET_DIR = $targetRoot
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
$env:RUST_MIN_STACK = "33554432"
$priorFlags = $env:RUSTFLAGS
Push-Location $repositoryRoot
try {
    if ($Profile -ceq "release") { $env:RUSTFLAGS = "-C overflow-checks=on" } else { $env:RUSTFLAGS = $null }
    $arguments = @("test", "--workspace", "--all-targets", "--all-features", "--locked", "--offline")
    if ($Profile -ceq "release") { $arguments += "--release" }
    $arguments += @("--", "--test-threads=1")
    & cargo @arguments 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "exact $Profile workspace tests failed" }
    $groups = 0
    $passed = 0
    $failed = 0
    $ignored = 0
    foreach ($line in [IO.File]::ReadLines($logPath)) {
        if ($line -cmatch '^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;') {
            $groups++
            $passed += [int]$Matches[1]
            $failed += [int]$Matches[2]
            $ignored += [int]$Matches[3]
        }
    }
    if ($groups -le 0 -or $failed -ne 0) { throw "workspace result summary is invalid" }
    $summary = [ordered]@{
        profile = "cantor-semantic-inspection-wire-workspace-test-summary/0.1"
        cargo_profile = $Profile
        locked = $true
        offline = $true
        all_features = $true
        all_targets = $true
        serialized_test_threads = 1
        overflow_checks = ($Profile -ceq "release")
        result_groups = $groups
        tests_passed = $passed
        tests_failed = $failed
        tests_ignored = $ignored
        stdin_reads = 0
        stdout_writes = 0
        filesystem_effects = 0
        network_effects = 0
        process_spawns = 0
        provider_requests = 0
        remote_calls = 0
        product_effects = 0
        installations = 0
        updates = 0
        synthetic_trials = 0
    }
    [IO.File]::WriteAllText($summaryPath, ((($summary | ConvertTo-Json -Depth 5).Replace("`r`n", "`n")) + "`n"), $utf8)
    Write-Output ("cantor_semantic_inspection_wire_workspace_passed=true profile={0} groups={1} passed={2} failed={3} ignored={4}" -f $Profile, $groups, $passed, $failed, $ignored)
} finally {
    $env:RUSTFLAGS = $priorFlags
    Pop-Location
}
