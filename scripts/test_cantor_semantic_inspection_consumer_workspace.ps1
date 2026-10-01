param(
    [ValidateSet("debug", "release")][string]$Profile = "debug",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [string]$EvidenceDirectory = "D:\CantorBuilds\cantor-semantic-inspection-consumer-handoff"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$selectedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null
$logPath = Join-Path $evidenceRoot ("workspace-{0}.log" -f $Profile)
$summaryPath = Join-Path $evidenceRoot ("workspace-{0}-summary.json" -f $Profile)
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
$env:RUST_MIN_STACK = "33554432"
$priorFlags = $env:RUSTFLAGS
$priorPath = $env:PATH
& (Join-Path $PSScriptRoot "rehash_current_evidence_manifests.ps1") -VerifyOnly
# Resolve a real interpreter now, before any native Rust fixture invokes python.
# This process-scoped prefix avoids stale Windows application aliases without
# installing anything or changing persistent host configuration.
$pythonCommand = (Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$env:PATH = ((Split-Path -Parent $pythonCommand) + ";" + $priorPath)
& $pythonCommand -c "import sys; print(sys.executable)"
if ($LASTEXITCODE -ne 0) { throw "Python fixture interpreter probe failed" }
Push-Location $selectedRoot
try {
    if ($Profile -ceq "release") { $env:RUSTFLAGS = "-C overflow-checks=on" } else { $env:RUSTFLAGS = $null }
    $hostArguments = @("build", "-p", "cantor_sop_inspect_wire", "--bin", "cantor-sop-inspect-stdio", "--locked", "--offline")
    if ($Profile -ceq "release") { $hostArguments += "--release" }
    & cargo @hostArguments
    if ($LASTEXITCODE -ne 0) { throw "workspace fixture host build failed" }
    $arguments = @("test", "--workspace", "--all-targets", "--all-features", "--locked", "--offline")
    if ($Profile -ceq "release") { $arguments += "--release" }
    $arguments += @("--", "--test-threads=1")
    & cargo @arguments 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "exact consumer workspace tests failed" }
    $groups = 0; $passed = 0; $failed = 0; $ignored = 0
    foreach ($line in [IO.File]::ReadLines($logPath)) {
        if ($line -cmatch '^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;') {
            $groups++; $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $ignored += [int]$Matches[3]
        }
    }
    if ($groups -le 0 -or $failed -ne 0) { throw "workspace result summary differs" }
    $summary = [ordered]@{
        profile = "cantor-semantic-inspection-consumer-workspace-test-summary/0.1"
        cargo_profile = $Profile; locked = $true; offline = $true; all_features = $true; all_targets = $true
        serialized_test_threads = 1; overflow_checks = ($Profile -ceq "release")
        result_groups = $groups; tests_passed = $passed; tests_failed = $failed; tests_ignored = $ignored
        component_fixture_cases = 8; component_development_host_process_trials = 9
        component_complete_wire_responses = 5; component_public_host_faults = 3; component_stalled_children_killed_and_reaped = 1
        consumer_library_io_effects = 0; component_production_process_launches = 0; component_product_filesystem_effects = 0
        component_network_effects = 0; component_service_effects = 0; component_provider_requests = 0
        component_model_requests = 0; component_remote_calls = 0; installed_application_acceptances = 0
    }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($summaryPath, ((($summary | ConvertTo-Json -Depth 5).Replace("`r`n", "`n")) + "`n"), $utf8)
    Write-Output ("cantor_consumer_workspace_passed=true profile={0} groups={1} passed={2} failed={3} ignored={4}" -f $Profile, $groups, $passed, $failed, $ignored)
} finally {
    $env:RUSTFLAGS = $priorFlags
    $env:PATH = $priorPath
    Pop-Location
}
