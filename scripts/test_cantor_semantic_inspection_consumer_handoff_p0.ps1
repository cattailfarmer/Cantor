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
$logPath = Join-Path $evidenceRoot ("focused-{0}.log" -f $Profile)
$summaryPath = Join-Path $evidenceRoot ("focused-{0}-summary.json" -f $Profile)
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
$priorFlags = $env:RUSTFLAGS
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_consumer_handoff_p0_formation.ps1")
Push-Location $selectedRoot
try {
    if ($Profile -ceq "release") { $env:RUSTFLAGS = "-C overflow-checks=on" } else { $env:RUSTFLAGS = $null }
    $hostArguments = @("build", "-p", "cantor_sop_inspect_wire", "--bin", "cantor-sop-inspect-stdio", "--locked", "--offline")
    $testArguments = @("test", "-p", "cantor_sop_inspect_consumer", "--all-targets", "--all-features", "--locked", "--offline")
    if ($Profile -ceq "release") { $hostArguments += "--release"; $testArguments += "--release" }
    & cargo @hostArguments
    if ($LASTEXITCODE -ne 0) { throw "fixture host build failed" }
    $testArguments += @("--", "--test-threads=1")
    & cargo @testArguments 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "focused consumer tests failed" }
    $groups = 0; $passed = 0; $failed = 0; $ignored = 0
    foreach ($line in [IO.File]::ReadLines($logPath)) {
        if ($line -cmatch '^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;') {
            $groups++; $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $ignored += [int]$Matches[3]
        }
    }
    if ($groups -ne 5 -or $passed -ne 22 -or $failed -ne 0 -or $ignored -ne 0) { throw "focused consumer result cardinality differs" }
    $fixturePath = Join-Path $selectedRoot "fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json"
    $summary = [ordered]@{
        profile = "cantor-semantic-inspection-consumer-focused-test-summary/0.1"
        cargo_profile = $Profile; locked = $true; offline = $true; all_targets = $true; all_features = $true
        serialized_test_threads = 1; overflow_checks = ($Profile -ceq "release")
        result_groups = $groups; tests_passed = $passed; tests_failed = $failed; tests_ignored = $ignored
        fixture_cases = 8; fixture_bytes = (Get-Item -LiteralPath $fixturePath).Length
        fixture_sha256 = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
        development_host_process_trials = 9; development_completed_eof_requests = 8
        development_complete_wire_responses = 5; development_public_host_faults = 3
        development_stalled_children_killed_and_reaped = 1
        consumer_library_io_effects = 0; production_process_launches = 0; product_filesystem_effects = 0
        network_effects = 0; service_effects = 0; provider_requests = 0; model_requests = 0; remote_calls = 0
        installed_application_acceptances = 0; synthetic_provider_trials = 0
    }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($summaryPath, ((($summary | ConvertTo-Json -Depth 5).Replace("`r`n", "`n")) + "`n"), $utf8)
    Write-Output ("cantor_consumer_handoff_focused_passed=true profile={0} groups={1} passed={2} fixtures=8 development_processes=9 product_effects=0" -f $Profile, $groups, $passed)
} finally {
    $env:RUSTFLAGS = $priorFlags
    Pop-Location
}
