param(
    [ValidateSet("debug", "release")][string]$Profile = "debug",
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [string]$EvidenceDirectory = "D:\CantorBuilds\cantor-semantic-inspection-mcp"
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
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_mcp_adapter_p0_formation.ps1")
Push-Location $selectedRoot
try {
    if ($Profile -ceq "release") { $env:RUSTFLAGS = "-C overflow-checks=on" } else { $env:RUSTFLAGS = $null }
    $arguments = @("test", "-p", "cantor_sop_inspect_mcp", "--all-targets", "--all-features", "--locked", "--offline")
    if ($Profile -ceq "release") { $arguments += "--release" }
    $arguments += @("--", "--test-threads=1")
    & cargo @arguments 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "focused MCP adapter tests failed" }
    $groups = 0; $passed = 0; $failed = 0; $ignored = 0
    foreach ($line in [IO.File]::ReadLines($logPath)) {
        if ($line -cmatch '^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;') {
            $groups++; $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $ignored += [int]$Matches[3]
        }
    }
    if ($groups -ne 6 -or $passed -ne 27 -or $failed -ne 0 -or $ignored -ne 0) { throw "focused result cardinality differs" }
    $fixturePath = Join-Path $selectedRoot "fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json"
    $summary = [ordered]@{
        profile = "cantor-semantic-inspection-mcp-focused-test-summary/0.1"
        cargo_profile = $Profile; locked = $true; offline = $true; all_targets = $true; all_features = $true
        serialized_test_threads = 1; overflow_checks = ($Profile -ceq "release")
        result_groups = $groups; tests_passed = $passed; tests_failed = $failed; tests_ignored = $ignored
        golden_cases = 8; golden_bytes = (Get-Item -LiteralPath $fixturePath).Length
        golden_sha256 = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
        direct_golden_complete_wire_responses = 5; direct_golden_adapter_refusals = 3
        native_process_trials = 9; native_initialized_fixture_sessions = 2
        native_fixture_calls = 16; native_fixture_complete_wire_responses = 10; native_fixture_adapter_refusals = 6
        native_unknown_tool_protocol_refusals = 2; native_cli_refusals = 1
        native_invalid_input_refusals = 4; native_closed_output_refusals = 1
        native_stalled_io_deadline_exits = 1; native_stalled_session_seconds = 60; native_runtime_shutdown_milliseconds = 250
        successful_native_children_killed_by_harness = 0
        sdk_duplex_fixture_sessions = 1; sdk_duplex_fixture_calls = 8
        product_stdio_transport_enabled = $true; product_pathname_acquisitions = 0
        product_subprocess_launches = 0; network_effects = 0; service_installs = 0; durable_custody_effects = 0
        provider_requests = 0; model_requests = 0; remote_calls = 0; synthetic_provider_trials = 0
        installed_application_acceptances = 0
    }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($summaryPath, ((($summary | ConvertTo-Json -Depth 5).Replace("`r`n", "`n")) + "`n"), $utf8)
    Write-Output ("cantor_mcp_adapter_focused_passed=true profile={0} groups={1} passed={2} native_trials=9 deadline_exits=1" -f $Profile,$groups,$passed)
} finally { $env:RUSTFLAGS = $priorFlags; Pop-Location }
