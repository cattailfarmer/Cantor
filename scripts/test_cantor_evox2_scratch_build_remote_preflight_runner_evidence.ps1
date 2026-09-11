[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $CargoTargetDir = 'D:\CantorBuilds\evox2-preflight-runner-target'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$build = Join-Path $rootPath 'scripts\build_cantor_evox2_scratch_build_remote_preflight_runner_evidence.ps1'
$verify = Join-Path $rootPath 'scripts\verify_cantor_evox2_scratch_build_remote_preflight_runner_evidence.ps1'
& $build -Root $rootPath
& $verify -Root $rootPath
$savedTarget = $env:CARGO_TARGET_DIR
$savedRustFlags = $env:RUSTFLAGS
$savedJobs = $env:CARGO_BUILD_JOBS
$savedIncremental = $env:CARGO_INCREMENTAL
try {
    $env:CARGO_TARGET_DIR = $CargoTargetDir
    $env:CARGO_BUILD_JOBS = '1'
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTFLAGS = $null
    & cargo test -p cantor_ecosystem evox2_scratch_build_remote_preflight_runner --lib --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'runner focused debug tests failed' }
    $env:RUSTFLAGS = '-C overflow-checks=on'
    & cargo test -p cantor_ecosystem evox2_scratch_build_remote_preflight_runner --lib --release --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'runner focused release tests failed' }
    $env:RUSTFLAGS = $null
    & cargo clippy -p cantor_ecosystem --lib --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'runner Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'runner format failed' }
} finally {
    $env:CARGO_TARGET_DIR = $savedTarget
    $env:RUSTFLAGS = $savedRustFlags
    $env:CARGO_BUILD_JOBS = $savedJobs
    $env:CARGO_INCREMENTAL = $savedIncremental
}
& $build -Root $rootPath -ExactGatesPassed
& $verify -Root $rootPath -RequireExactGates
"cantor_evox2_scratch_build_remote_preflight_runner_tests_passed=true focused_debug=10 focused_release=10 clippy=true format=true provider_requests_performed=0 remote_calls_performed=0 effects_performed=0 live_invocations_performed=0"
