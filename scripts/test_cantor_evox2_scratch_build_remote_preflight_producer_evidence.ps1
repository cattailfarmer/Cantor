[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $CargoTargetDir = 'D:\CantorBuilds\evox2-preflight-producer-target'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$build = Join-Path $rootPath 'scripts\build_cantor_evox2_scratch_build_remote_preflight_producer_evidence.ps1'
$verify = Join-Path $rootPath 'scripts\verify_cantor_evox2_scratch_build_remote_preflight_producer_evidence.ps1'
& $build -Root $rootPath -CargoTargetDir $CargoTargetDir
if ($LASTEXITCODE -ne 0) { throw 'producer evidence build failed' }
& $verify -Root $rootPath
if ($LASTEXITCODE -ne 0) { throw 'producer evidence verification failed' }
$savedTarget = $env:CARGO_TARGET_DIR
$savedRustFlags = $env:RUSTFLAGS
try {
    $env:CARGO_TARGET_DIR = $CargoTargetDir
    $env:RUSTFLAGS = $null
    & cargo test -p cantor_core --test evox2_scratch_build_remote_preflight_producer --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'producer focused debug tests failed' }
    $env:RUSTFLAGS = '-C overflow-checks=on'
    & cargo test -p cantor_core --test evox2_scratch_build_remote_preflight_producer --release --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'producer focused release tests failed' }
    $env:RUSTFLAGS = $null
    & cargo clippy -p cantor_core --all-targets --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'producer Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'producer format failed' }
} finally {
    $env:CARGO_TARGET_DIR = $savedTarget
    $env:RUSTFLAGS = $savedRustFlags
}
& $build -Root $rootPath -CargoTargetDir $CargoTargetDir -ExactGatesPassed
if ($LASTEXITCODE -ne 0) { throw 'producer exact evidence rebuild failed' }
& $verify -Root $rootPath -RequireExactGates
if ($LASTEXITCODE -ne 0) { throw 'producer exact evidence verification failed' }
"cantor_evox2_scratch_build_remote_preflight_producer_tests_passed=true focused_debug=9 focused_release=9 clippy=true format=true provider_requests_performed=0 remote_calls_performed=0 effects_performed=0"
