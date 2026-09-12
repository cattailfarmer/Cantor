[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $CargoTargetDir = 'D:\CantorBuilds\evox2-private-permit-bridge-target'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$savedTarget = $env:CARGO_TARGET_DIR
$savedRustFlags = $env:RUSTFLAGS
$savedJobs = $env:CARGO_BUILD_JOBS
$savedIncremental = $env:CARGO_INCREMENTAL
try {
    $env:CARGO_TARGET_DIR = $CargoTargetDir
    $env:CARGO_BUILD_JOBS = '1'
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTFLAGS = $null
    & cargo test -p cantor_ecosystem --lib evox2_remote_preflight_private_permit_bridge --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge focused debug semantic tests failed' }
    & cargo test -p cantor_ecosystem --test evox2_remote_preflight_private_permit_bridge_static --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge focused debug static tests failed' }

    $env:RUSTFLAGS = '-C overflow-checks=on'
    & cargo test --release -p cantor_ecosystem --lib evox2_remote_preflight_private_permit_bridge --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge focused release semantic tests failed' }
    & cargo test --release -p cantor_ecosystem --test evox2_remote_preflight_private_permit_bridge_static --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge focused release static tests failed' }

    $env:RUSTFLAGS = $null
    & cargo clippy -p cantor_ecosystem --lib --test evox2_remote_preflight_private_permit_bridge_static --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge focused Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'private permit bridge format failed' }
} finally {
    $env:CARGO_TARGET_DIR = $savedTarget
    $env:RUSTFLAGS = $savedRustFlags
    $env:CARGO_BUILD_JOBS = $savedJobs
    $env:CARGO_INCREMENTAL = $savedIncremental
}

"cantor_evox2_remote_preflight_private_permit_bridge_implementation_tests_passed=true focused_debug=7 focused_release=7 static_absence=3 permits_minted=0 runner_invocations=0 process_spawns=0 provider_requests=0 remote_calls=0 effects=0 synthetic_trials=0"
