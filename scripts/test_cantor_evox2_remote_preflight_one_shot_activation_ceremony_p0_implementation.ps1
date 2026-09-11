[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $CargoTargetDir = 'D:\CantorBuilds\evox2-activation-ceremony-target'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$build = Join-Path $rootPath 'scripts/build_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_evidence.ps1'
$verify = Join-Path $rootPath 'scripts/verify_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_implementation_evidence.ps1'
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
    & cargo test -p cantor_ecosystem --test evox2_remote_preflight_one_shot_activation_ceremony --test evox2_remote_preflight_one_shot_activation_ceremony_evidence --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'activation focused debug tests failed' }
    $debugFirst = & cargo run --quiet -p cantor_ecosystem --bin cantor-evox2-remote-preflight-activation-evidence-verify --locked --offline -- (Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence')
    if ($LASTEXITCODE -ne 0) { throw 'activation debug evidence replay failed' }
    $debugSecond = & cargo run --quiet -p cantor_ecosystem --bin cantor-evox2-remote-preflight-activation-evidence-verify --locked --offline -- (Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence')
    if ($LASTEXITCODE -ne 0 -or $debugFirst -cne $debugSecond) { throw 'activation debug evidence replay is not deterministic' }
    $env:RUSTFLAGS = '-C overflow-checks=on'
    & cargo test --release -p cantor_ecosystem --test evox2_remote_preflight_one_shot_activation_ceremony --test evox2_remote_preflight_one_shot_activation_ceremony_evidence --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'activation focused release tests failed' }
    $releaseFirst = & cargo run --release --quiet -p cantor_ecosystem --bin cantor-evox2-remote-preflight-activation-evidence-verify --locked --offline -- (Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence')
    if ($LASTEXITCODE -ne 0 -or $debugFirst -cne $releaseFirst) { throw 'activation release evidence replay differs' }
    $env:RUSTFLAGS = $null
    & cargo clippy -p cantor_ecosystem --lib --bin cantor-evox2-remote-preflight-activation-evidence-verify --test evox2_remote_preflight_one_shot_activation_ceremony --test evox2_remote_preflight_one_shot_activation_ceremony_evidence --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'activation focused Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'activation format failed' }
} finally {
    $env:CARGO_TARGET_DIR = $savedTarget
    $env:RUSTFLAGS = $savedRustFlags
    $env:CARGO_BUILD_JOBS = $savedJobs
    $env:CARGO_INCREMENTAL = $savedIncremental
}
& $build -Root $rootPath
& $verify -Root $rootPath
"cantor_evox2_remote_preflight_activation_implementation_tests_passed=true focused_debug=16 focused_release=16 evidence_replays=3 clippy=true format=true live_authorization=false permits=0 runner_invocations=0 process_spawns=0 provider_requests=0 remote_calls=0 effects=0 synthetic_trials=0"
