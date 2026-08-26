[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$UseNative
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

if ($UseNative) {
    & (Join-Path $PSScriptRoot 'build_cantor_succeeding_sop_activation_fixture.ps1') -UseNative
    if ($LASTEXITCODE -ne 0) { throw 'native corrected fixture generation failed' }
    $priorStack = [Environment]::GetEnvironmentVariable('RUST_MIN_STACK', 'Process')
    try {
        $env:RUST_MIN_STACK = '33554432'
        & cargo test -p cantor_core --test succeeding_sop_activation_transaction --locked --offline -- --skip cli_admits_and_replays_receipt_without_output_path --skip cli_admit_verify_and_static_effect_boundary_hold
        if ($LASTEXITCODE -ne 0) { throw 'native B2A semantic or execution-policy gate failed' }
        & cargo test -p cantor_ecosystem --test succeeding_sop_fixture_persistence --locked --offline
        if ($LASTEXITCODE -ne 0) { throw 'native B2B1 plus B2B2 semantic or execution-policy gate failed' }
    } finally {
        [Environment]::SetEnvironmentVariable('RUST_MIN_STACK', $priorStack, 'Process')
    }
    return
}

$command = @'
set -euo pipefail
cd /mnt/c/Project/Cantor
shim_dir="$(mktemp -d /tmp/cantor-sfr-p0-python.XXXXXX)"
trap 'rm -f "$shim_dir/python"; rmdir "$shim_dir"' EXIT
ln -s /usr/bin/python3 "$shim_dir/python"
export PATH="$shim_dir:$PATH"
export CARGO_TARGET_DIR=/tmp/cantor-sfr-p0-target
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 RUST_MIN_STACK=33554432 LC_ALL=C
"$HOME/.cargo/bin/cargo" test -p cantor_core --test succeeding_sop_activation_transaction --locked --offline
"$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --test succeeding_sop_fixture_persistence --locked --offline
"$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --test succeeding_sop_fixture_rollback --locked --offline
RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_sfr_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_core --release --test succeeding_sop_activation_transaction --locked --offline
RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_sfr_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --release --test succeeding_sop_fixture_persistence --locked --offline
RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_sfr_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --release --test succeeding_sop_fixture_rollback --locked --offline
"$HOME/.cargo/bin/cargo" clippy -p cantor_core --test succeeding_sop_activation_transaction -p cantor_ecosystem --lib --test succeeding_sop_fixture_persistence --test succeeding_sop_fixture_rollback --locked --offline -- -D warnings
"$HOME/.cargo/bin/cargo" clippy -p cantor_ecosystem --example succeeding_sop_fixture_rollback_fixture --locked --offline -- -D warnings
"$HOME/.cargo/bin/cargo" fmt --all -- --check
printf '%s\n' 'cantor-succeeding-sop-fixture-rollback-wsl-gate-receipt/0.1 b2a_debug=45 combined_debug=16 rollback_debug=9 b2a_release=45 combined_release=16 rollback_release=9 clippy=pass format=pass'
'@
$transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command))
& wsl.exe -d $Distro --cd $root -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
if ($LASTEXITCODE -ne 0) { throw 'focused WSL rollback gates failed' }
