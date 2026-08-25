[CmdletBinding()]
param(
    [switch]$UseWsl,
    [switch]$UseWslRelease
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

if ($UseWsl) {
    if ($UseWslRelease) { throw 'UseWsl and UseWslRelease are mutually exclusive' }
    $commands = @(
        'set -euo pipefail'
        'cd /mnt/c/Project/Cantor'
        'shim_dir=$(mktemp -d /tmp/cantor-satx-python.XXXXXX)'
        'trap ''rm -rf "$shim_dir"'' EXIT'
        'ln -s /usr/bin/python3 "$shim_dir/python"'
        'export PATH="$shim_dir:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
        'export CARGO_TARGET_DIR=/mnt/d/CantorBuilds/cantor-satx-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 LC_ALL=C'
        '"$HOME/.cargo/bin/cargo" test -p cantor_core --test succeeding_sop_activation_transaction --locked --offline'
        'RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_satx_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_core --release --test succeeding_sop_activation_transaction --locked --offline'
        '"$HOME/.cargo/bin/cargo" clippy -p cantor_core --all-targets --all-features --locked --offline -- -D warnings'
        '"$HOME/.cargo/bin/cargo" fmt --all -- --check'
    ) -join "`n"
    $transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($commands))
    & wsl.exe -d Ubuntu-24.04 -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
    if ($LASTEXITCODE -ne 0) { throw 'focused WSL tests failed' }
    Write-Output 'succeeding_sop_activation_transaction_tests_passed wsl_debug=45 wsl_release=45 clippy=true format=true'
    return
}

Push-Location $root
try {
    & cargo test -p cantor_core --test succeeding_sop_activation_transaction --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'focused debug tests failed' }

    if ($UseWslRelease) {
        $commands = @(
            'set -euo pipefail'
            'cd /mnt/c/Project/Cantor'
            'shim_dir=$(mktemp -d /tmp/cantor-satx-python.XXXXXX)'
            'trap ''rm -rf "$shim_dir"'' EXIT'
            'ln -s /usr/bin/python3 "$shim_dir/python"'
            'export PATH="$shim_dir:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
            'export CARGO_TARGET_DIR=/mnt/d/CantorBuilds/cantor-satx-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 LC_ALL=C'
            'RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_satx_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_core --release --test succeeding_sop_activation_transaction --locked --offline'
        ) -join "`n"
        $transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($commands))
        & wsl.exe -d Ubuntu-24.04 -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
        if ($LASTEXITCODE -ne 0) { throw 'focused WSL overflow-checked release tests failed' }
    }

    & cargo clippy -p cantor_core --all-targets --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'focused Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'format check failed' }
}
finally {
    Pop-Location
}

Write-Output "succeeding_sop_activation_transaction_tests_passed debug=45 wsl_release=$(if ($UseWslRelease) { 45 } else { 0 }) clippy=true format=true"
