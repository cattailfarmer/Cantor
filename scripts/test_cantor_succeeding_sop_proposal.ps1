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
        'shim_dir=$(mktemp -d /tmp/cantor-ssp-python.XXXXXX)'
        'trap ''rm -rf "$shim_dir"'' EXIT'
        'ln -s /usr/bin/python3 "$shim_dir/python"'
        'export PATH="$shim_dir:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
        'export CARGO_TARGET_DIR=/tmp/cantor-ssp-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 LC_ALL=C'
        '"$HOME/.cargo/bin/cargo" test -p cantor_core --test succeeding_sop_proposal --locked --offline'
        'RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_ssp_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_core --release --test succeeding_sop_proposal --locked --offline'
        '"$HOME/.cargo/bin/cargo" clippy -p cantor_core --all-targets --all-features --locked --offline -- -D warnings'
        '"$HOME/.cargo/bin/cargo" fmt --all -- --check'
    ) -join "`n"
    $transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($commands))
    & wsl.exe -d Ubuntu-24.04 -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
    if ($LASTEXITCODE -ne 0) { throw 'focused WSL tests failed' }
    Write-Output 'succeeding_sop_proposal_tests_passed wsl_debug=26 wsl_release=26 clippy=true format=true'
    return
}

Push-Location $root
try {
    & cargo test -p cantor_core --test succeeding_sop_proposal --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'focused debug tests failed' }

    if ($UseWslRelease) {
        $command = 'set -euo pipefail; cd /mnt/c/Project/Cantor; export CARGO_TARGET_DIR=/tmp/cantor-ssp-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_ssp_p0_release"; "$HOME/.cargo/bin/cargo" test -p cantor_core --release --test succeeding_sop_proposal --locked --offline'
        & wsl.exe -d Ubuntu-24.04 -- bash -lc $command
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

Write-Output "succeeding_sop_proposal_tests_passed debug=26 wsl_release=$(if ($UseWslRelease) { 26 } else { 0 }) clippy=true format=true"
