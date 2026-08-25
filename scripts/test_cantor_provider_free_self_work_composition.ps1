[CmdletBinding()]
param([switch]$UseWsl)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

if ($UseWsl) {
    $commands = @(
        'set -euo pipefail'
        'cd /mnt/c/Project/Cantor'
        'shim_dir=$(mktemp -d /tmp/cantor-pfc-python.XXXXXX)'
        'trap ''rm -rf "$shim_dir"'' EXIT'
        'ln -s /usr/bin/python3 "$shim_dir/python"'
        'export PATH="$shim_dir:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
        'export CARGO_TARGET_DIR=/tmp/cantor-pfc-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 LC_ALL=C'
        '"$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --test provider_free_self_work_composition --locked --offline'
        'RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_pfc_p0_release" "$HOME/.cargo/bin/cargo" test -p cantor_ecosystem --release --test provider_free_self_work_composition --locked --offline'
        '"$HOME/.cargo/bin/cargo" clippy -p cantor_ecosystem --all-targets --all-features --locked --offline -- -D warnings'
        '"$HOME/.cargo/bin/cargo" fmt --all -- --check'
    ) -join "`n"
    $transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($commands))
    & wsl.exe -d Ubuntu-24.04 -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
    if ($LASTEXITCODE -ne 0) { throw 'provider-free composition WSL gates failed' }
    Write-Output 'provider_free_self_work_composition_tests_passed wsl_debug=32 wsl_release=32 clippy=true format=true'
    return
}

Push-Location $root
try {
    & cargo test -p cantor_ecosystem --test provider_free_self_work_composition --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'provider-free composition debug tests failed' }
    & cargo clippy -p cantor_ecosystem --all-targets --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'provider-free composition Clippy failed' }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'provider-free composition format failed' }
}
finally {
    Pop-Location
}
Write-Output 'provider_free_self_work_composition_tests_passed debug=32 clippy=true format=true'
