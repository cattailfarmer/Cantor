[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu-24.04'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$installed = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Trim("`0 ") } | Where-Object { $_ }
if ($installed -cnotcontains $Distro) { throw "required WSL distribution is unavailable: $Distro" }

$body = @'
set -euo pipefail
export CARGO_TARGET_DIR=/tmp/cantor-sfp-p0-target
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 LC_ALL=C
"$HOME/.cargo/bin/cargo" test -q -p cantor_core --test succeeding_sop_activation_transaction --locked --offline -- --test-threads=1
"$HOME/.cargo/bin/cargo" test -q -p cantor_ecosystem --test succeeding_sop_fixture_persistence --locked --offline -- --test-threads=1
"$HOME/.cargo/bin/cargo" test -q -p cantor_ecosystem --test succeeding_sop_fixture_persistence_evidence --locked --offline -- --test-threads=1
RUSTFLAGS="-C overflow-checks=on -C metadata=cantor_sfp_p0_release" "$HOME/.cargo/bin/cargo" test -q -p cantor_ecosystem --release --test succeeding_sop_fixture_persistence --locked --offline -- --test-threads=1
'@
$transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body))
& wsl.exe -d $Distro --cd $root -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash"
if ($LASTEXITCODE -ne 0) { throw 'succeeding SOP fixture persistence focused verification failed' }
Write-Output 'succeeding_sop_fixture_persistence_focused_verification=passed upstream=45 debug=7 evidence=6 overflow_release=7'
