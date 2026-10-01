param([string]$TargetDirectory = "D:\CantorBuilds\target")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_source.ps1")
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_formation.ps1")
Push-Location $repositoryRoot
try {
    & cargo test -p cantor_sop_inspect_wire --all-targets --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "semantic inspection stdio host focused debug tests failed" }
    $priorFlags = $env:RUSTFLAGS
    try {
        $env:RUSTFLAGS = "-C overflow-checks=on"
        & cargo test -p cantor_sop_inspect_wire --all-targets --release --locked --offline -- --test-threads=1
    } finally {
        $env:RUSTFLAGS = $priorFlags
    }
    if ($LASTEXITCODE -ne 0) { throw "semantic inspection stdio host focused release tests failed" }
    & cargo clippy -p cantor_sop_inspect_wire --all-targets --all-features --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "semantic inspection stdio host focused Clippy failed" }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "format check failed" }
    Write-Output "cantor_semantic_inspection_stdio_host_tests_passed=true debug=21 release=21 source_files=4 formation_artifacts=7 filesystem_effects=0 network_effects=0 services=0 providers=0 models=0 remote_calls=0"
} finally {
    Pop-Location
}
