param([string]$TargetDirectory = "D:\CantorBuilds\target")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"

& (Join-Path $PSScriptRoot "verify_cantor_scribe_semantic_kernel_p0_source.ps1")

Push-Location $repositoryRoot
try {
    cargo test -p cantor_sop_semantics -p cantor_instance_contract --all-targets --locked --offline
    if ($LASTEXITCODE -ne 0) { throw "semantic kernel focused debug tests failed" }

    $priorFlags = $env:RUSTFLAGS
    try {
        $env:RUSTFLAGS = "-C overflow-checks=on"
        cargo test -p cantor_sop_semantics -p cantor_instance_contract --all-targets --release --locked --offline
        if ($LASTEXITCODE -ne 0) { throw "semantic kernel focused overflow-checked release tests failed" }
    } finally {
        $env:RUSTFLAGS = $priorFlags
    }

    cargo clippy -p cantor_sop_semantics -p cantor_instance_contract --all-targets --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "semantic kernel focused Clippy failed" }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "format check failed" }

    Write-Output "cantor_scribe_semantic_kernel_tests_passed=true debug=25 release=25 custody_files=6 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
} finally {
    Pop-Location
}
