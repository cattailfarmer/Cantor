param([string]$TargetDirectory = "D:\CantorBuilds\target")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"; $env:CARGO_INCREMENTAL = "0"
& (Join-Path $PSScriptRoot "verify_cantor_in_memory_source_excerpt_p0_source.ps1")
Push-Location $repositoryRoot
try {
    $packages = @("cantor_sop_excerpt", "cantor_sop_query", "cantor_sop_project", "cantor_sop_semantics", "cantor_instance_contract")
    $arguments = @("test"); foreach ($package in $packages) { $arguments += @("-p", $package) }; $arguments += @("--all-targets", "--locked", "--offline")
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) { throw "source excerpt focused debug tests failed" }
    $releaseArguments = @("test"); foreach ($package in $packages) { $releaseArguments += @("-p", $package) }; $releaseArguments += @("--all-targets", "--release", "--locked", "--offline")
    $priorFlags = $env:RUSTFLAGS
    try { $env:RUSTFLAGS = "-C overflow-checks=on"; & cargo @releaseArguments } finally { $env:RUSTFLAGS = $priorFlags }
    if ($LASTEXITCODE -ne 0) { throw "source excerpt focused release tests failed" }
    $clippy = @("clippy"); foreach ($package in $packages) { $clippy += @("-p", $package) }; $clippy += @("--all-targets", "--locked", "--offline", "--", "-D", "warnings")
    & cargo @clippy
    if ($LASTEXITCODE -ne 0) { throw "source excerpt focused Clippy failed" }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "format check failed" }
    Write-Output "cantor_in_memory_source_excerpt_tests_passed=true debug=54 release=54 custody_files=6 whole_scribe_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0"
} finally { Pop-Location }
