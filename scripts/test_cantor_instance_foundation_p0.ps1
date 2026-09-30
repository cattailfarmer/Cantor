param([string]$TargetDirectory = "D:\CantorBuilds\target")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$env:CARGO_TARGET_DIR = $TargetDirectory
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"

Push-Location $repositoryRoot
try {
    cargo test -p cantor_instance_contract --all-targets --locked
    if ($LASTEXITCODE -ne 0) { throw "focused debug tests failed" }
    $priorFlags = $env:RUSTFLAGS
    try {
        $env:RUSTFLAGS = "-C overflow-checks=on"
        cargo test -p cantor_instance_contract --all-targets --release --locked
        if ($LASTEXITCODE -ne 0) { throw "focused overflow-checked release tests failed" }
    } finally { $env:RUSTFLAGS = $priorFlags }
    cargo clippy -p cantor_instance_contract --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "focused Clippy failed" }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "format check failed" }

    $temporary = Join-Path $TargetDirectory "cantor-instance-contract-fixtures"
    New-Item -ItemType Directory -Force -Path $temporary | Out-Null
    $utf8 = New-Object Text.UTF8Encoding($false)
    $kernel = cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --quiet -- kernel
    if ($LASTEXITCODE -ne 0) { throw "kernel fixture failed" }
    $instance = cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --quiet -- eclipse
    if ($LASTEXITCODE -ne 0) { throw "instance fixture failed" }
    $candidate = cargo run -p cantor_instance_contract --bin cantor-instance-fixture --locked --quiet -- eclipse-kernel-candidate
    if ($LASTEXITCODE -ne 0) { throw "candidate fixture failed" }
    $kernelPath = Join-Path $temporary "kernel.json"
    $instancePath = Join-Path $temporary "eclipse.json"
    $candidatePath = Join-Path $temporary "eclipse-kernel-candidate.json"
    [IO.File]::WriteAllText($kernelPath, ($kernel -join "`n") + "`n", $utf8)
    [IO.File]::WriteAllText($instancePath, ($instance -join "`n") + "`n", $utf8)
    [IO.File]::WriteAllText($candidatePath, ($candidate -join "`n") + "`n", $utf8)
    $admitted = cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --quiet -- $kernelPath $instancePath
    if ($LASTEXITCODE -ne 0 -or ($admitted -join "`n") -notmatch '"status": "admitted"') { throw "fresh-process admitted verification failed" }
    $held = cargo run -p cantor_instance_contract --bin cantor-instance-verify --locked --quiet -- $kernelPath $candidatePath
    if ($LASTEXITCODE -ne 2 -or ($held -join "`n") -notmatch 'kernel_candidate_requires_separate_promotion') { throw "fresh-process held verification failed" }
    Write-Output "cantor_instance_foundation_tests_passed=true debug=14 release=14 cli_admitted=1 cli_held=1 processes=0 providers=0 remote_calls=0 effects=0 installations=0 updates=0 synthetic_trials=0"
} finally {
    Pop-Location
}
