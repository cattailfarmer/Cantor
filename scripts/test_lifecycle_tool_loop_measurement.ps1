[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$experimentManifest = Join-Path $repositoryRoot 'experiments\llama_tool_reflection\Cargo.toml'
$probeOutput = Join-Path ([System.IO.Path]::GetTempPath()) "cantor-lifecycle-bridge-probe-$([guid]::NewGuid()).json"

Push-Location $repositoryRoot
try {
    & cargo test -p cantor_lifecycle_tool_loop -p cantor_compiler_mcp -p cantor_compiler_custody_mcp --locked --offline
    if ($LASTEXITCODE -ne 0) {
        throw 'workspace lifecycle bridge tests failed'
    }
    & cargo test --manifest-path $experimentManifest --locked --offline
    if ($LASTEXITCODE -ne 0) {
        throw 'provider-independent lifecycle transcript tests failed'
    }
    & cargo run -p cantor_lifecycle_tool_loop --bin cantor-lifecycle-bridge-probe --locked --offline -- --output $probeOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'provider-independent lifecycle bridge probe failed'
    }
    $probe = Get-Content -LiteralPath $probeOutput -Raw | ConvertFrom-Json
    if ($probe.status -ne 'passed' `
        -or $probe.provider_contacted -ne $false `
        -or $probe.restart_trial.old_handle_refused -ne $true `
        -or $probe.trials.Count -ne 8) {
        throw 'provider-independent lifecycle bridge probe evidence is incomplete'
    }
    & cargo clippy -p cantor_lifecycle_tool_loop -p cantor_compiler_mcp -p cantor_compiler_custody_mcp --all-targets --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw 'workspace lifecycle bridge lint failed'
    }
    & cargo clippy --manifest-path $experimentManifest --all-targets --locked --offline -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw 'lifecycle experiment lint failed'
    }
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        throw 'workspace format gate failed'
    }
    & cargo fmt --manifest-path $experimentManifest -- --check
    if ($LASTEXITCODE -ne 0) {
        throw 'experiment format gate failed'
    }
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $probeOutput) {
        Remove-Item -LiteralPath $probeOutput -Force
    }
}

Write-Output 'lifecycle_tool_loop_provider_independent=passed'
