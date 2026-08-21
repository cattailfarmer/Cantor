[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$experimentManifest = Join-Path $repositoryRoot 'experiments\llama_tool_reflection\Cargo.toml'
$probeOutput = Join-Path ([System.IO.Path]::GetTempPath()) "cantor-lifecycle-bridge-probe-$([guid]::NewGuid()).json"
$verificationOutput = Join-Path ([System.IO.Path]::GetTempPath()) "cantor-lifecycle-bridge-verification-$([guid]::NewGuid()).json"
$unavailableVerificationOutput = Join-Path ([System.IO.Path]::GetTempPath()) "cantor-lifecycle-provider-unavailable-verification-$([guid]::NewGuid()).json"

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
    & cargo run -p cantor_lifecycle_tool_loop --bin cantor-lifecycle-evidence-verify --locked --offline -- `
        --input $probeOutput `
        --output $verificationOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'provider-independent lifecycle bridge evidence did not recompute'
    }
    $verification = Get-Content -LiteralPath $verificationOutput -Raw | ConvertFrom-Json
    if ($verification.status -ne 'passed' `
        -or $verification.verified_trial_count -ne 8 `
        -or $verification.comparison.transport_bytes_saved -ne 122944) {
        throw 'provider-independent lifecycle bridge verification is incomplete'
    }
    & cargo run -p cantor_lifecycle_tool_loop --bin cantor-lifecycle-evidence-verify --locked --offline -- `
        --evidence-kind provider-unavailable `
        --input 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json' `
        --output $unavailableVerificationOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'provider-unavailable evidence did not verify'
    }
    $unavailableVerification = Get-Content -LiteralPath $unavailableVerificationOutput -Raw | ConvertFrom-Json
    if ($unavailableVerification.status -ne 'provider_unavailable_verified' `
        -or $unavailableVerification.provider_contacted -ne $false `
        -or $unavailableVerification.registration_count -ne 0 `
        -or $unavailableVerification.trial_count -ne 0) {
        throw 'provider-unavailable verification is incomplete'
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
    if (Test-Path -LiteralPath $verificationOutput) {
        Remove-Item -LiteralPath $verificationOutput -Force
    }
    if (Test-Path -LiteralPath $unavailableVerificationOutput) {
        Remove-Item -LiteralPath $unavailableVerificationOutput -Force
    }
}

Write-Output 'lifecycle_tool_loop_provider_independent=passed'
