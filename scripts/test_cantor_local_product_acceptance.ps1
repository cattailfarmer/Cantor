[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$audit = Join-Path $PSScriptRoot 'audit_cantor_local_product_acceptance.ps1'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-local-product-acceptance-$([guid]::NewGuid())"
$goodOutput = Join-Path $temporaryRoot 'acceptance.json'
$bareName = ".cantor-local-product-acceptance-$([guid]::NewGuid()).json"
$bareOutput = Join-Path $root $bareName

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([object]$Value, [string]$Path) {
    [IO.File]::WriteAllText(
        $Path,
        "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
        [Text.UTF8Encoding]::new($false)
    )
}

function Assert-VerifyRefused([string]$Name, [scriptblock]$Mutation) {
    $candidatePath = Join-Path $temporaryRoot "$Name.json"
    $candidate = Get-Content -LiteralPath $goodOutput -Raw | ConvertFrom-Json
    & $Mutation $candidate
    Write-Json $candidate $candidatePath
    $refused = $false
    try {
        & $audit -VerifyOnly -OutputPath $candidatePath *> $null
    }
    catch {
        $refused = $true
    }
    Assert-Condition $refused "acceptance verifier admitted tamper: $Name"
}

[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
Push-Location $root
try {
    & $audit -OutputPath $goodOutput | Out-Null
    & $audit -VerifyOnly -OutputPath $goodOutput | Out-Null
    $report = Get-Content -LiteralPath $goodOutput -Raw | ConvertFrom-Json
    Assert-Condition ($report.profile -ceq 'cantor-local-product-developer-alpha-acceptance/0.1') 'acceptance profile differs'
    Assert-Condition ($report.status -ceq 'provider_free_developer_alpha_verified_with_declared_gaps') 'acceptance status differs'
    Assert-Condition (@($report.artifacts).Count -eq 8) 'immutable artifact account differs'
    Assert-Condition ([int]$report.evidence_state.stale_reference_count -eq 0) 'stale recursive evidence admitted'
    Assert-Condition ($report.component_acceptance.live_provider -ceq 'provider_unavailable_zero_trials') 'provider-unavailable boundary differs'
    Assert-Condition ($report.release_stage.developer_alpha -ceq 'satisfied_provider_free') 'developer-alpha stage differs'
    Assert-Condition ($report.release_stage.private_beta -ceq 'partial') 'private-beta gap differs'
    Assert-Condition ($report.release_stage.operator_product -ceq 'not_satisfied') 'operator-product gap differs'
    Assert-Condition ($report.release_stage.production_product -ceq 'not_satisfied') 'production-product gap differs'

    & $audit -OutputPath $bareName | Out-Null
    Assert-Condition (Test-Path -LiteralPath $bareOutput -PathType Leaf) 'bare output filename was not created'
    & $audit -VerifyOnly -OutputPath $bareName | Out-Null

    $wslGuardRefused = $false
    try {
        & $audit -UseWslFocusedLane -OutputPath $goodOutput *> $null
    }
    catch {
        $wslGuardRefused = $true
    }
    Assert-Condition $wslGuardRefused 'WSL focused-lane option was admitted without focused execution'

    Assert-VerifyRefused 'artifact_hash' {
        param($candidate)
        $candidate.artifacts[0].sha256 = [string]::new('0', 64)
    }
    Assert-VerifyRefused 'stage_status' {
        param($candidate)
        $candidate.status = 'production_ready'
    }
    Assert-VerifyRefused 'capability_denial' {
        param($candidate)
        $candidate.capability_denials[0] = 'live_provider_success_claimed'
    }
    Assert-VerifyRefused 'recursive_evidence_count' {
        param($candidate)
        $candidate.evidence_state.artifact_reference_count = [int]$candidate.evidence_state.artifact_reference_count + 1
    }
    Assert-VerifyRefused 'nonancestor_commit' {
        param($candidate)
        $candidate.source_commit = [string]::new('0', 40)
    }
    Assert-VerifyRefused 'unknown_field' {
        param($candidate)
        $candidate | Add-Member -NotePropertyName unexpected_authority -NotePropertyValue $true
    }
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $bareOutput) {
        Remove-Item -LiteralPath $bareOutput -Force
    }
}

Write-Output 'local_product_acceptance_tests=passed report_refusals=6 cli_refusals=1'
