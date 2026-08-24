[CmdletBinding()]
param([string]$EvidencePath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$cargo = (Get-Command cargo -ErrorAction Stop).Source
$fixtureScript = Join-Path $PSScriptRoot 'build_sjs_commit_envelope_journal_p2_fixtures.ps1'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-sjs-commit-envelope-p2-$([guid]::NewGuid())"
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Cli([string[]]$Arguments) {
    $global:LASTEXITCODE = 0
    $lines = @(& $script:binary @Arguments 2>&1)
    [pscustomobject]@{ Lines = $lines; ExitCode = $LASTEXITCODE }
}

function Write-Json([object]$Value, [string]$Path) {
    $json = ([string]::Join("`n", @($Value | ConvertTo-Json -Depth 100))).Replace("`r", "")
    [IO.File]::WriteAllText($Path, ($json + "`n"), [Text.UTF8Encoding]::new($false))
}

& $fixtureScript -VerifyOnly | Out-Null
$env:CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS = 'true'
try {
    & $cargo build --quiet --release --offline --locked -p cantor_ecosystem --bin cantor-sjs-commit-envelope-journal-verify
    if ($LASTEXITCODE -ne 0) { throw 'journal release binary build failed' }
}
finally {
    Remove-Item Env:\CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS -ErrorAction SilentlyContinue
}
$script:binary = Join-Path $root 'target\release\cantor-sjs-commit-envelope-journal-verify.exe'
if (-not (Test-Path -LiteralPath $script:binary -PathType Leaf)) {
    $script:binary = Join-Path $root 'target\release\cantor-sjs-commit-envelope-journal-verify'
}
if (-not (Test-Path -LiteralPath $script:binary -PathType Leaf)) { throw 'journal release binary is absent' }

[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$successes = 0
$refusals = 0
try {
    $one = Invoke-Cli @('--bundle', (Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2\one_link.json'))
    Assert-Exact ($one.ExitCode -eq 0 -and $one.Lines.Count -eq 1) 'one-link CLI success differs'
    $oneReceipt = $one.Lines[0] | ConvertFrom-Json
    Assert-Exact ([int]$oneReceipt.link_count -eq 1 -and [int]$oneReceipt.open_tip_count -eq 1) 'one-link receipt count differs'
    $successes++

    $two = Invoke-Cli @('--bundle', (Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2\two_link.json'))
    Assert-Exact ($two.ExitCode -eq 0 -and $two.Lines.Count -eq 1) 'two-link CLI success differs'
    $twoReceipt = $two.Lines[0] | ConvertFrom-Json
    Assert-Exact ([int]$twoReceipt.link_count -eq 2 -and [int]$twoReceipt.open_tip_count -eq 1) 'two-link receipt count differs'
    $successes++

    $replay = Invoke-Cli @('--bundle', (Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2\two_link.json'))
    Assert-Exact ($replay.ExitCode -eq 0 -and $replay.Lines[0] -ceq $two.Lines[0]) 'deterministic CLI replay differs'
    $successes++

    $unknown = Invoke-Cli @('--output', (Join-Path $temporaryRoot 'forbidden.json'))
    Assert-Exact ($unknown.ExitCode -eq 2 -and $unknown.Lines.Count -eq 1) 'unknown argument was not refused'
    Assert-Exact (($unknown.Lines[0] | ConvertFrom-Json).code -ceq 'cli') 'unknown argument fault differs'
    $refusals++

    $digestCandidate = Get-Content -LiteralPath (Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2\one_link.json') -Raw | ConvertFrom-Json
    $digestCandidate.open_tip_commit = '3333333333333333333333333333333333333333'
    $digestPath = Join-Path $temporaryRoot 'digest_tamper.json'
    Write-Json $digestCandidate $digestPath
    $digestRefusal = Invoke-Cli @('--bundle', $digestPath)
    Assert-Exact ($digestRefusal.ExitCode -eq 2) 'digest tamper was not refused'
    Assert-Exact (($digestRefusal.Lines[0] | ConvertFrom-Json).code -in @('chain', 'digest')) 'digest tamper fault differs'
    $refusals++

    $authorityCandidate = Get-Content -LiteralPath (Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2\one_link.json') -Raw | ConvertFrom-Json
    $authorityCandidate.links[0].placement.physical_contact = $true
    $authorityPath = Join-Path $temporaryRoot 'authority_tamper.json'
    Write-Json $authorityCandidate $authorityPath
    $authorityRefusal = Invoke-Cli @('--bundle', $authorityPath)
    Assert-Exact ($authorityRefusal.ExitCode -eq 2) 'authority tamper was not refused'
    Assert-Exact (($authorityRefusal.Lines[0] | ConvertFrom-Json).code -ceq 'authority') 'authority tamper fault differs'
    $refusals++

    $summary = [ordered]@{
        profile = 'cantor-sjs-commit-envelope-journal-p2-controlled-evidence/0.1'
        fixture_count = 2
        one_link_count = [int]$oneReceipt.link_count
        two_link_count = [int]$twoReceipt.link_count
        one_open_tip_count = [int]$oneReceipt.open_tip_count
        two_open_tip_count = [int]$twoReceipt.open_tip_count
        one_result_sha256 = [string]$oneReceipt.result_sha256
        two_result_sha256 = [string]$twoReceipt.result_sha256
        cli_successes = $successes
        cli_refusals = $refusals
        deterministic_replay = $true
        authority = 'verification_only'
        placement_authority = 'supplied_data'
        physical_contact = $false
        git_process_count = 0
        mutation_count = 0
    }
    if ($EvidencePath) {
        $resolvedEvidence = [IO.Path]::GetFullPath((Join-Path $root $EvidencePath))
        $resolvedRoot = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if (-not $resolvedEvidence.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'evidence path escaped repository root' }
        [IO.Directory]::CreateDirectory((Split-Path -Parent $resolvedEvidence)) | Out-Null
        Write-Json $summary $resolvedEvidence
    }
    Write-Output "sjs_commit_envelope_journal_p2_tests=passed cli_successes=$successes cli_refusals=$refusals"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporary = [IO.Path]::GetFullPath($temporaryRoot)
        if (-not $resolvedTemporary.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase)) { throw 'temporary cleanup escaped system temp' }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
