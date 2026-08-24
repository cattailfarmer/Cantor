[CmdletBinding()]
param([switch]$VerifyOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$fixtureRoot = Join-Path $root 'fixtures\sjs_commit_envelope_journal_p2'
$cargo = (Get-Command cargo -ErrorAction Stop).Source

function Get-FixtureJson([string]$Name) {
    $lines = @(& $cargo run --quiet --offline --locked -p cantor_ecosystem --example build_sjs_commit_envelope_journal_p2_fixture -- $Name)
    if ($LASTEXITCODE -ne 0) { throw "fixture generator failed: $Name" }
    (([string]::Join("`n", $lines)).Replace("`r", "") + "`n")
}

$fixtures = [ordered]@{
    'one_link.json' = Get-FixtureJson 'one'
    'two_link.json' = Get-FixtureJson 'two'
}

foreach ($name in $fixtures.Keys) {
    $path = Join-Path $fixtureRoot $name
    if ($VerifyOnly) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "fixture absent: $name" }
        $actual = [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false))
        if ($actual -cne $fixtures[$name]) { throw "fixture differs: $name" }
    }
    else {
        [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
        [IO.File]::WriteAllText($path, $fixtures[$name], [Text.UTF8Encoding]::new($false))
    }
}

Write-Output "sjs_commit_envelope_journal_p2_fixtures=$($fixtures.Count) verified=$([bool]$VerifyOnly)"
