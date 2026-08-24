param([string]$Configuration = 'debug')

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$binary = Join-Path $root "target/$Configuration/cantor-sjs-graph-verify.exe"
$inventory = Join-Path $root 'fixtures/sjs_repository_graph_p0/diff_inventory.json'
$changeSet = Join-Path $root 'fixtures/sjs_repository_graph_p0/change_set.json'
$expectedReceipt = Join-Path $root 'fixtures/sjs_repository_graph_p0/verification_receipt.json'

if (-not (Test-Path -LiteralPath $binary)) { throw "verifier binary is absent: $binary" }
& (Join-Path $root 'scripts/build_sjs_repository_graph_p0_evidence_manifest.ps1') -VerifyOnly
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temp = Join-Path $tempBase ("cantor-sjs-graph-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
$resolvedTemp = [IO.Path]::GetFullPath($temp)
if (-not $resolvedTemp.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary root escaped the system temporary directory'
}

try {
    Push-Location $temp
    try {
        & $binary --change-set $changeSet --diff-inventory $inventory --output receipt.json
        if ($LASTEXITCODE -ne 0) { throw 'bare output filename invocation failed' }
        if (-not (Test-Path -LiteralPath 'receipt.json')) { throw 'bare output receipt is absent' }

        & $binary --change-set $changeSet --diff-inventory $inventory --output nested/receipt.json
        if ($LASTEXITCODE -ne 0) { throw 'nested output invocation failed' }
        if (-not (Test-Path -LiteralPath 'nested/receipt.json')) { throw 'nested output receipt is absent' }

        $actual = Get-Content -LiteralPath 'receipt.json' -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 64 -Compress
        $expected = Get-Content -LiteralPath $expectedReceipt -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 64 -Compress
        if ($actual -cne $expected) { throw 'CLI receipt differs from checked fixture' }

        $stdout = (& $binary --change-set $changeSet --diff-inventory $inventory | Out-String) | ConvertFrom-Json | ConvertTo-Json -Depth 64 -Compress
        if ($LASTEXITCODE -ne 0 -or $stdout -cne $expected) { throw 'stdout receipt differs' }

        & $binary --unknown 2>$null
        if ($LASTEXITCODE -ne 2) { throw 'unknown argument did not refuse with exit code 2' }

        $tampered = Get-Content -LiteralPath $changeSet -Raw | ConvertFrom-Json
        $tampered.physical_contact = $true
        [IO.File]::WriteAllText(
            (Join-Path $temp 'tampered.json'),
            (($tampered | ConvertTo-Json -Depth 64) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        & $binary --change-set (Join-Path $temp 'tampered.json') --diff-inventory $inventory 2>$null
        if ($LASTEXITCODE -ne 2) { throw 'authority tamper did not refuse with exit code 2' }

        [IO.File]::WriteAllText(
            (Join-Path $temp 'malformed.json'),
            '{',
            [Text.UTF8Encoding]::new($false)
        )
        & $binary --change-set (Join-Path $temp 'malformed.json') --diff-inventory $inventory 2>$null
        if ($LASTEXITCODE -ne 2) { throw 'malformed JSON did not refuse with exit code 2' }
    } finally {
        Pop-Location
    }
} finally {
    if (Test-Path -LiteralPath $resolvedTemp) {
        if (-not $resolvedTemp.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'refusing to remove a temporary path outside the system temporary directory'
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

Write-Output 'sjs_repository_graph_p0_tests=passed cli_successes=3 cli_refusals=3'
