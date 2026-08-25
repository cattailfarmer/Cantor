[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_provider_free_self_work_composition_evidence.ps1'
$manifestPath = Join-Path $root 'experiments/provider_free_self_work_composition_p0/artifacts/provider_free_self_work_composition_evidence_manifest.json'
& $verifier -ManifestPath $manifestPath | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-pfc-evidence-$([guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $baseline = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    $tampered = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $tampered.artifacts[0].sha256 = '0' * 64
    $tamperedPath = Join-Path $temporaryRoot 'tampered.json'
    [IO.File]::WriteAllText($tamperedPath, ($tampered | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $tamperedPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'tampered manifest was accepted' }

    $missing = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $missing.artifacts = @($missing.artifacts | Where-Object { $_.path -ne 'crates/cantor_ecosystem/src/provider_free_self_work_composition.rs' })
    $missingPath = Join-Path $temporaryRoot 'missing.json'
    [IO.File]::WriteAllText($missingPath, ($missing | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $missingPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing required artifact was accepted' }

    $authority = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $authority.non_authority_statement = 'physical update and activation authorized'
    $authorityPath = Join-Path $temporaryRoot 'authority.json'
    [IO.File]::WriteAllText($authorityPath, ($authority | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $authorityPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority-laundered manifest was accepted' }
}
finally {
    [IO.Directory]::Delete($temporaryRoot, $true)
}

Write-Output 'provider_free_self_work_composition_evidence_tests_passed positive=1 refusals=3 cleanup=true'
