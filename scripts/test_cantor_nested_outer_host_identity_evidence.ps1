[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_nested_outer_host_identity_evidence.ps1'
$manifestPath = Join-Path $root 'experiments/nested_outer_host_identity_p0/artifacts/nested_outer_host_identity_evidence_manifest.json'

& $verifier -ManifestPath $manifestPath | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-nho-evidence-$([guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $base = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $tamperedBytes = $base | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $tamperedBytes.artifacts[0].bytes = [uint64]$tamperedBytes.artifacts[0].bytes + 1
    $bytesPath = Join-Path $temporaryRoot 'tampered-bytes.json'
    [IO.File]::WriteAllText($bytesPath, ($tamperedBytes | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    try {
        & $verifier -ManifestPath $bytesPath | Out-Null
        throw 'tampered byte identity was accepted'
    }
    catch {
        if ($_.Exception.Message -eq 'tampered byte identity was accepted') { throw }
    }

    $missingRequired = $base | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $missingRequired.artifacts = @($missingRequired.artifacts | Where-Object {
        $_.path -ne 'crates/cantor_core/src/nested_host_identity.rs'
    })
    $missingPath = Join-Path $temporaryRoot 'missing-required.json'
    [IO.File]::WriteAllText($missingPath, ($missingRequired | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    try {
        & $verifier -ManifestPath $missingPath | Out-Null
        throw 'missing required evidence was accepted'
    }
    catch {
        if ($_.Exception.Message -eq 'missing required evidence was accepted') { throw }
    }
}
finally {
    [IO.Directory]::Delete($temporaryRoot, $true)
}

Write-Output 'nested_outer_host_identity_evidence_tests_passed positive=1 refusals=2 cleanup=true'
