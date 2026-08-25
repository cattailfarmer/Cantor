[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_succeeding_sop_review_admission_evidence.ps1'
$manifestPath = Join-Path $root 'experiments/succeeding_sop_review_admission_p0/artifacts/succeeding_sop_review_admission_evidence_manifest.json'
& $verifier -ManifestPath $manifestPath | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-sra-evidence-$([guid]::NewGuid().ToString('N'))"
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
    $missing.artifacts = @($missing.artifacts | Where-Object { $_.path -ne 'crates/cantor_core/src/succeeding_sop_review_admission.rs' })
    $missingPath = Join-Path $temporaryRoot 'missing.json'
    [IO.File]::WriteAllText($missingPath, ($missing | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $missingPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing required artifact was accepted' }

    $authority = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $authority.non_authority_statement = 'semantic truth and activation authorized'
    $authorityPath = Join-Path $temporaryRoot 'authority.json'
    [IO.File]::WriteAllText($authorityPath, ($authority | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $authorityPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority-laundered manifest was accepted' }

    $workspace = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $workspace.workspace_verification.debug.passed = 1223
    $workspacePath = Join-Path $temporaryRoot 'workspace.json'
    [IO.File]::WriteAllText($workspacePath, ($workspace | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $workspacePath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'workspace-count mutation was accepted' }

    $protocol = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $protocol.satisfaction_signature_uuid = '00000000-0000-0000-0000-000000000000'
    $protocolPath = Join-Path $temporaryRoot 'protocol.json'
    [IO.File]::WriteAllText($protocolPath, ($protocol | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $protocolPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'signature identity mutation was accepted' }

    $duplicate = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $duplicate.artifacts = @($duplicate.artifacts) + @($duplicate.artifacts[0])
    $duplicatePath = Join-Path $temporaryRoot 'duplicate.json'
    [IO.File]::WriteAllText($duplicatePath, ($duplicate | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $duplicatePath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'duplicate artifact was accepted' }
}
finally {
    [IO.Directory]::Delete($temporaryRoot, $true)
}

Write-Output 'succeeding_sop_review_admission_evidence_tests_passed positive=1 refusals=6 cleanup=true'
