[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_succeeding_sop_activation_transaction_evidence.ps1'
$manifestPath = Join-Path $root 'experiments/succeeding_sop_activation_transaction_p0/artifacts/succeeding_sop_activation_transaction_evidence_manifest.json'
$controlledPath = Join-Path $root 'experiments/succeeding_sop_activation_transaction_p0/artifacts/controlled_provider_free_verification.json'
& $verifier -ManifestPath $manifestPath -ControlledPath $controlledPath | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "cantor-satx-evidence-$([guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $baseline = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $controlledBaseline = Get-Content -LiteralPath $controlledPath -Raw | ConvertFrom-Json

    $tampered = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $tampered.artifacts[0].sha256 = '0' * 64
    $tamperedPath = Join-Path $temporaryRoot 'tampered.json'
    [IO.File]::WriteAllText($tamperedPath, ($tampered | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $tamperedPath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'tampered manifest was accepted' }

    $missing = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $missing.artifacts = @($missing.artifacts | Where-Object { $_.path -ne 'crates/cantor_core/src/succeeding_sop_activation_transaction.rs' })
    $missingPath = Join-Path $temporaryRoot 'missing.json'
    [IO.File]::WriteAllText($missingPath, ($missing | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $missingPath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing required artifact was accepted' }

    $authority = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $authority.non_authority_statement = 'physical activation authorized'
    $authorityPath = Join-Path $temporaryRoot 'authority.json'
    [IO.File]::WriteAllText($authorityPath, ($authority | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $authorityPath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority-laundered manifest was accepted' }

    $workspace = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $workspace.workspace_verification.debug.passed = 1268
    $workspacePath = Join-Path $temporaryRoot 'workspace.json'
    [IO.File]::WriteAllText($workspacePath, ($workspace | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $workspacePath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'workspace-count mutation was accepted' }

    $identity = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $identity.evidence_manifest_uuid = '00000000-0000-0000-0000-000000000000'
    $identityPath = Join-Path $temporaryRoot 'identity.json'
    [IO.File]::WriteAllText($identityPath, ($identity | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $identityPath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'manifest-identity mutation was accepted' }

    $duplicate = $baseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $duplicate.artifacts = @($duplicate.artifacts) + @($duplicate.artifacts[0])
    $duplicatePath = Join-Path $temporaryRoot 'duplicate.json'
    [IO.File]::WriteAllText($duplicatePath, ($duplicate | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $duplicatePath -ControlledPath $controlledPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'duplicate artifact was accepted' }

    $physical = $controlledBaseline | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $physical.boundaries.registry_persisted = $true
    $physicalPath = Join-Path $temporaryRoot 'physical.json'
    [IO.File]::WriteAllText($physicalPath, ($physical | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verifier -ManifestPath $manifestPath -ControlledPath $physicalPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'physical-boundary mutation was accepted' }
}
finally {
    [IO.Directory]::Delete($temporaryRoot, $true)
}

Write-Output 'succeeding_sop_activation_transaction_evidence_tests_passed positive=1 refusals=7 cleanup=true'
