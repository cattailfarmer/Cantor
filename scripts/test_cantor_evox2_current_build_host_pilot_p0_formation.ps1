param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verify = Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_formation.ps1'
& $verify -Root $root

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = Join-Path $parent ('evox2-current-host-formation-' + [guid]::NewGuid().Guid)
$resolved = [IO.Path]::GetFullPath($testRoot)
if (-not $resolved.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $manifestSource = Join-Path $root 'experiments/evox2_current_build_host_pilot_p0/formation_evidence_manifest.json'
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    $manifestDestination = Join-Path $testRoot 'experiments/evox2_current_build_host_pilot_p0/formation_evidence_manifest.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $manifestDestination) -Force | Out-Null
    Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination
    foreach ($artifact in $manifest.artifacts) {
        $destination = Join-Path $testRoot ([string]$artifact.path)
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root ([string]$artifact.path)) -Destination $destination
    }
    $scriptDestination = Join-Path $testRoot 'scripts/verify_cantor_evox2_current_build_host_pilot_p0_formation.ps1'
    New-Item -ItemType Directory -Path (Split-Path -Parent $scriptDestination) -Force | Out-Null
    Copy-Item -LiteralPath $verify -Destination $scriptDestination
    & $scriptDestination -Root $testRoot

    $spec = Join-Path $testRoot 'specifications/Cantor_EVO_X2_Current_Build_Host_Pilot_P0.sop'
    [IO.File]::AppendAllText($spec, [Environment]::NewLine)
    $refused = $false
    try { & $scriptDestination -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'tampered specification admitted' }
    Copy-Item -LiteralPath (Join-Path $root 'specifications/Cantor_EVO_X2_Current_Build_Host_Pilot_P0.sop') -Destination $spec -Force

    $mutated = Get-Content -LiteralPath $manifestDestination -Raw | ConvertFrom-Json
    $mutated.verification.autonomous_workspace_mutation_authorized = $true
    $mutated | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestDestination -NoNewline
    $refused = $false
    try { & $scriptDestination -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority promotion admitted' }
    Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination -Force

    $mutated = Get-Content -LiteralPath $manifestDestination -Raw | ConvertFrom-Json
    $mutated.verification.remote_root = 'C:/AI/services/cantor-needle-runtime'
    $mutated | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestDestination -NoNewline
    $refused = $false
    try { & $scriptDestination -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'protected-root substitution admitted' }

    'cantor_evox2_current_build_host_pilot_p0_formation_tests=passed isolated_successes=1 isolated_refusals=3'
} finally {
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
