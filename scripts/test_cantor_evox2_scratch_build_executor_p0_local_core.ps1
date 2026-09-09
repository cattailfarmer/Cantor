param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verifyRelative = 'scripts/verify_cantor_evox2_scratch_build_executor_p0_local_core.ps1'
$verify = Join-Path $root $verifyRelative
& $verify -Root $root

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = Join-Path $parent ('evox2-scratch-build-local-core-' + [guid]::NewGuid().Guid)
$resolved = [IO.Path]::GetFullPath($testRoot)
if (-not $resolved.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
try {
    New-Item -ItemType Directory -Path $resolved -Force | Out-Null
    $manifestRelative = 'experiments/evox2_scratch_build_executor_p0/local_core_evidence_manifest.json'
    $manifestSource = Join-Path $root $manifestRelative
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($relative in @($manifestRelative) + @($manifest.artifacts | ForEach-Object { [string] $_.path })) {
        $source = Join-Path $root $relative
        $destination = Join-Path $resolved $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $isolatedVerify = Join-Path $resolved $verifyRelative
    & $isolatedVerify -Root $resolved

    $moduleRelative = 'crates/cantor_core/src/evox2_scratch_build_executor.rs'
    $modulePath = Join-Path $resolved $moduleRelative
    [IO.File]::AppendAllText($modulePath, [Environment]::NewLine)
    $refused = $false
    try { & $isolatedVerify -Root $resolved | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'raw module byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $moduleRelative) -Destination $modulePath -Force

    $manifestPath = Join-Path $resolved $manifestRelative
    $mutated = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $mutated.verification.effects = 1
    $mutated | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestPath -NoNewline
    $refused = $false
    try { & $isolatedVerify -Root $resolved | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'effect promotion admitted' }
    Copy-Item -LiteralPath $manifestSource -Destination $manifestPath -Force

    $mutated = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $mutated.verification.remote_effects_authorized = $true
    $mutated | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestPath -NoNewline
    $refused = $false
    try { & $isolatedVerify -Root $resolved | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'remote authority promotion admitted' }
    Copy-Item -LiteralPath $manifestSource -Destination $manifestPath -Force

    $mutated = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $mutated.verification.authority_grants = 6
    $mutated | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestPath -NoNewline
    $refused = $false
    try { & $isolatedVerify -Root $resolved | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority grant promotion admitted' }

    'cantor_evox2_scratch_build_executor_p0_local_core_tests=passed isolated_successes=1 isolated_refusals=4'
} finally {
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
