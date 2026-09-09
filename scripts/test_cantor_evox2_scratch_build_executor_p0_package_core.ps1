param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verifyRelative = 'scripts/verify_cantor_evox2_scratch_build_executor_p0_package_core.ps1'
$verify = Join-Path $root $verifyRelative
& $verify -Root $root

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-scratch-build-package-core-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $manifestRelative = 'experiments/evox2_scratch_build_executor_p0/package_core_evidence_manifest.json'
    $manifestSource = Join-Path $root $manifestRelative
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($relative in @($manifestRelative) + @($manifest.artifacts | ForEach-Object { [string] $_.path })) {
        $source = Join-Path $root $relative
        $destination = Join-Path $testRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $isolatedVerify = Join-Path $testRoot $verifyRelative
    & $isolatedVerify -Root $testRoot | Out-Null

    $semanticRelative = 'crates/cantor_core/src/evox2_scratch_build_executor.rs'
    $semantic = Join-Path $testRoot $semanticRelative
    [IO.File]::AppendAllText($semantic, [Environment]::NewLine)
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'raw semantic byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $semanticRelative) -Destination $semantic -Force

    $manifestPath = Join-Path $testRoot $manifestRelative
    foreach ($mutation in @('effects', 'live', 'count')) {
        Copy-Item -LiteralPath $manifestSource -Destination $manifestPath -Force
        $changed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($mutation -ceq 'effects') { $changed.verification.effects = 1 }
        if ($mutation -ceq 'live') { $changed.verification.live_effects_authorized = $true }
        if ($mutation -ceq 'count') { $changed.verification.package_artifacts = 21 }
        [IO.File]::WriteAllText($manifestPath, ($changed | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false))
        $refused = $false
        try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
        if (-not $refused) { throw "$mutation promotion admitted" }
    }
    'cantor_evox2_scratch_build_executor_p0_package_core_tests=passed isolated_successes=1 isolated_refusals=4 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
