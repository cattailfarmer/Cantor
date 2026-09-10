param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verifyRelative = 'scripts/verify_cantor_evox2_scratch_build_executor_p0_harness_implementation.ps1'
$verify = Join-Path $root $verifyRelative
& $verify -Root $root | Out-Null

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-scratch-build-harness-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'test root escaped build parent' }
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $manifestRelative = 'experiments/evox2_scratch_build_executor_p0/harness_implementation_evidence_manifest.json'
    $manifestSource = Join-Path $root $manifestRelative
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($relative in @($manifestRelative) + @($manifest.artifacts | ForEach-Object { [string] $_.path })) {
        $destination = Join-Path $testRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $destination
    }
    $isolatedVerify = Join-Path $testRoot $verifyRelative
    & $isolatedVerify -Root $testRoot | Out-Null

    $harnessRelative = 'scripts/invoke-cantor-evox2-scratch-build-once.ps1'
    [IO.File]::AppendAllText((Join-Path $testRoot $harnessRelative), "`n", [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'raw harness byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $harnessRelative) -Destination (Join-Path $testRoot $harnessRelative) -Force

    $runnerRelative = 'crates/cantor_ecosystem/src/bin/cantor-evox2-scratch-build-operation-runner.rs'
    [IO.File]::AppendAllText((Join-Path $testRoot $runnerRelative), "`n", [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'raw operation-runner byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $runnerRelative) -Destination (Join-Path $testRoot $runnerRelative) -Force

    $manifestPath = Join-Path $testRoot $manifestRelative
    $changed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $changed.verification.live_effects_authorized = $true
    [IO.File]::WriteAllText($manifestPath, ($changed | ConvertTo-Json -Depth 30 -Compress), [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'live authority promotion admitted' }
    Copy-Item -LiteralPath $manifestSource -Destination $manifestPath -Force

    Remove-Item -LiteralPath (Join-Path $testRoot 'feature_support\Cantor_EVO_X2_Scratch_Build_Executor_P0_Harness_Coverage.sop') -Force
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing evidence artifact admitted' }

    'cantor_evox2_scratch_build_harness_implementation_tests=passed isolated_successes=1 isolated_refusals=4 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { [IO.Directory]::Delete(('\\?\' + $testRoot), $true) }
}
