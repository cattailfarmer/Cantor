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

    $packageEvidence = Get-Content -LiteralPath (Join-Path $root 'experiments\evox2_scratch_build_executor_p0\package_construction_evidence.json') -Raw | ConvertFrom-Json
    if (-not [bool] $packageEvidence.package_verified -or [int] $packageEvidence.commission_authority_grants -ne 5 -or [int] $packageEvidence.construction_authority_grants -ne 0 -or [int] $packageEvidence.effects -ne 0) { throw 'package commission authority evidence differs' }
    $harness = Get-Content -LiteralPath (Join-Path $root $harnessRelative) -Raw
    if (-not $harness.Contains('[int] $result.authority_grants -ne 5') -or $harness.Contains('[int] $result.authority_grants -ne 0')) { throw 'host harness commission authority expectation regressed' }

    $builderPath = Join-Path $root 'scripts\build_cantor_evox2_scratch_build_executor_p0_package.ps1'
    $tokens = $null
    $errors = $null
    $builderAst = [Management.Automation.Language.Parser]::ParseFile($builderPath, [ref] $tokens, [ref] $errors)
    if ($errors.Count -ne 0) { throw 'package builder AST unavailable' }
    $functionAst = $builderAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Copy-CanonicalRepositoryJson'
    }, $true)
    if ($null -eq $functionAst) { throw 'canonical repository JSON function absent' }
    . ([scriptblock]::Create($functionAst.Extent.Text))
    $utf8 = [Text.UTF8Encoding]::new($false)
    $canonical = '{"x":1}'
    foreach ($ending in @("`n", "`r`n")) {
        $source = Join-Path $testRoot ('canonical-success-' + [guid]::NewGuid().Guid + '.json')
        $destination = $source + '.out'
        [IO.File]::WriteAllBytes($source, $utf8.GetBytes($canonical + $ending))
        Copy-CanonicalRepositoryJson $source $destination
        if ([IO.File]::ReadAllText($destination) -cne $canonical) { throw 'canonical repository JSON success differs' }
    }
    $refusalBytes = [Collections.Generic.List[byte[]]]::new()
    $refusalBytes.Add([byte[]] (@(0xEF, 0xBB, 0xBF) + $utf8.GetBytes($canonical + "`n")))
    $refusalBytes.Add([byte[]] @(0xFF, 0x0A))
    $refusalBytes.Add($utf8.GetBytes($canonical))
    $refusalBytes.Add($utf8.GetBytes($canonical + "`r"))
    $refusalBytes.Add($utf8.GetBytes($canonical + "`n`n"))
    $refusalBytes.Add([byte[]] @(0x0A))
    foreach ($bytes in $refusalBytes) {
        $source = Join-Path $testRoot ('canonical-refusal-' + [guid]::NewGuid().Guid + '.json')
        $destination = $source + '.out'
        [IO.File]::WriteAllBytes($source, [byte[]] $bytes)
        $refused = $false
        try { Copy-CanonicalRepositoryJson $source $destination } catch { $refused = $true }
        if (-not $refused -or (Test-Path -LiteralPath $destination)) { throw 'canonical repository JSON refusal differs' }
    }

    'cantor_evox2_scratch_build_harness_implementation_tests=passed isolated_successes=1 isolated_refusals=4 canonical_copy_successes=2 canonical_copy_refusals=6 commission_authority_checks=2 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { [IO.Directory]::Delete(('\\?\' + $testRoot), $true) }
}
