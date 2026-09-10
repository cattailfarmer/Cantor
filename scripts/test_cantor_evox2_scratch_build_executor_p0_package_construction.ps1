param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$package = 'D:\CantorBuilds\evox2-scratch-build-executor-p0-package-56c5e1da'
$verify = Join-Path $root 'scripts\verify_cantor_evox2_scratch_build_executor_p0_package_construction.ps1'
& $verify -Root $root -PackageRoot $package | Out-Null

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-scratch-build-package-verification-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'package adversary root escaped build parent' }
try {
    Copy-Item -LiteralPath $package -Destination $testRoot -Recurse
    & $verify -Root $root -PackageRoot $testRoot -AllowCopiedPackage | Out-Null

    $harness = 'scripts\invoke-cantor-evox2-scratch-build-once.ps1'
    [IO.File]::AppendAllText((Join-Path $testRoot $harness), "`n", [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verify -Root $root -PackageRoot $testRoot -AllowCopiedPackage | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'package artifact raw-byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $package $harness) -Destination (Join-Path $testRoot $harness) -Force

    [IO.File]::AppendAllText((Join-Path $testRoot 'implementation_manifest.json'), "`n", [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verify -Root $root -PackageRoot $testRoot -AllowCopiedPackage | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'package manifest raw-byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $package 'implementation_manifest.json') -Destination (Join-Path $testRoot 'implementation_manifest.json') -Force

    [IO.File]::WriteAllText((Join-Path $testRoot 'unexpected.bin'), 'x', [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verify -Root $root -PackageRoot $testRoot -AllowCopiedPackage | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'unexpected package member admitted' }
    [IO.File]::Delete((Join-Path $testRoot 'unexpected.bin'))

    [IO.File]::Delete((Join-Path $testRoot 'command_set.json'))
    $refused = $false
    try { & $verify -Root $root -PackageRoot $testRoot -AllowCopiedPackage | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing package member admitted' }

    'cantor_evox2_scratch_build_package_construction_tests=passed isolated_successes=1 isolated_refusals=4 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { [IO.Directory]::Delete(('\\?\' + $testRoot), $true) }
}
