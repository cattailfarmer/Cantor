[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$verify = Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_package.ps1'
$valid = & $verify -PackageRoot $PackageRoot | ConvertFrom-Json
if ($valid.status -cne 'verified') { throw 'real package did not verify' }

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-package-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe package test root' }
try {
    Copy-Item -LiteralPath $PackageRoot -Destination $testRoot -Recurse
    $binary = Join-Path $testRoot 'bin\cantor.exe'
    [IO.File]::AppendAllText($binary, 'x')
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'binary tamper was admitted' }
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'bin\cantor.exe') -Destination $binary -Force

    $extra = Join-Path $testRoot 'extra.bin'
    [IO.File]::WriteAllText($extra, 'extra', [Text.UTF8Encoding]::new($false))
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'extra file was admitted' }
    Remove-Item -LiteralPath $extra -Force

    $missing = Join-Path $testRoot 'evidence\a8\receipt.json'
    Remove-Item -LiteralPath $missing -Force
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'missing file was admitted' }

    [pscustomobject]@{
        profile = 'cantor-evox2-current-build-pilot-package-tests/0.1'
        status = 'passed'
        real_successes = 1
        isolated_refusals = 3
        manifest_sha256 = $valid.manifest_sha256
        artifact_count = $valid.artifact_count
    } | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
