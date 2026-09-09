[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $PackageRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$verify = Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_package.ps1'
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
& $verify -PackageRoot $package | Out-Null

$compiler = Join-Path $package 'bin/cantor-evox2-plan-only-build-job.exe'
$verifier = Join-Path $package 'bin/cantor-evox2-plan-only-build-job-verify.exe'
Push-Location -LiteralPath $package
try {
    $first = & $compiler request.json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'first compiler process failed' }
    $second = & $compiler request.json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $first -cne $second) { throw 'compiler process determinism failed' }
    $plan = $first.TrimEnd("`r", "`n")
    [IO.File]::WriteAllText((Join-Path $package 'plan-1.json'), $plan, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $package 'plan-2.json'), $plan, [Text.UTF8Encoding]::new($false))
    $verification1 = & $verifier request.json plan-1.json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'first verifier process failed' }
    $verification2 = & $verifier request.json plan-2.json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'second verifier process failed' }
    $v1 = $verification1 | ConvertFrom-Json
    $v2 = $verification2 | ConvertFrom-Json
    if ($v1.status -cne 'passed' -or $v2.status -cne 'passed' -or $v1.plan_sha256 -cne $v2.plan_sha256 -or [int64] $v1.authority_grant_count -ne 0 -or [int64] $v1.effects -ne 0) { throw 'verification result mismatch' }
} finally {
    Remove-Item -LiteralPath (Join-Path $package 'plan-1.json'), (Join-Path $package 'plan-2.json') -Force -ErrorAction SilentlyContinue
    Pop-Location
}

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-plan-only-package-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
try {
    Copy-Item -LiteralPath $package -Destination $testRoot -Recurse
    $tamper = Join-Path $testRoot 'request.json'
    [IO.File]::AppendAllText($tamper, [Environment]::NewLine)
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'raw request tamper admitted' }

    Remove-Item -LiteralPath $testRoot -Recurse -Force
    Copy-Item -LiteralPath $package -Destination $testRoot -Recurse
    $manifestPath = Join-Path $testRoot 'deployment_manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.authority_grants = @('process_execute')
    $manifest | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $manifestPath -NoNewline
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'authority grant admitted' }

    Remove-Item -LiteralPath $testRoot -Recurse -Force
    Copy-Item -LiteralPath $package -Destination $testRoot -Recurse
    $extra = Join-Path $testRoot 'extra.bin'
    [IO.File]::WriteAllBytes($extra, [byte[]] @(1))
    $refused = $false
    try { & $verify -PackageRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'extra package file admitted' }
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}

'cantor_evox2_plan_only_build_job_p0_package_tests=passed compiler_processes=2 verifier_processes=2 isolated_refusals=3 effects=0'
