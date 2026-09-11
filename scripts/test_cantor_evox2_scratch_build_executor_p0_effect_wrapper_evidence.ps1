[CmdletBinding()]
param([string] $Root = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$verifyRelative = 'scripts/verify_cantor_evox2_scratch_build_executor_p0_effect_wrapper_evidence.ps1'
$verify = Join-Path $rootPath $verifyRelative
& $verify -Root $rootPath | Out-Null
$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-scratch-build-effect-wrapper-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'effect-wrapper test root escaped build parent' }
function Set-ManifestIdentity([string] $Relative) {
    $manifestPath = Join-Path $testRoot 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_implementation_evidence_manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $artifact = @($manifest.artifacts | Where-Object { $_.path -ceq $Relative })
    if ($artifact.Count -ne 1) { throw 'effect-wrapper test manifest coordinate differs' }
    $path = Join-Path $testRoot $Relative
    $item = Get-Item -LiteralPath $path -Force
    $artifact[0].bytes = [int64] $item.Length
    $artifact[0].sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}
function Assert-Refusal {
    $refused = $false
    try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'effect-wrapper adversary was admitted' }
}
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $manifestRelative = 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_implementation_evidence_manifest.json'
    $manifestSource = Join-Path $rootPath $manifestRelative
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($relative in @($manifestRelative) + @($manifest.artifacts | ForEach-Object { [string] $_.path })) {
        $destination = Join-Path $testRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $rootPath $relative) -Destination $destination
    }
    $isolatedVerify = Join-Path $testRoot $verifyRelative
    & $isolatedVerify -Root $testRoot | Out-Null

    $module = 'crates/cantor_core/src/evox2_scratch_build_deployment_effect.rs'
    [IO.File]::AppendAllText((Join-Path $testRoot $module), "`n", [Text.UTF8Encoding]::new($false))
    Assert-Refusal
    Copy-Item -LiteralPath (Join-Path $rootPath $module) -Destination (Join-Path $testRoot $module) -Force

    $program = 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json'
    $programPath = Join-Path $testRoot $program
    [IO.File]::WriteAllText($programPath, ([IO.File]::ReadAllText($programPath).Replace('"execution_authorized":false', '"execution_authorized":true')), [Text.UTF8Encoding]::new($false))
    Set-ManifestIdentity $program
    Assert-Refusal
    Copy-Item -LiteralPath (Join-Path $rootPath $program) -Destination $programPath -Force

    $verification = 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/refusal_verification.json'
    $verificationPath = Join-Path $testRoot $verification
    [IO.File]::WriteAllText($verificationPath, ([IO.File]::ReadAllText($verificationPath).Replace('"effects":0', '"effects":1')), [Text.UTF8Encoding]::new($false))
    Set-ManifestIdentity $verification
    Assert-Refusal
    Copy-Item -LiteralPath (Join-Path $rootPath $verification) -Destination $verificationPath -Force

    $preflight = 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/preflight_refusal.json'
    $preflightPath = Join-Path $testRoot $preflight
    [IO.File]::AppendAllText($preflightPath, "`n", [Text.UTF8Encoding]::new($false))
    Set-ManifestIdentity $preflight
    Assert-Refusal
    Copy-Item -LiteralPath (Join-Path $rootPath $preflight) -Destination $preflightPath -Force

    Remove-Item -LiteralPath (Join-Path $testRoot 'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Effect_Wrapper_Design_2026-09-10.sop') -Force
    Assert-Refusal
    'cantor_evox2_scratch_build_effect_wrapper_evidence_tests=passed isolated_successes=1 isolated_refusals=5 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { [IO.Directory]::Delete(('\\?\' + $testRoot), $true) }
}
