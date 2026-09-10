param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verifyRelative = 'scripts/verify_cantor_evox2_scratch_build_executor_p0_controller_evidence.ps1'
$verify = Join-Path $root $verifyRelative
& $verify -Root $root | Out-Null
$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-scratch-build-controller-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'controller test root escaped build parent' }
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $manifestRelative = 'experiments/evox2_scratch_build_executor_p0/controller_implementation_evidence_manifest.json'
    $manifestSource = Join-Path $root $manifestRelative
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($relative in @($manifestRelative) + @($manifest.artifacts | ForEach-Object { [string] $_.path })) {
        $destination = Join-Path $testRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $destination
    }
    $isolatedVerify = Join-Path $testRoot $verifyRelative
    & $isolatedVerify -Root $testRoot | Out-Null
    $module = 'crates/cantor_core/src/evox2_scratch_build_deployment_controller.rs'
    [IO.File]::AppendAllText((Join-Path $testRoot $module), "`n", [Text.UTF8Encoding]::new($false))
    $refused = $false; try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }; if (-not $refused) { throw 'controller module byte tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $module) -Destination (Join-Path $testRoot $module) -Force
    $plan = 'experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json'
    $raw = [IO.File]::ReadAllText((Join-Path $testRoot $plan)).Replace('operational_refusal_before_commission_no_receipt', 'receipt_fabricated___________________________')
    [IO.File]::WriteAllText((Join-Path $testRoot $plan), $raw, [Text.UTF8Encoding]::new($false))
    $refused = $false; try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }; if (-not $refused) { throw 'controller plan semantic tamper admitted' }
    Copy-Item -LiteralPath (Join-Path $root $plan) -Destination (Join-Path $testRoot $plan) -Force
    $manifestPath = Join-Path $testRoot $manifestRelative
    $changed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $changed.verification.remote_contact_authorized = $true
    [IO.File]::WriteAllText($manifestPath, ($changed | ConvertTo-Json -Depth 30 -Compress), [Text.UTF8Encoding]::new($false))
    $refused = $false; try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }; if (-not $refused) { throw 'controller authority promotion admitted' }
    Copy-Item -LiteralPath $manifestSource -Destination $manifestPath -Force
    Remove-Item -LiteralPath (Join-Path $testRoot 'narrative/research/Cantor_EVO_X2_Scratch_Build_Executor_P0_Deployment_Controller_Design_2026-09-10.sop') -Force
    $refused = $false; try { & $isolatedVerify -Root $testRoot | Out-Null } catch { $refused = $true }; if (-not $refused) { throw 'missing controller artifact admitted' }
    'cantor_evox2_scratch_build_controller_evidence_tests=passed isolated_successes=1 isolated_refusals=4 provider_requests=0 remote_calls=0 effects=0'
} finally {
    if (Test-Path -LiteralPath $testRoot) { [IO.Directory]::Delete(('\\?\' + $testRoot), $true) }
}
