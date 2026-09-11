param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$verify = Join-Path $PSScriptRoot 'verify_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_formation.ps1'
& $verify -Root $root

$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = Join-Path $parent ('evox2-remote-preflight-activation-formation-' + [guid]::NewGuid().Guid)
$resolved = [IO.Path]::GetFullPath($testRoot)
if (-not $resolved.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $manifestRelative = 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_evidence_manifest.json'
    $manifestSource = Join-Path $root $manifestRelative
    $manifestDestination = Join-Path $testRoot $manifestRelative
    New-Item -ItemType Directory -Path (Split-Path -Parent $manifestDestination) -Force | Out-Null
    Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination
    $manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
    foreach ($artifact in $manifest.artifacts) {
        $destination = Join-Path $testRoot ([string]$artifact.path)
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root ([string]$artifact.path)) -Destination $destination
    }
    $scriptDestination = Join-Path $testRoot 'scripts/verify_cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_formation.ps1'
    New-Item -ItemType Directory -Path (Split-Path -Parent $scriptDestination) -Force | Out-Null
    Copy-Item -LiteralPath $verify -Destination $scriptDestination
    & $scriptDestination -Root $testRoot

    $refusals = 0
    $specRelative = 'specifications/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0.sop'
    $specDestination = Join-Path $testRoot $specRelative
    [IO.File]::AppendAllText($specDestination, [Environment]::NewLine)
    try { & $scriptDestination -Root $testRoot | Out-Null; throw 'raw-byte tamper admitted' } catch { if ($_.Exception.Message -eq 'raw-byte tamper admitted') { throw }; $refusals++ }
    Copy-Item -LiteralPath (Join-Path $root $specRelative) -Destination $specDestination -Force

    $mutations = @(
        @('work_slice_language_is_operator_decision', $true),
        @('permit_consumed_before_runner', $false),
        @('retry_count', 1),
        @('formation_permits_minted', 1),
        @('formation_runner_invocations', 1),
        @('synthetic_trials', 1),
        @('terminal_has_outgoing_edge', $true),
        @('live_invocation_authorized_by_formation', $true),
        @('runner_bookend_commit', ('0' * 40))
    )
    foreach ($mutation in $mutations) {
        Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination -Force
        $changed = Get-Content -LiteralPath $manifestDestination -Raw | ConvertFrom-Json
        $changed.verification.($mutation[0]) = $mutation[1]
        $json = $changed | ConvertTo-Json -Depth 8 -Compress
        [IO.File]::WriteAllText($manifestDestination, $json, [Text.UTF8Encoding]::new($false))
        try { & $scriptDestination -Root $testRoot | Out-Null; throw "semantic mutation admitted $($mutation[0])" } catch { if ($_.Exception.Message -like 'semantic mutation admitted*') { throw }; $refusals++ }
    }
    "cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_formation_tests=passed isolated_successes=1 isolated_refusals=$refusals"
} finally {
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
