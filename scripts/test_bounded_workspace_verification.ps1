[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$subject = Join-Path $PSScriptRoot 'invoke_bounded_workspace_verification.ps1'
$pwsh = (Get-Process -Id $PID).Path

function Invoke-Subject {
    param([string[]]$Arguments)

    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $pwsh -NoLogo -NoProfile -File $subject @Arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorPreference
    }
    [pscustomobject]@{ Code = $code; Output = $output.Trim() }
}

[void][scriptblock]::Create((Get-Content -LiteralPath $subject -Raw))

$default = Invoke-Subject @()
if ($default.Code -ne 0) {
    throw "default plan failed: $($default.Output)"
}
$defaultPlan = $default.Output | ConvertFrom-Json
$decodedDefaultCommand = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($defaultPlan.bash_transport_payload)
)
if ($defaultPlan.profile -ne 'cantor-bounded-workspace-verification/0.2' -or
    $defaultPlan.action -ne 'test' -or
    $defaultPlan.execute -ne $false -or
    $defaultPlan.target_dir -ne '/home/pinky/.cache/cantor-workspace-verification' -or
    $defaultPlan.minimum_free_gib -ne 40 -or
    $defaultPlan.reserve_free_gib -ne 8 -or
    $defaultPlan.monitor_interval_seconds -ne 2 -or
    $defaultPlan.windows_volume_mount -ne '/mnt/c' -or
    $defaultPlan.capacity_sufficient -ne ($defaultPlan.free_bytes -ge $defaultPlan.minimum_free_bytes) -or
    $defaultPlan.cargo_build_jobs -ne 1 -or
    $defaultPlan.test_threads -ne 1 -or
    $defaultPlan.cargo_incremental -ne 0 -or
    $defaultPlan.cargo_profile_test_debug -ne 0 -or
    $defaultPlan.cargo_profile_dev_debug -ne 0 -or
    $defaultPlan.capacity_guard_exit_code -ne 73 -or
    $defaultPlan.capacity_monitor_exit_code -ne 74 -or
    $defaultPlan.bash_transport_encoding -ne 'utf8-base64' -or
    $decodedDefaultCommand -ne $defaultPlan.bash_command -or
    $defaultPlan.bash_transport_command -match '\$' -or
    $defaultPlan.bash_transport_command -notmatch [regex]::Escape($defaultPlan.bash_transport_payload) -or
    $defaultPlan.remote_hosts.Count -ne 0 -or
    $defaultPlan.destructive_actions.Count -ne 0 -or
    $defaultPlan.automatic_cleanup -ne $false) {
    throw 'default plan violates the closed contract'
}

$clippy = Invoke-Subject @('-Action', 'clippy')
if ($clippy.Code -ne 0) {
    throw "clippy plan failed: $($clippy.Output)"
}
$clippyPlan = $clippy.Output | ConvertFrom-Json
if ($clippyPlan.bash_command -notmatch 'RUSTFLAGS=' -or
    $clippyPlan.bash_command -notmatch 'CARGO_INCREMENTAL=0' -or
    $clippyPlan.bash_command -notmatch 'CARGO_PROFILE_TEST_DEBUG=0' -or
    $clippyPlan.bash_command -notmatch 'CARGO_PROFILE_DEV_DEBUG=0' -or
    $clippyPlan.bash_command -notmatch "df -PB1 '/mnt/c'" -or
    $clippyPlan.bash_command -notmatch 'kill -INT' -or
    $clippyPlan.bash_command -notmatch 'return 73' -or
    $clippyPlan.bash_command -notmatch 'return 74' -or
    $clippyPlan.bash_command -notmatch 'run_with_capacity_guard cargo clippy --workspace --all-targets --all-features --locked --quiet') {
    throw 'clippy plan omitted its exact bounded command'
}

$capacity = Invoke-Subject @('-MinimumFreeGiB', '1048576')
if ($capacity.Code -ne 0) {
    throw "impossible capacity plan failed: $($capacity.Output)"
}
$capacityPlan = $capacity.Output | ConvertFrom-Json
if ($capacityPlan.capacity_sufficient -ne $false -or $capacityPlan.execute -ne $false) {
    throw 'impossible capacity plan did not remain diagnostic and non-executing'
}

$capacityExecute = Invoke-Subject @('-MinimumFreeGiB', '1048576', '-Execute')
if ($capacityExecute.Code -eq 0 -or $capacityExecute.Output -notmatch 'capacity_fault') {
    throw 'impossible capacity execution did not fail before WSL admission'
}

$badThresholdRelation = Invoke-Subject @('-MinimumFreeGiB', '8', '-ReserveFreeGiB', '8')
if ($badThresholdRelation.Code -eq 0 -or
    $badThresholdRelation.Output -notmatch 'strictly greater') {
    throw 'startup and reserve threshold relation did not fail closed'
}

$badMonitor = Invoke-Subject @('-MonitorIntervalSeconds', '11')
if ($badMonitor.Code -eq 0) {
    throw 'invalid monitor interval did not fail parameter admission'
}

$badAction = Invoke-Subject @('-Action', 'deploy')
if ($badAction.Code -eq 0) {
    throw 'unknown action did not fail parameter admission'
}

$badTarget = Invoke-Subject @('-TargetDir', '/home/pinky/../escape')
if ($badTarget.Code -eq 0 -or $badTarget.Output -notmatch 'TargetDir') {
    throw 'parent-traversing target did not fail admission'
}

Write-Output 'bounded_workspace_verification_tests=passed cases=8'
