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
if ($defaultPlan.profile -ne 'cantor-bounded-workspace-verification/0.1' -or
    $defaultPlan.action -ne 'test' -or
    $defaultPlan.execute -ne $false -or
    $defaultPlan.target_dir -ne '/home/pinky/.cache/cantor-workspace-verification' -or
    $defaultPlan.cargo_build_jobs -ne 1 -or
    $defaultPlan.test_threads -ne 1 -or
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
    $clippyPlan.bash_command -notmatch 'cargo clippy --workspace --all-targets --all-features --locked --quiet') {
    throw 'clippy plan omitted its exact bounded command'
}

$capacity = Invoke-Subject @('-MinimumFreeGiB', '1048576')
if ($capacity.Code -eq 0 -or $capacity.Output -notmatch 'capacity_fault') {
    throw 'impossible capacity threshold did not fail closed'
}

$badAction = Invoke-Subject @('-Action', 'deploy')
if ($badAction.Code -eq 0) {
    throw 'unknown action did not fail parameter admission'
}

$badTarget = Invoke-Subject @('-TargetDir', '/home/pinky/../escape')
if ($badTarget.Code -eq 0 -or $badTarget.Output -notmatch 'TargetDir') {
    throw 'parent-traversing target did not fail admission'
}

Write-Output 'bounded_workspace_verification_tests=passed cases=5'
