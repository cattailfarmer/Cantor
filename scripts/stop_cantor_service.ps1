param(
    [Parameter(Mandatory = $true)]
    [string]$StatePath,

    [ValidateRange(100, 120000)]
    [UInt32]$ExitTimeoutMilliseconds = 15000
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "CantorServiceLifecycle.psm1") -Force

$stateFullPath = Resolve-CantorAbsoluteStatePath -Path $StatePath -RequireExisting
$state = Read-CantorSupervisorState -StatePath $stateFullPath
$process = Assert-CantorStateProcessIdentity -State $state
Resolve-CantorAbsoluteRegularFile `
    -Path ([string]$state.client_path) `
    -ParameterName "state.client_path" | Out-Null
Resolve-CantorAbsoluteRegularFile `
    -Path ([string]$state.config_path) `
    -ParameterName "state.config_path" | Out-Null

$statusInvocation = Invoke-CantorCtl `
    -ClientPath ([string]$state.client_path) `
    -Arguments @(
        "status",
        "--config",
        [string]$state.config_path,
        "--request-id",
        "request:supervisor_pre_shutdown_$($state.pid)"
    )
$statusResponse = Assert-CantorSuccessfulStatus -Invocation $statusInvocation
$generation = [string]$statusResponse.result.status.active_binding.generation_id.value

$shutdownInvocation = Invoke-CantorCtl `
    -ClientPath ([string]$state.client_path) `
    -Arguments @(
        "shutdown",
        "--config",
        [string]$state.config_path,
        "--request-id",
        "request:supervisor_shutdown_$($state.pid)",
        "--expected-generation",
        $generation
    )
$shutdownResponse = $shutdownInvocation.response
if (
    $shutdownInvocation.exit_code -ne 0 -or
    $shutdownResponse.protocol_version -cne "cantor-service-protocol/0.1" -or
    $shutdownResponse.disposition -cne "success" -or
    $null -eq $shutdownResponse.result -or
    $shutdownResponse.result.kind -cne "shutdown" -or
    @($shutdownResponse.faults).Count -ne 0
) {
    $faultCode = if (@($shutdownResponse.faults).Count -gt 0) {
        [string]$shutdownResponse.faults[0].code
    }
    else {
        "invalid_shutdown_response"
    }
    throw "Authenticated Cantor shutdown failed: $faultCode"
}
if (-not $process.WaitForExit([int]$ExitTimeoutMilliseconds)) {
    throw "cantord accepted shutdown but did not exit within the bounded timeout"
}

Remove-Item -LiteralPath $stateFullPath -Force
[ordered]@{
    schema = "cantor-service-supervisor-stop/0.1"
    state = "stopped"
    pid = [Int64]$state.pid
    generation_id = $generation
    exit_code = [Int32]$process.ExitCode
    state_removed = $true
    stopped_at_utc = ConvertTo-CantorUtcText -Value ([DateTime]::UtcNow)
} | ConvertTo-Json -Depth 5
