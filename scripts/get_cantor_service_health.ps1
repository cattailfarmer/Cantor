param(
    [Parameter(Mandatory = $true)]
    [string]$StatePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "CantorServiceLifecycle.psm1") -Force

$stateFullPath = Resolve-CantorAbsoluteStatePath -Path $StatePath -RequireExisting
$state = Read-CantorSupervisorState -StatePath $stateFullPath
Assert-CantorStateProcessIdentity -State $state | Out-Null
Resolve-CantorAbsoluteRegularFile `
    -Path ([string]$state.client_path) `
    -ParameterName "state.client_path" | Out-Null
Resolve-CantorAbsoluteRegularFile `
    -Path ([string]$state.config_path) `
    -ParameterName "state.config_path" | Out-Null

$invocation = Invoke-CantorCtl `
    -ClientPath ([string]$state.client_path) `
    -Arguments @(
        "status",
        "--config",
        [string]$state.config_path,
        "--request-id",
        "request:supervisor_health_$($state.pid)"
    )
$statusResponse = Assert-CantorSuccessfulStatus -Invocation $invocation
New-CantorSupervisorHealth -State $state -StatusResponse $statusResponse |
    ConvertTo-Json -Depth 5
