param(
    [Parameter(Mandatory = $true)]
    [string]$ServerPath,

    [Parameter(Mandatory = $true)]
    [string]$ClientPath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$StatePath,

    [ValidateRange(100, 120000)]
    [UInt32]$ReadinessTimeoutMilliseconds = 15000,

    [ValidateRange(10, 5000)]
    [UInt32]$ProbeIntervalMilliseconds = 100,

    [switch]$ReplaceStale
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "CantorServiceLifecycle.psm1") -Force

$serverFullPath = Resolve-CantorAbsoluteRegularFile `
    -Path $ServerPath `
    -ParameterName "ServerPath"
$clientFullPath = Resolve-CantorAbsoluteRegularFile `
    -Path $ClientPath `
    -ParameterName "ClientPath"
$configFullPath = Resolve-CantorAbsoluteRegularFile `
    -Path $ConfigPath `
    -ParameterName "ConfigPath"
$stateFullPath = Resolve-CantorAbsoluteStatePath -Path $StatePath
Assert-CantorDistinctPaths -Paths @(
    $serverFullPath,
    $clientFullPath,
    $configFullPath,
    $stateFullPath
)

$stateDirectory = [IO.Path]::GetDirectoryName($stateFullPath)
if ([string]::IsNullOrWhiteSpace($stateDirectory)) {
    throw "StatePath must have an absolute parent directory"
}
[IO.Directory]::CreateDirectory($stateDirectory) | Out-Null

if ([IO.File]::Exists($stateFullPath)) {
    $priorState = Read-CantorSupervisorState -StatePath $stateFullPath
    $priorIdentity = Get-CantorProcessIdentity `
        -ProcessId ([Int64]$priorState.pid) `
        -ExpectedServerPath ([string]$priorState.server_path) `
        -ExpectedStartTimeUtc ([string]$priorState.process_start_time_utc)
    if ($priorIdentity.matches) {
        throw "A live matching Cantor service already owns StatePath"
    }
    if (-not $ReplaceStale) {
        throw "StatePath is stale ($($priorIdentity.reason)); use -ReplaceStale only after review"
    }
    Remove-Item -LiteralPath $stateFullPath -Force
}

$logIdentity = "{0}-{1}" -f (
    [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffffffZ")
), ([guid]::NewGuid().ToString("N"))
$stdoutLogPath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($stateDirectory, "cantord-$logIdentity.stdout.log")
)
$stderrLogPath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($stateDirectory, "cantord-$logIdentity.stderr.log")
)
Assert-CantorDistinctPaths -Paths @(
    $serverFullPath,
    $clientFullPath,
    $configFullPath,
    $stateFullPath,
    $stdoutLogPath,
    $stderrLogPath
)

$process = $null
$processStartTime = $null
$published = $false
$outputJson = $null
try {
    $process = Start-Process `
        -FilePath $serverFullPath `
        -ArgumentList @("--config", "`"$configFullPath`"") `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLogPath `
        -RedirectStandardError $stderrLogPath `
        -PassThru
    $process.Refresh()
    $processStartTime = ConvertTo-CantorUtcText -Value $process.StartTime

    $deadline = [DateTime]::UtcNow.AddMilliseconds($ReadinessTimeoutMilliseconds)
    $attempt = 0
    $statusResponse = $null
    $lastReadinessFault = "no readiness probe completed"
    while ([DateTime]::UtcNow -lt $deadline) {
        $attempt += 1
        $process.Refresh()
        if ($process.HasExited) {
            throw "cantord exited before authenticated readiness (exit $($process.ExitCode))"
        }
        try {
            $invocation = Invoke-CantorCtl `
                -ClientPath $clientFullPath `
                -Arguments @(
                    "status",
                    "--config",
                    $configFullPath,
                    "--request-id",
                    "request:supervisor_start_$($process.Id)_$attempt"
                )
            $statusResponse = Assert-CantorSuccessfulStatus -Invocation $invocation
            break
        }
        catch {
            $lastReadinessFault = $_.Exception.Message
            $statusResponse = $null
        }
        Start-Sleep -Milliseconds $ProbeIntervalMilliseconds
    }
    if ($null -eq $statusResponse) {
        throw "cantord did not pass authenticated readiness within the bounded timeout: $lastReadinessFault"
    }

    $identity = Get-CantorProcessIdentity `
        -ProcessId $process.Id `
        -ExpectedServerPath $serverFullPath `
        -ExpectedStartTimeUtc $processStartTime
    if (-not $identity.matches) {
        throw "New cantord process identity changed before state publication: $($identity.reason)"
    }
    $binding = $statusResponse.result.status.active_binding
    $state = [ordered]@{
        schema = "cantor-service-supervisor-state/0.1"
        pid = [Int64]$process.Id
        process_start_time_utc = $processStartTime
        server_path = $serverFullPath
        client_path = $clientFullPath
        config_path = $configFullPath
        stdout_log_path = $stdoutLogPath
        stderr_log_path = $stderrLogPath
        generation_id = [string]$binding.generation_id.value
        activation_sequence = [UInt64]$binding.activation_sequence
        started_at_utc = ConvertTo-CantorUtcText -Value ([DateTime]::UtcNow)
    }
    Write-CantorAtomicUtf8 `
        -Path $stateFullPath `
        -Text "$($state | ConvertTo-Json -Depth 5 -Compress)`n"
    $published = $true
    $health = New-CantorSupervisorHealth `
        -State ([pscustomobject]$state) `
        -StatusResponse $statusResponse
    $outputJson = $health | ConvertTo-Json -Depth 5
}
finally {
    if (-not $published -and $null -ne $process -and $null -ne $processStartTime) {
        $identity = Get-CantorProcessIdentity `
            -ProcessId $process.Id `
            -ExpectedServerPath $serverFullPath `
            -ExpectedStartTimeUtc $processStartTime
        if ($identity.matches) {
            Stop-Process -Id $process.Id
            $process.WaitForExit(5000) | Out-Null
        }
    }
}
if ([string]::IsNullOrWhiteSpace($outputJson)) {
    throw "Supervisor failed to construct its machine-readable start result"
}
[Console]::Out.WriteLine($outputJson)
