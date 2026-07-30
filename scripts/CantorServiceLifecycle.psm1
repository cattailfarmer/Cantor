$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:SupervisorStateSchema = "cantor-service-supervisor-state/0.1"
$script:SupervisorHealthSchema = "cantor-service-supervisor-health/0.1"
$script:ExpectedStateProperties = @(
    "activation_sequence",
    "client_path",
    "config_path",
    "generation_id",
    "pid",
    "process_start_time_utc",
    "schema",
    "server_path",
    "started_at_utc",
    "stderr_log_path",
    "stdout_log_path"
)

function Resolve-CantorAbsoluteRegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "$ParameterName must be an absolute path"
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($fullPath)) {
        throw "$ParameterName must identify an existing regular file"
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer) {
        throw "$ParameterName must identify an existing regular file"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$ParameterName must not identify a reparse point"
    }
    return [IO.Path]::GetFullPath($item.FullName)
}

function Resolve-CantorAbsoluteStatePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$RequireExisting
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "StatePath must be an absolute path"
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ([IO.Directory]::Exists($fullPath)) {
        throw "StatePath must not identify a directory"
    }
    if ([IO.File]::Exists($fullPath)) {
        $item = Get-Item -LiteralPath $fullPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "StatePath must not identify a reparse point"
        }
    }
    if ($RequireExisting -and -not [IO.File]::Exists($fullPath)) {
        throw "StatePath does not identify an existing supervisor state file"
    }
    return $fullPath
}

function Assert-CantorDistinctPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($path in $Paths) {
        if (-not $seen.Add([IO.Path]::GetFullPath($path))) {
            throw "Lifecycle authority paths must be distinct"
        }
    }
}

function Enter-CantorSupervisorStartMutex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StatePath
    )

    $normalized = [IO.Path]::GetFullPath($StatePath).ToUpperInvariant()
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))
    }
    finally {
        $sha256.Dispose()
    }
    $name = "Local\CantorServiceStart_$(
        ([BitConverter]::ToString($digest)).Replace('-', '')
    )"
    $mutex = [Threading.Mutex]::new($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            throw "Another start operation already owns this StatePath"
        }
        return $mutex
    }
    catch {
        $mutex.Dispose()
        throw
    }
}

function Exit-CantorSupervisorStartMutex {
    param(
        [Parameter(Mandatory = $true)]
        [Threading.Mutex]$Mutex
    )

    try {
        $Mutex.ReleaseMutex()
    }
    finally {
        $Mutex.Dispose()
    }
}

function ConvertTo-CantorUtcText {
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$Value
    )

    return $Value.ToUniversalTime().ToString("o", [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-CantorUtcText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $styles = [Globalization.DateTimeStyles]::RoundtripKind
    $parsed = [DateTime]::MinValue
    if (
        -not [DateTime]::TryParseExact(
            $Value,
            "o",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed
        )
    ) {
        throw "$FieldName must be a round-trip UTC timestamp"
    }
    $canonical = ConvertTo-CantorUtcText -Value $parsed
    if (-not $Value.Equals($canonical, [StringComparison]::Ordinal)) {
        throw "$FieldName must be a canonical UTC timestamp"
    }
    return $parsed
}

function Read-CantorSupervisorState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StatePath
    )

    $stateFullPath = Resolve-CantorAbsoluteStatePath -Path $StatePath -RequireExisting
    $bytes = [IO.File]::ReadAllBytes($stateFullPath)
    if (
        $bytes.Length -ge 3 -and
        $bytes[0] -eq 0xef -and
        $bytes[1] -eq 0xbb -and
        $bytes[2] -eq 0xbf
    ) {
        throw "Supervisor state must be UTF-8 without a byte-order mark"
    }
    try {
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        $rawState = $strictUtf8.GetString($bytes)
        $state = $rawState | ConvertFrom-Json
    }
    catch {
        throw "StatePath does not contain strict UTF-8 supervisor JSON: $($_.Exception.Message)"
    }
    if ($null -eq $state -or $state -is [Array]) {
        throw "Supervisor state must be one JSON object"
    }
    $canonicalState = "$($state | ConvertTo-Json -Depth 5 -Compress)`n"
    if ($rawState -cne $canonicalState) {
        throw "Supervisor state is not exact canonical machine JSON"
    }

    $actualProperties = @($state.PSObject.Properties.Name | Sort-Object)
    if (
        $actualProperties.Count -ne $script:ExpectedStateProperties.Count -or
        [string]::Join("`n", $actualProperties) -cne
            [string]::Join("`n", $script:ExpectedStateProperties)
    ) {
        throw "Supervisor state has missing or unknown properties"
    }
    if ($state.schema -cne $script:SupervisorStateSchema) {
        throw "Supervisor state uses an unsupported schema"
    }

    $pidValue = [Int64]0
    if (-not [Int64]::TryParse([string]$state.pid, [ref]$pidValue) -or $pidValue -le 0) {
        throw "Supervisor state pid must be a positive integer"
    }
    $sequence = [UInt64]0
    if (
        -not [UInt64]::TryParse(
            [string]$state.activation_sequence,
            [ref]$sequence
        ) -or
        $sequence -eq 0
    ) {
        throw "Supervisor state activation_sequence must be a positive integer"
    }
    if (
        [string]$state.generation_id -notmatch
            '\A[0-9a-f]{64}\z'
    ) {
        throw "Supervisor state generation_id must be lowercase SHA-256"
    }

    ConvertFrom-CantorUtcText `
        -Value ([string]$state.process_start_time_utc) `
        -FieldName "process_start_time_utc" | Out-Null
    ConvertFrom-CantorUtcText `
        -Value ([string]$state.started_at_utc) `
        -FieldName "started_at_utc" | Out-Null

    foreach ($field in @(
        "server_path",
        "client_path",
        "config_path",
        "stdout_log_path",
        "stderr_log_path"
    )) {
        $value = [string]$state.$field
        if (
            [string]::IsNullOrWhiteSpace($value) -or
            -not [IO.Path]::IsPathRooted($value) -or
            [IO.Path]::GetFullPath($value) -cne $value
        ) {
            throw "Supervisor state $field must be a canonical absolute path"
        }
    }

    Assert-CantorDistinctPaths -Paths @(
        [string]$state.server_path,
        [string]$state.client_path,
        [string]$state.config_path,
        $stateFullPath,
        [string]$state.stdout_log_path,
        [string]$state.stderr_log_path
    )
    return $state
}

function Get-CantorProcessIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [Int64]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedServerPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedStartTimeUtc
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return [pscustomobject][ordered]@{
            matches = $false
            reason = "process_not_found"
            process = $null
        }
    }
    try {
        $actualPath = [IO.Path]::GetFullPath($process.Path)
        $actualStartTime = ConvertTo-CantorUtcText -Value $process.StartTime
    }
    catch {
        return [pscustomobject][ordered]@{
            matches = $false
            reason = "process_identity_unavailable"
            process = $process
        }
    }
    if (-not $actualPath.Equals($ExpectedServerPath, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject][ordered]@{
            matches = $false
            reason = "process_executable_mismatch"
            process = $process
        }
    }
    if (-not $actualStartTime.Equals($ExpectedStartTimeUtc, [StringComparison]::Ordinal)) {
        return [pscustomobject][ordered]@{
            matches = $false
            reason = "process_start_time_mismatch"
            process = $process
        }
    }
    return [pscustomobject][ordered]@{
        matches = $true
        reason = "complete_identity_match"
        process = $process
    }
}

function Assert-CantorStateProcessIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $identity = Get-CantorProcessIdentity `
        -ProcessId ([Int64]$State.pid) `
        -ExpectedServerPath ([string]$State.server_path) `
        -ExpectedStartTimeUtc ([string]$State.process_start_time_utc)
    if (-not $identity.matches) {
        throw "Supervisor process identity rejected: $($identity.reason)"
    }
    return $identity.process
}

function ConvertTo-CantorNativeArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"')) {
            throw "Native process argument contains an unsupported quote character"
        }
        '"' + $argument + '"'
    }
    return [string]::Join(" ", $quoted)
}

function Invoke-CantorCtl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [UInt32]$TimeoutMilliseconds = 70000
    )

    $clientFullPath = Resolve-CantorAbsoluteRegularFile `
        -Path $ClientPath `
        -ParameterName "ClientPath"
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $clientFullPath
    $startInfo.Arguments = ConvertTo-CantorNativeArguments -Arguments $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "cantorctl did not start"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit([int]$TimeoutMilliseconds)) {
            $process.Kill()
            $process.WaitForExit()
            throw "cantorctl exceeded its bounded execution timeout"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    $response = $null
    try {
        $response = $stdout | ConvertFrom-Json
    }
    catch {
        throw "cantorctl returned invalid machine JSON (exit $exitCode)"
    }
    if ($null -eq $response -or $response -is [Array]) {
        throw "cantorctl returned a non-object response"
    }
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        response = $response
        stderr = $stderr.Trim()
    }
}

function Assert-CantorSuccessfulStatus {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Invocation
    )

    $response = $Invocation.response
    if (
        $Invocation.exit_code -ne 0 -or
        $response.protocol_version -cne "cantor-service-protocol/0.1" -or
        $response.disposition -cne "success" -or
        $null -eq $response.result -or
        $response.result.kind -cne "status" -or
        $null -eq $response.result.status -or
        @($response.faults).Count -ne 0
    ) {
        $faultCode = if (@($response.faults).Count -gt 0) {
            [string]$response.faults[0].code
        }
        else {
            "invalid_status_response"
        }
        throw "Authenticated Cantor status failed: $faultCode"
    }
    $binding = $response.result.status.active_binding
    if (
        $null -eq $binding -or
        [string]$binding.generation_id.algorithm -cne "sha256" -or
        [string]$binding.generation_id.value -notmatch '\A[0-9a-f]{64}\z' -or
        [UInt64]$binding.activation_sequence -eq 0
    ) {
        throw "Authenticated Cantor status returned an invalid active binding"
    }
    return $response
}

function Write-CantorAtomicUtf8 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $temporary = "$Path.tmp-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText(
            $temporary,
            $Text,
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporary -Destination $Path
    }
    finally {
        if ([IO.File]::Exists($temporary)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function New-CantorSupervisorHealth {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [psobject]$StatusResponse
    )

    $status = $StatusResponse.result.status
    return [ordered]@{
        schema = $script:SupervisorHealthSchema
        state = "active"
        pid = [Int64]$State.pid
        process_start_time_utc = [string]$State.process_start_time_utc
        server_path = [string]$State.server_path
        client_path = [string]$State.client_path
        config_path = [string]$State.config_path
        stdout_log_path = [string]$State.stdout_log_path
        stderr_log_path = [string]$State.stderr_log_path
        started_at_utc = [string]$State.started_at_utc
        started_generation_id = [string]$State.generation_id
        started_activation_sequence = [UInt64]$State.activation_sequence
        service_profile = [string]$status.service_profile
        current_generation_id = [string]$status.active_binding.generation_id.value
        current_activation_sequence = [UInt64]$status.active_binding.activation_sequence
        uptime_milliseconds = [UInt64]$status.uptime_milliseconds
        checked_at_utc = ConvertTo-CantorUtcText -Value ([DateTime]::UtcNow)
    }
}

Export-ModuleMember -Function @(
    "Assert-CantorDistinctPaths",
    "Assert-CantorStateProcessIdentity",
    "Assert-CantorSuccessfulStatus",
    "ConvertTo-CantorUtcText",
    "Enter-CantorSupervisorStartMutex",
    "Exit-CantorSupervisorStartMutex",
    "Get-CantorProcessIdentity",
    "Invoke-CantorCtl",
    "New-CantorSupervisorHealth",
    "Read-CantorSupervisorState",
    "Resolve-CantorAbsoluteRegularFile",
    "Resolve-CantorAbsoluteStatePath",
    "Write-CantorAtomicUtf8"
)
