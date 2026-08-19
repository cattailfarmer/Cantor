[CmdletBinding()]
param(
    [string] $SshHost = "evo-x2"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Assert-Exact {
    param(
        [Parameter(Mandatory = $true)] [bool] $Condition,
        [Parameter(Mandatory = $true)] [string] $Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

$expectedSha256 = "abf9c33976320297018bc90723c50ee779b746b129539daaf963e91f5eb40b52"
$expectedBytes = 2840064
$expectedProcessId = 12780
$expectedProcessCreationUtc = "2026-08-15T20:51:49.8374230Z"
$remoteScript = @'
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$root = "C:\AI\services\cantor-field-cycle"
$exe = Join-Path $root "cantor-field-cycle-p0-h8.exe"
$exeBefore = Get-Item -LiteralPath $exe
$exeSha256Before = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$process = Get-CimInstance Win32_Process -Filter "ProcessId=12780"
$listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8081 -ErrorAction SilentlyContinue)
$rootAcl = Get-Acl -LiteralPath $root
$exeAcl = Get-Acl -LiteralPath $exe
$fieldFiles = @(Get-ChildItem -LiteralPath $root -Filter "attention-cycle-*.json" -File)
$reportFiles = @(
    Get-ChildItem -LiteralPath $root -Recurse -Filter "*.json" -File |
        Where-Object { -not $_.Name.StartsWith("attention-cycle-", [StringComparison]::Ordinal) } |
        Sort-Object FullName
)
$assurance = @{}
$terminalStates = @{}
$failures = @()
$reportIdentities = @()
foreach ($file in $reportFiles) {
    $reportSha256Before = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $reportBytesBefore = $file.Length
    $raw = @(& $exe verify $file.FullName 2>&1)
    $exitCode = $LASTEXITCODE
    $reportAfter = Get-Item -LiteralPath $file.FullName
    $reportSha256After = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($reportSha256Before -cne $reportSha256After -or $reportBytesBefore -ne $reportAfter.Length) {
        $failures += [pscustomobject]@{
            path = $file.FullName.Substring($root.Length + 1).Replace("\", "/")
            exit_code = $exitCode
            reason = "report identity changed during replay"
        }
        continue
    }
    if ($exitCode -ne 0) {
        $failures += [pscustomobject]@{
            path = $file.FullName.Substring($root.Length + 1).Replace("\", "/")
            exit_code = $exitCode
            reason = "verifier returned nonzero"
        }
        continue
    }
    try {
        $verification = ($raw -join "`n") | ConvertFrom-Json
    } catch {
        $failures += [pscustomobject]@{
            path = $file.FullName.Substring($root.Length + 1).Replace("\", "/")
            exit_code = $exitCode
            reason = "verifier output was not JSON"
        }
        continue
    }
    $reportIdentities += [pscustomobject]@{
        path = $file.FullName.Substring($root.Length + 1).Replace("\", "/")
        sha256 = $reportSha256After
        bytes = $reportAfter.Length
    }
    $assuranceName = [string]$verification.assurance
    if (-not $assurance.ContainsKey($assuranceName)) { $assurance[$assuranceName] = 0 }
    $assurance[$assuranceName]++
    $terminalState = [string]$verification.terminal_state
    if (-not $terminalStates.ContainsKey($terminalState)) { $terminalStates[$terminalState] = 0 }
    $terminalStates[$terminalState]++
}
$exeAfter = Get-Item -LiteralPath $exe
$exeSha256After = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    computer = $env:COMPUTERNAME
    executable_sha256_before = $exeSha256Before
    executable_bytes_before = $exeBefore.Length
    executable_sha256_after = $exeSha256After
    executable_bytes_after = $exeAfter.Length
    field_file_count = $fieldFiles.Count
    report_count = $reportFiles.Count
    verified_count = $reportFiles.Count - $failures.Count
    assurance = $assurance
    terminal_states = $terminalStates
    failures = $failures
    report_identities = $reportIdentities
    llama_pid = if ($null -ne $process) { [int]$process.ProcessId } else { $null }
    llama_creation_utc = if ($null -ne $process) { $process.CreationDate.ToUniversalTime().ToString("o") } else { $null }
    listeners = @($listeners | ForEach-Object {
        [pscustomobject]@{
            address = $_.LocalAddress
            port = $_.LocalPort
            pid = $_.OwningProcess
        }
    })
    root_sddl = $rootAcl.Sddl
    executable_sddl = $exeAcl.Sddl
    executable_access = @($exeAcl.Access | ForEach-Object {
        [pscustomobject]@{
            identity = $_.IdentityReference.Value
            type = $_.AccessControlType.ToString()
            rights = $_.FileSystemRights.ToString()
            inherited = $_.IsInherited
        }
    })
} | ConvertTo-Json -Depth 8 -Compress
'@

$ssh = Get-Command ssh.exe -ErrorAction Stop
$priorPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $remoteLines = @($remoteScript | & $ssh.Source -T $SshHost powershell.exe -NoProfile -NonInteractive -OutputFormat Text -Command '$source=[Console]::In.ReadToEnd(); Invoke-Expression $source' 2>&1)
    $sshExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $priorPreference
}
Assert-Exact ($sshExit -eq 0) "EVO-X2 read-only deployment audit failed over SSH: $($remoteLines -join ' | ')"
$jsonLines = @($remoteLines | Where-Object {
    $line = $_.ToString().Trim()
    $line.StartsWith("{", [StringComparison]::Ordinal) -and $line.EndsWith("}", [StringComparison]::Ordinal)
})
Assert-Exact ($jsonLines.Count -eq 1) "EVO-X2 audit did not return exactly one JSON record: $($remoteLines -join ' | ')"
$remote = $jsonLines[0] | ConvertFrom-Json

Assert-Exact ($remote.computer -ceq "EVO-X2") "remote computer identity changed"
Assert-Exact ($remote.executable_sha256_before -ceq $expectedSha256) "deployed h8 pre-replay digest changed"
Assert-Exact ($remote.executable_bytes_before -eq $expectedBytes) "deployed h8 pre-replay byte count changed"
Assert-Exact ($remote.executable_sha256_after -ceq $expectedSha256) "deployed h8 post-replay digest changed"
Assert-Exact ($remote.executable_bytes_after -eq $expectedBytes) "deployed h8 post-replay byte count changed"
Assert-Exact ($remote.field_file_count -eq 4) "remote field fixture count changed"
Assert-Exact ($remote.report_count -eq 31) "remote report count changed"
Assert-Exact ($remote.verified_count -eq 31 -and @($remote.failures).Count -eq 0) "not every remote report reverified"

function Get-RemoteReportPath {
    param([Parameter(Mandatory = $true)] [string] $LocalPath)
    switch -CaseSensitive ($LocalPath) {
        "evox2_live_v1.json" { return "field-cycle-live-v1.json" }
        "evox2_live_v2.json" { return "field-cycle-live-v2.json" }
        "evox2_live_v3_fault.json" { return "field-cycle-live-v3.json" }
        "evox2_live_v4_fault.json" { return "field-cycle-live-v4.json" }
        "evox2_live_v5.json" { return "field-cycle-live-v5.json" }
        "evox2_control_v5.json" { return "field-cycle-control-v5.json" }
        "evox2_hostile_boundary_v5.json" { return "field-cycle-hostile-boundary-v5.json" }
        "evox2_forbidden_relation_v1.json" { return "field-cycle-forbidden-relation-h4.json" }
        "evox2_forbidden_relation_all_kinds_v1.json" { return "field-cycle-forbidden-relation-all-kinds-h4.json" }
        default { return $LocalPath }
    }
}

$localEvidenceRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0"
$expectedReports = @()
foreach ($file in @(Get-ChildItem -LiteralPath $localEvidenceRoot -Recurse -Filter "*.json" -File | Sort-Object FullName)) {
    try {
        $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    } catch {
        continue
    }
    if ($null -eq $report.PSObject.Properties["profile"] -or
        $report.profile -cne "cantor-field-attention-cycle/0.1" -or
        $report.provider.base_url -ceq "fixture://local") {
        continue
    }
    $localPath = $file.FullName.Substring($localEvidenceRoot.Length + 1).Replace("\", "/")
    $expectedReports += [pscustomobject]@{
        path = Get-RemoteReportPath -LocalPath $localPath
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = $file.Length
    }
}
Assert-Exact ($expectedReports.Count -eq 31) "local tracked provider report count changed"
$expectedPathCount = @($expectedReports | Select-Object -ExpandProperty path -Unique).Count
Assert-Exact ($expectedPathCount -eq $expectedReports.Count) "local-to-remote report path mapping is not one-to-one"
$observedReports = @($remote.report_identities)
Assert-Exact ($observedReports.Count -eq $expectedReports.Count) "remote report identity cardinality changed"
$observedByPath = @{}
foreach ($report in $observedReports) {
    Assert-Exact (-not $observedByPath.ContainsKey([string]$report.path)) "duplicate remote report identity"
    $observedByPath[[string]$report.path] = $report
}
foreach ($expected in $expectedReports) {
    Assert-Exact ($observedByPath.ContainsKey($expected.path)) "remote report is missing: $($expected.path)"
    $observed = $observedByPath[$expected.path]
    Assert-Exact ($observed.sha256 -ceq $expected.sha256) "remote report digest changed: $($expected.path)"
    Assert-Exact ($observed.bytes -eq $expected.bytes) "remote report byte count changed: $($expected.path)"
}
$orderedReportIdentity = @($expectedReports | Sort-Object path | ForEach-Object { "$($_.path) $($_.sha256) $($_.bytes)" }) -join "`n"
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $orderedReportSetSha256 = -join ($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($orderedReportIdentity)) | ForEach-Object { $_.ToString("x2") })
} finally {
    $sha256.Dispose()
}

Assert-Exact ($remote.assurance.stored_provider_replay -eq 29) "stored-provider assurance distribution changed"
Assert-Exact ($remote.assurance.response_backed_fault_replay -eq 2) "response-backed fault assurance distribution changed"
Assert-Exact ($remote.terminal_states.completed -eq 9) "completed report distribution changed"
Assert-Exact ($remote.terminal_states.rejected -eq 11) "rejected report distribution changed"
Assert-Exact ($remote.terminal_states.control_completed -eq 9) "control report distribution changed"
Assert-Exact ($remote.terminal_states.faulted -eq 2) "faulted report distribution changed"
Assert-Exact ($remote.llama_pid -eq $expectedProcessId) "llama.cpp PID changed"
$observedProcessCreationUtc = ([DateTime]$remote.llama_creation_utc).ToUniversalTime().ToString("o")
Assert-Exact ($observedProcessCreationUtc -ceq $expectedProcessCreationUtc) "llama.cpp process creation identity changed"
$listeners = @($remote.listeners)
Assert-Exact ($listeners.Count -eq 1) "llama.cpp listener count changed"
Assert-Exact ($listeners[0].address -ceq "127.0.0.1" -and $listeners[0].port -eq 8081 -and $listeners[0].pid -eq $expectedProcessId) "llama.cpp listener identity changed"

$authenticatedUsers = @($remote.executable_access | Where-Object {
    $_.identity -ceq "NT AUTHORITY\Authenticated Users" -and $_.type -ceq "Allow"
})
$authenticatedUsersModify = $authenticatedUsers.Count -eq 1 -and
    ([string]$authenticatedUsers[0].rights).Contains("Modify", [StringComparison]::Ordinal)

[pscustomobject]@{
    profile = "cantor-field-attention-evox2-deployment-audit/0.1"
    status = if ($authenticatedUsersModify) { "passed_with_open_acl_residual" } else { "passed" }
    host = $remote.computer
    verifier = [pscustomobject]@{
        sha256_before = $remote.executable_sha256_before
        bytes_before = $remote.executable_bytes_before
        sha256_after = $remote.executable_sha256_after
        bytes_after = $remote.executable_bytes_after
    }
    replay = [pscustomobject]@{
        report_count = $remote.report_count
        verified_count = $remote.verified_count
        terminal_states = $remote.terminal_states
        assurance = $remote.assurance
        ordered_file_set_sha256 = $orderedReportSetSha256
        all_remote_files_equal_tracked_local_bytes = $true
        provider_requests_made_by_audit = 0
    }
    provider = [pscustomobject]@{
        pid = $remote.llama_pid
        creation_utc = $observedProcessCreationUtc
        listener = $listeners[0]
        modified_or_restarted = $false
    }
    deployment_acl = [pscustomobject]@{
        root_sddl = $remote.root_sddl
        executable_sddl = $remote.executable_sddl
        authenticated_users_modify = $authenticatedUsersModify
        trust_interpretation = if ($authenticatedUsersModify) {
            "current bytes are observed exactly but the inherited deployment ACL is not a protected production trust root"
        } else {
            "no Authenticated Users Modify entry observed by this bounded audit"
        }
    }
    external_effects = "read-only SSH observation and report replay only"
} | ConvertTo-Json -Depth 8
