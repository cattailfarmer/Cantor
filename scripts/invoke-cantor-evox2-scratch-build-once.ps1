[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$servicePortable = 'C:/AI/services/cantor-scratch-build-4fdd29cb'
$service = 'C:\AI\services\cantor-scratch-build-4fdd29cb'
$workspacePortable = 'C:/AI/workspaces/cantor-build-4fdd29cb'
$workspace = 'C:\AI\workspaces\cantor-build-4fdd29cb'
$targetPortable = 'C:/AI/builds/cantor-build-4fdd29cb'
$target = 'C:\AI\builds\cantor-build-4fdd29cb'
$executorPortable = 'C:/AI/services/cantor-scratch-build-4fdd29cb/bin/cantor-evox2-scratch-build-executor.exe'
$executor = Join-Path $service 'bin\cantor-evox2-scratch-build-executor.exe'
$runner = Join-Path $service 'bin\cantor-evox2-scratch-build-operation-runner.exe'
$packageVerifier = Join-Path $service 'bin\cantor-evox2-scratch-build-package-verify.exe'
$commissionVerifier = Join-Path $service 'bin\cantor-evox2-scratch-build-commission-verify.exe'
$receiptVerifier = Join-Path $service 'bin\cantor-evox2-scratch-build-receipt-verify.exe'
$emptySha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
$maximumMachineBytes = 1048576
$minimumFreeBytes = [int64]103079215104
$maximumTotalMilliseconds = [int64]36000000
$runTimer = [Diagnostics.Stopwatch]::StartNew()

function Assert-DirectDirectory([string] $Path, [string] $Name) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Name must be an ordinary directory"
    }
}

function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

function Write-Utf8New([string] $Path, [string] $Text) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally {
        $stream.Dispose()
    }
}

function Get-DirectoryIdentity([string] $Root, [string] $PortableRoot) {
    Assert-DirectDirectory $Root 'protected root'
    $members = @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName)
    $rows = @()
    [int64] $aggregate = 0
    [int] $fileCount = 0
    foreach ($member in $members) {
        if ($member.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'protected root contains a reparse point' }
        $relative = $member.FullName.Substring($Root.Length + 1).Replace('\', '/')
        if ($member.PSIsContainer) {
            $rows += "d|$relative"
        } else {
            $hash = (Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $rows += "f|$relative|$($member.Length)|$hash"
            $aggregate += [int64] $member.Length
            $fileCount++
        }
    }
    [ordered]@{
        root = $PortableRoot
        file_count = $fileCount
        aggregate_bytes = $aggregate
        set_sha256 = Get-TextSha256 ($rows -join "`n")
    }
}

function Get-ProtectedState {
    @(
        (Get-DirectoryIdentity 'C:\AI\services\cantor-build-planner-d805681d' 'C:/AI/services/cantor-build-planner-d805681d'),
        (Get-DirectoryIdentity 'C:\AI\services\cantor-current-pilot-48479932' 'C:/AI/services/cantor-current-pilot-48479932'),
        (Get-DirectoryIdentity 'C:\AI\services\cantor-attention-mcp' 'C:/AI/services/cantor-attention-mcp'),
        (Get-DirectoryIdentity 'C:\AI\services\cantor-needle-runtime' 'C:/AI/services/cantor-needle-runtime'),
        (Get-DirectoryIdentity 'C:\AI\services\sop-agent' 'C:/AI/services/sop-agent')
    )
}

function Get-ProviderState {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8081 -ErrorAction Stop)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1') { throw 'loopback provider listener identity differs' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($listeners[0].OwningProcess)"
    if ($null -eq $process) { throw 'loopback provider process is absent' }
    $executableItem = Get-Item -LiteralPath $process.ExecutablePath -Force
    $modelPath = 'C:\AI\models\validation\Qwen3.5-0.8B-GGUF\Qwen3.5-0.8B-Q4_0.gguf'
    $modelItem = Get-Item -LiteralPath $modelPath -Force
    foreach ($item in @($executableItem, $modelItem)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'provider file boundary differs' }
    }
    [ordered]@{
        pid = [int] $process.ProcessId
        creation_utc = $process.CreationDate.ToUniversalTime().ToString('o')
        command_sha256 = Get-TextSha256 ([string] $process.CommandLine)
        executable_bytes = [int64] $executableItem.Length
        executable_sha256 = (Get-FileHash -LiteralPath $executableItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        model_bytes = [int64] $modelItem.Length
        model_sha256 = (Get-FileHash -LiteralPath $modelItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        listener = '127.0.0.1:8081'
    }
}

function Get-ExecutorProcessCount {
    @(Get-CimInstance Win32_Process | Where-Object {
        $null -ne $_.ExecutablePath -and $_.ExecutablePath.StartsWith($service + '\', [StringComparison]::OrdinalIgnoreCase)
    }).Count
}

function Invoke-JsonProcess([string] $File, [string[]] $Arguments, [string] $WorkingDirectory, [string] $Name) {
    if ($runTimer.ElapsedMilliseconds -ge $maximumTotalMilliseconds) { throw 'total execution duration bound reached' }
    Push-Location -LiteralPath $WorkingDirectory
    try {
        $lines = @(& $File @Arguments)
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($exitCode -ne 0) { throw "$Name process failed with exit code $exitCode" }
    $raw = (($lines | ForEach-Object { $_.ToString() }) -join "`n").TrimEnd("`r", "`n")
    if ($raw.Length -eq 0 -or [Text.Encoding]::UTF8.GetByteCount($raw) -gt $maximumMachineBytes) { throw "$Name output boundary differs" }
    try { return ($raw | ConvertFrom-Json) } catch { throw "$Name did not emit one JSON object" }
}

function Invoke-PackageVerification {
    $result = Invoke-JsonProcess $packageVerifier @('implementation_manifest.json', 'command_set.json', 'commission.json', 'deployment_envelope.json') $service 'package verification'
    if ($result.profile -cne 'cantor-evox2-scratch-build-package-verification/0.1' -or $result.status -cne 'passed' -or [int] $result.artifact_count -ne 21 -or [int] $result.package_file_count -ne 24 -or [int] $result.authority_grants -ne 5 -or [int] $result.effects -ne 0) {
        throw 'package verification semantics differ'
    }
    $result
}

function Invoke-Operation([int] $Ordinal, [string] $ExecutablePath, [string] $ExecutableSha256, [string] $WorkingDirectory) {
    $record = Invoke-JsonProcess $runner @('run', '--ordinal', [string] $Ordinal, '--executable-path', $ExecutablePath, '--executable-sha256', $ExecutableSha256) $WorkingDirectory "operation $Ordinal"
    if ([int] $record.ordinal -ne $Ordinal -or -not [bool] $record.admitted -or $record.evidence_sha256 -cne '') { throw "operation $Ordinal record differs" }
    $record
}

function New-UnobservedToolchain {
    [ordered]@{
        architecture = 'not_observed'
        cargo_path = 'not_observed'
        cargo_sha256 = $emptySha256
        cargo_version = 'not_observed'
        rustc_path = 'not_observed'
        rustc_sha256 = $emptySha256
        rustc_version = 'not_observed'
        linker_path = 'not_observed'
        linker_sha256 = $emptySha256
        offline_probe_status = 'not_observed_due_to_preflight_refusal'
        observation_sha256 = ''
    }
}

function New-ReceiptCandidate([string] $Disposition, [bool] $PhysicalBuildPerformed, $Toolchain, [array] $OperationRecords, [string] $ProtectedBeforeHash, [string] $ProtectedAfterHash, [string] $ProviderBeforeHash, [string] $ProviderAfterHash, [int] $PersistentProcessCount) {
    $commission = Get-Content -LiteralPath (Join-Path $service 'commission.json') -Raw | ConvertFrom-Json
    [ordered]@{
        profile = 'cantor-evox2-scratch-build-executor-receipt/0.1'
        receipt_uuid = [guid]::NewGuid().Guid.ToLowerInvariant()
        canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
        commission_uuid = [string] $commission.commission_uuid
        commission_sha256 = [string] $commission.commission_sha256
        source_archive_sha256 = '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d'
        source_commit = '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'
        target_host = 'EVO-X2'
        workspace_root = $workspacePortable
        target_root = $targetPortable
        toolchain_observation = $Toolchain
        operation_records = @($OperationRecords)
        protected_before = $ProtectedBeforeHash
        protected_after = $ProtectedAfterHash
        provider_before = $ProviderBeforeHash
        provider_after = $ProviderAfterHash
        persistent_executor_process_count = $PersistentProcessCount
        physical_build_performed = $PhysicalBuildPerformed
        disposition = $Disposition
        receipt_sha256 = ''
    }
}

function Invoke-CandidateSealer([string] $Candidate) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $executor
    $start.Arguments = 'seal-candidate --stdin'
    $start.WorkingDirectory = $service
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'receipt candidate sealer did not start' }
        $process.StandardInput.Write($Candidate)
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'receipt candidate sealer timed out' }
        $stdout = $stdoutTask.Result.TrimEnd("`r", "`n")
        $stderr = $stderrTask.Result
        if ($process.ExitCode -ne 0) { throw "receipt candidate sealer failed: $stderr" }
        if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt $maximumMachineBytes) { throw 'sealed receipt output exceeds bound' }
        return $stdout
    } finally {
        $process.Dispose()
    }
}

function Assert-Conservation($ProtectedBefore, $ProviderBefore) {
    $protectedAfter = Get-ProtectedState
    $providerAfter = Get-ProviderState
    $protectedBeforeRaw = $ProtectedBefore | ConvertTo-Json -Depth 20 -Compress
    $protectedAfterRaw = $protectedAfter | ConvertTo-Json -Depth 20 -Compress
    $providerBeforeRaw = $ProviderBefore | ConvertTo-Json -Depth 20 -Compress
    $providerAfterRaw = $providerAfter | ConvertTo-Json -Depth 20 -Compress
    $processCount = Get-ExecutorProcessCount
    if ($protectedBeforeRaw -cne $protectedAfterRaw -or $providerBeforeRaw -cne $providerAfterRaw -or $processCount -ne 0) { throw 'protected provider or process conservation differs' }
    [ordered]@{
        protected_after = $protectedAfter
        protected_after_sha256 = Get-TextSha256 $protectedAfterRaw
        provider_after = $providerAfter
        provider_after_sha256 = Get-TextSha256 $providerAfterRaw
        persistent_process_count = $processCount
    }
}

function Complete-StoppedReceipt([string] $Disposition, $Toolchain, [array] $Records, $Preflight, $ProtectedBefore, [string] $ProtectedBeforeHash, $ProviderBefore, [string] $ProviderBeforeHash) {
    $closure = Assert-Conservation $ProtectedBefore $ProviderBefore
    $candidateObject = New-ReceiptCandidate $Disposition $false $Toolchain $Records $ProtectedBeforeHash $closure.protected_after_sha256 $ProviderBeforeHash $closure.provider_after_sha256 $closure.persistent_process_count
    $candidate = $candidateObject | ConvertTo-Json -Depth 30 -Compress
    $receipt = Invoke-CandidateSealer $candidate
    if (Test-Path -LiteralPath $target) {
        $preflightPath = Join-Path $target 'preflight.json'
        if (-not (Test-Path -LiteralPath $preflightPath)) { Write-Utf8New $preflightPath ($Preflight | ConvertTo-Json -Depth 30 -Compress) }
        Write-Utf8New (Join-Path $target 'final_audit.json') ($closure | ConvertTo-Json -Depth 30 -Compress)
        Write-Utf8New (Join-Path $target 'receipt_candidate.json') $candidate
        Write-Utf8New (Join-Path $target 'receipt.json') $receipt
        Copy-Item -LiteralPath (Join-Path $service 'commission.json') -Destination (Join-Path $target 'commission.json')
        $verification = Invoke-JsonProcess $receiptVerifier @('commission.json', 'receipt.json') $target 'stopped receipt verification'
        Write-Utf8New (Join-Path $target 'receipt_verification.json') ($verification | ConvertTo-Json -Depth 20 -Compress)
    }
    [ordered]@{
        profile = 'cantor-evox2-scratch-build-host-run/0.1'
        status = $Disposition
        target_host = 'EVO-X2'
        operation_record_count = $Records.Count
        physical_build_performed = $false
        receipt = ($receipt | ConvertFrom-Json)
        total_duration_ms = [int64] $runTimer.ElapsedMilliseconds
        persistent_processes = 0
    } | ConvertTo-Json -Depth 40 -Compress
}

$resolvedService = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ($resolvedService.Replace('\', '/') -cne $servicePortable) { throw 'fixed service root differs' }
if ($env:COMPUTERNAME -cne 'EVO-X2') { throw 'target host differs' }
Assert-DirectDirectory $service 'service root'
Assert-DirectDirectory 'C:\AI\workspaces' 'workspace parent'
Assert-DirectDirectory 'C:\AI\builds' 'target parent'
foreach ($path in @($executor, $runner, $packageVerifier, $commissionVerifier, $receiptVerifier)) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'package executable boundary differs' }
}
if (Test-Path -LiteralPath $workspace) { throw 'workspace root collision' }
if (Test-Path -LiteralPath $target) { throw 'target or receipt root collision' }
if ((Get-PSDrive -Name C).Free -lt $minimumFreeBytes) { throw 'minimum free-space bound refused' }
$archive = Get-Item -LiteralPath (Join-Path $service 'source.tar') -Force
if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $archive.Length -gt 268435456 -or (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d') {
    throw 'source archive identity differs'
}
$package = Invoke-PackageVerification
$commissionVerification = Invoke-JsonProcess $commissionVerifier @('commission.json') $service 'commission verification'
if ($commissionVerification.status -cne 'passed' -or [int] $commissionVerification.authority_grant_count -ne 5 -or [int] $commissionVerification.authority_denial_count -ne 14 -or [int] $commissionVerification.effects -ne 0) { throw 'commission verification semantics differ' }
if ((Get-ExecutorProcessCount) -ne 0) { throw 'pre-existing executor process refused' }
$protectedBefore = Get-ProtectedState
$providerBefore = Get-ProviderState
$protectedBeforeRaw = $protectedBefore | ConvertTo-Json -Depth 20 -Compress
$providerBeforeRaw = $providerBefore | ConvertTo-Json -Depth 20 -Compress
$protectedBeforeHash = Get-TextSha256 $protectedBeforeRaw
$providerBeforeHash = Get-TextSha256 $providerBeforeRaw
$preflight = [ordered]@{
    profile = 'cantor-evox2-scratch-build-preflight/0.1'
    status = 'admitted'
    target_host = $env:COMPUTERNAME
    package_manifest_sha256 = [string] $package.implementation_manifest_sha256
    source_archive_sha256 = '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d'
    workspace_absent = $true
    target_absent = $true
    free_bytes = [int64] (Get-PSDrive -Name C).Free
    protected_state = $protectedBefore
    protected_sha256 = $protectedBeforeHash
    provider_state = $providerBefore
    provider_sha256 = $providerBeforeHash
    persistent_process_count = 0
}

$records = @()
$toolchain = New-UnobservedToolchain
$executorSha256 = (Get-FileHash -LiteralPath $executor -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $record = Invoke-Operation 1 $executorPortable $executorSha256 $service
} catch {
    Complete-StoppedReceipt 'refused' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
    exit 0
}
$records += $record
if ([int] $record.exit_code -ne 0 -or [bool] $record.stdout_truncated -or [bool] $record.stderr_truncated) {
    Complete-StoppedReceipt 'failed' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
    exit 0
}
Write-Utf8New (Join-Path $target 'preflight.json') ($preflight | ConvertTo-Json -Depth 30 -Compress)

try {
    $record = Invoke-Operation 2 $executorPortable $executorSha256 'C:\AI\workspaces'
} catch {
    Complete-StoppedReceipt 'refused' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
    exit 0
}
$records += $record
if ([int] $record.exit_code -ne 0 -or [bool] $record.stdout_truncated -or [bool] $record.stderr_truncated) {
    Complete-StoppedReceipt 'failed' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
    exit 0
}
Assert-DirectDirectory $workspace 'materialized workspace'

try {
    $cargoCommand = Get-Command cargo.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $rustcCommand = Get-Command rustc.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $linkerCommand = Get-Command link.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $cargoItem = Get-Item -LiteralPath $cargoCommand.Source -Force
    $rustcItem = Get-Item -LiteralPath $rustcCommand.Source -Force
    $linkerItem = Get-Item -LiteralPath $linkerCommand.Source -Force
    foreach ($item in @($cargoItem, $rustcItem, $linkerItem)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.FullName.StartsWith('C:\', [StringComparison]::OrdinalIgnoreCase)) { throw 'existing toolchain executable boundary differs' }
    }
    $cargoPortable = $cargoItem.FullName.Replace('\', '/')
    $cargoSha256 = (Get-FileHash -LiteralPath $cargoItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $probe = Invoke-JsonProcess $runner @('probe', '--executable-path', $cargoPortable, '--executable-sha256', $cargoSha256) $workspace 'locked-offline toolchain probe'
    if ($probe.status -cne 'passed' -or [int] $probe.exit_code -ne 0 -or [int] $probe.persistent_processes -ne 0 -or [int] $probe.effects -ne 0) { throw 'locked-offline toolchain probe semantics differ' }
    $cargoVersion = if ([string]::IsNullOrWhiteSpace($cargoItem.VersionInfo.FileVersion)) { 'unknown_file_version' } else { [string] $cargoItem.VersionInfo.FileVersion }
    $rustcVersion = if ([string]::IsNullOrWhiteSpace($rustcItem.VersionInfo.FileVersion)) { 'unknown_file_version' } else { [string] $rustcItem.VersionInfo.FileVersion }
    $toolchain = [ordered]@{
        architecture = [string] $env:PROCESSOR_ARCHITECTURE
        cargo_path = $cargoPortable
        cargo_sha256 = $cargoSha256
        cargo_version = $cargoVersion
        rustc_path = $rustcItem.FullName.Replace('\', '/')
        rustc_sha256 = (Get-FileHash -LiteralPath $rustcItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        rustc_version = $rustcVersion
        linker_path = $linkerItem.FullName.Replace('\', '/')
        linker_sha256 = (Get-FileHash -LiteralPath $linkerItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        offline_probe_status = 'available_without_mutation'
        observation_sha256 = ''
    }
} catch {
    Complete-StoppedReceipt 'refused' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
    exit 0
}
Write-Utf8New (Join-Path $target 'toolchain_observation.json') ($toolchain | ConvertTo-Json -Depth 10 -Compress)

foreach ($ordinal in 3..6) {
    try {
        $record = Invoke-Operation $ordinal $cargoPortable $cargoSha256 $workspace
    } catch {
        Complete-StoppedReceipt 'refused' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
        exit 0
    }
    $records += $record
    if ([int] $record.exit_code -ne 0 -or [bool] $record.stdout_truncated -or [bool] $record.stderr_truncated) {
        Complete-StoppedReceipt 'failed' $toolchain $records $preflight $protectedBefore $protectedBeforeHash $providerBefore $providerBeforeHash
        exit 0
    }
}

$null = Invoke-PackageVerification
$closure = Assert-Conservation $protectedBefore $providerBefore
$finalAudit = [ordered]@{
    profile = 'cantor-evox2-scratch-build-final-audit/0.1'
    status = 'passed'
    target_host = 'EVO-X2'
    protected_state = $closure.protected_after
    protected_sha256 = $closure.protected_after_sha256
    provider_state = $closure.provider_after
    provider_sha256 = $closure.provider_after_sha256
    persistent_process_count = $closure.persistent_process_count
    package_unchanged = $true
}
Write-Utf8New (Join-Path $target 'final_audit.json') ($finalAudit | ConvertTo-Json -Depth 30 -Compress)
Copy-Item -LiteralPath (Join-Path $service 'commission.json') -Destination (Join-Path $target 'commission.json')
$candidateObject = New-ReceiptCandidate 'succeeded' $true $toolchain $records $protectedBeforeHash $closure.protected_after_sha256 $providerBeforeHash $closure.provider_after_sha256 $closure.persistent_process_count
$candidate = $candidateObject | ConvertTo-Json -Depth 30 -Compress
Write-Utf8New (Join-Path $target 'receipt_candidate.json') $candidate
$seal = Invoke-JsonProcess $runner @('run', '--ordinal', '7', '--executable-path', $executorPortable, '--executable-sha256', $executorSha256) $target 'receipt seal'
if ($seal.status -cne 'passed' -or [int] $seal.exit_code -ne 0 -or [int] $seal.persistent_processes -ne 0 -or [int] $seal.effects -ne 0) { throw 'receipt seal observation differs' }
$verification = Invoke-JsonProcess $receiptVerifier @('commission.json', 'receipt.json') $target 'receipt verification'
if ($verification.status -cne 'passed' -or $verification.disposition -cne 'succeeded' -or [int] $verification.operation_record_count -ne 7 -or -not [bool] $verification.physical_build_performed -or [int] $verification.persistent_executor_process_count -ne 0) { throw 'receipt verification semantics differ' }
Write-Utf8New (Join-Path $target 'receipt_verification.json') ($verification | ConvertTo-Json -Depth 20 -Compress)
$postflight = Assert-Conservation $protectedBefore $providerBefore
if ($runTimer.ElapsedMilliseconds -gt $maximumTotalMilliseconds) { throw 'total execution duration bound exceeded' }
[ordered]@{
    profile = 'cantor-evox2-scratch-build-host-run/0.1'
    status = 'succeeded'
    target_host = 'EVO-X2'
    operation_record_count = 7
    physical_build_performed = $true
    receipt_sha256 = [string] $verification.receipt_sha256
    package_manifest_sha256 = [string] $package.implementation_manifest_sha256
    total_duration_ms = [int64] $runTimer.ElapsedMilliseconds
    protected_state_unchanged = ($protectedBeforeHash -ceq $postflight.protected_after_sha256)
    provider_state_unchanged = ($providerBeforeHash -ceq $postflight.provider_after_sha256)
    persistent_processes = [int] $postflight.persistent_process_count
    denied_effects = 0
} | ConvertTo-Json -Depth 20 -Compress
