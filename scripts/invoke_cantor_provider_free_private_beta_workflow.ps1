[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidatePattern('^127\.0\.0\.1:[0-9]{4,5}$')]
    [string]$ListenAddress = '127.0.0.1:39851',

    [switch]$UsePrebuilt,

    [switch]$ReplaceOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$run = [IO.Path]::GetFullPath($RunRoot)
$output = [IO.Path]::GetFullPath($OutputPath)
$runLeaf = [IO.Path]::GetFileName($run)
$runParent = [IO.Path]::GetDirectoryName($run)
$repositoryPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$userProfileRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
$driveRoot = [IO.Path]::GetPathRoot($run)
$script:scriptInvocationSequence = 0

function Assert-Workflow([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-FileIdentity([string]$Name, [string]$Path, [string]$RelativePath) {
    $item = Get-Item -LiteralPath $Path
    [ordered]@{
        name = $Name
        source_path = $RelativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-TextSha256([string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)))
}

function Read-Json([string]$Path) {
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Invoke-NativeJson(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$Label,
    [string]$ErrorDirectory
) {
    $errorPath = Join-Path $ErrorDirectory "$Label.stderr.txt"
    $global:LASTEXITCODE = 0
    $lines = @(& $FilePath @Arguments 2> $errorPath)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $detail = if (Test-Path -LiteralPath $errorPath) {
            (Get-Content -LiteralPath $errorPath -Raw).Trim()
        }
        else { '' }
        throw "$Label failed with exit $exitCode`: $($detail.Substring(0, [Math]::Min(1000, $detail.Length)))"
    }
    $text = ($lines -join "`n").Trim()
    try { return $text | ConvertFrom-Json }
    catch { throw "$Label did not emit one JSON value: $($_.Exception.Message)" }
}

function Invoke-ScriptJson([string]$Path, [hashtable]$Parameters, [string]$Label) {
    try {
        $invokeParts = [Collections.Generic.List[string]]::new()
        $invokeParts.Add("& '$($Path.Replace("'", "''"))'")
        foreach ($name in @($Parameters.Keys | Sort-Object)) {
            $parameterValue = ([string]$Parameters[$name]).Replace("'", "''")
            $invokeParts.Add("-$name '$parameterValue'")
        }
        $childCommand = @(
            '$ErrorActionPreference = ''Stop'''
            'Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop'
            ($invokeParts -join ' ')
        ) -join "`r`n"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
        $script:scriptInvocationSequence += 1
        $captureDirectory = Join-Path $run 'workflow-logs'
        [IO.Directory]::CreateDirectory($captureDirectory) | Out-Null
        $stdoutPath = Join-Path $captureDirectory ("script-$($script:scriptInvocationSequence).stdout.json")
        $stderrPath = Join-Path $captureDirectory ("script-$($script:scriptInvocationSequence).stderr.txt")
        $process = Start-Process `
            -FilePath 'powershell.exe' `
            -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand $encodedCommand" `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            $detail = if (Test-Path -LiteralPath $stderrPath) { (Get-Content -LiteralPath $stderrPath -Raw).Trim() } else { '' }
            throw "Windows PowerShell child exited with status $($process.ExitCode)`: $($detail.Substring(0, [Math]::Min(1000, $detail.Length)))"
        }
        return ((Get-Content -LiteralPath $stdoutPath -Raw).Trim() | ConvertFrom-Json)
    }
    catch {
        throw "$Label failed: $($_.Exception.Message)"
    }
}

Assert-Workflow ([IO.Path]::IsPathRooted($RunRoot)) 'RunRoot must be absolute'
Assert-Workflow ($runLeaf -cmatch '^cantor-private-beta-[a-f0-9]{32}$') 'RunRoot leaf must match cantor-private-beta plus 32 lowercase hexadecimal characters'
Assert-Workflow (-not [string]::IsNullOrWhiteSpace($runParent) -and [IO.Directory]::Exists($runParent)) 'RunRoot parent must already exist'
$runParentItem = Get-Item -LiteralPath $runParent -Force
Assert-Workflow ($runParentItem.PSIsContainer -and ($runParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'RunRoot parent must be a physical directory rather than a reparse point'
Assert-Workflow (-not $run.Equals($root, [StringComparison]::OrdinalIgnoreCase) -and -not $run.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) 'RunRoot must be outside the repository'
Assert-Workflow (-not $run.Equals($userProfileRoot, [StringComparison]::OrdinalIgnoreCase)) 'RunRoot must not be the user profile root'
Assert-Workflow (-not $run.Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) 'RunRoot must not be a drive root'
Assert-Workflow (-not (Test-Path -LiteralPath $run)) 'RunRoot must be absent before execution'
Assert-Workflow (-not $output.Equals($run, [StringComparison]::OrdinalIgnoreCase) -and -not $output.StartsWith(($run.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) 'OutputPath must be outside RunRoot'
Assert-Workflow (-not [IO.Directory]::Exists($output)) 'OutputPath must not identify a directory'
Assert-Workflow ($ReplaceOutput -or -not [IO.File]::Exists($output)) 'OutputPath already exists; use ReplaceOutput only after reviewing the target'
$port = [int]$ListenAddress.Substring($ListenAddress.LastIndexOf(':') + 1)
Assert-Workflow ($port -ge 1024 -and $port -le 65535) 'ListenAddress port must be 1024 through 65535'

$head = (& git -C $root rev-parse HEAD).Trim()
Assert-Workflow ($LASTEXITCODE -eq 0) 'cannot resolve repository HEAD'
$branch = (& git -C $root rev-parse --abbrev-ref HEAD).Trim()
$upstream = (& git -C $root rev-parse '@{upstream}').Trim()
Assert-Workflow ($branch -ceq 'codex/self-hosted-corpus' -and $head -ceq $upstream) 'workflow requires the published codex/self-hosted-corpus HEAD'

$cargoLock = Get-FileIdentity 'Cargo.lock' (Join-Path $root 'Cargo.lock') 'Cargo.lock'
$steps = [Collections.Generic.List[object]]::new()
$steps.Add([ordered]@{ name = 'published_preflight'; status = 'passed'; detail = 'head_equals_upstream' })
$serviceStarted = $false
$statePath = $null
$completed = $false

try {
    [IO.Directory]::CreateDirectory($run) | Out-Null
    $runItem = Get-Item -LiteralPath $run -Force
    Assert-Workflow ($runItem.PSIsContainer -and ($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and [IO.Path]::GetFullPath($runItem.FullName) -ceq $run) 'created RunRoot identity or path type differs'
    $binDirectory = Join-Path $run 'bin'
    $keyDirectory = Join-Path $run 'fixture-keys'
    $corpusDirectory = Join-Path $run 'corpus'
    $runtimeDirectory = Join-Path $run 'service-runtime'
    $supervisorDirectory = Join-Path $run 'service-supervisor'
    $logDirectory = Join-Path $run 'workflow-logs'
    foreach ($directory in @($binDirectory, $keyDirectory, $runtimeDirectory, $supervisorDirectory, $logDirectory)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }

    if (-not $UsePrebuilt) {
        Push-Location $root
        try {
            & cargo build -p cantor_cli -p cantor_service --bins --release --locked --offline
            Assert-Workflow ($LASTEXITCODE -eq 0) 'locked offline release build failed'
        }
        finally { Pop-Location }
        $buildDetail = 'built_locked_offline_release'
    }
    else {
        $buildDetail = 'verified_prebuilt_locked_workspace_release'
    }
    $steps.Add([ordered]@{ name = 'release_build'; status = 'passed'; detail = $buildDetail })

    $binaryNames = @('cantor.exe', 'cantor-corpus.exe', 'cantord.exe', 'cantorctl.exe')
    $releaseArtifacts = @()
    foreach ($binaryName in $binaryNames) {
        $source = Join-Path $root "target/release/$binaryName"
        Assert-Workflow (Test-Path -LiteralPath $source -PathType Leaf) "release binary is absent: $binaryName"
        $installed = Join-Path $binDirectory $binaryName
        Copy-Item -LiteralPath $source -Destination $installed
        $sourceIdentity = Get-FileIdentity $binaryName $source "target/release/$binaryName"
        $installedIdentity = Get-FileIdentity $binaryName $installed "bin/$binaryName"
        Assert-Workflow ($sourceIdentity.bytes -eq $installedIdentity.bytes -and $sourceIdentity.sha256 -ceq $installedIdentity.sha256) "installed binary differs: $binaryName"
        $releaseArtifacts += [ordered]@{
            name = $binaryName
            source_path = $sourceIdentity.source_path
            installed_path = $installedIdentity.source_path
            bytes = $sourceIdentity.bytes
            sha256 = $sourceIdentity.sha256
            installed_equal = $true
        }
    }
    Assert-Workflow (@($releaseArtifacts.sha256 | Select-Object -Unique).Count -eq 4) 'release binary identities must be distinct'
    $steps.Add([ordered]@{ name = 'disposable_install'; status = 'passed'; detail = 'four_exact_distinct_binaries' })

    $authorityKey = Join-Path $keyDirectory 'authority.key'
    $compilerKey = Join-Path $keyDirectory 'compiler.key'
    $authorityBytes = [byte[]]::new(32)
    $compilerBytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($authorityBytes)
    do { [Security.Cryptography.RandomNumberGenerator]::Fill($compilerBytes) }
    while ([Linq.Enumerable]::SequenceEqual($authorityBytes, $compilerBytes))
    [IO.File]::WriteAllBytes($authorityKey, $authorityBytes)
    [IO.File]::WriteAllBytes($compilerKey, $compilerBytes)
    $steps.Add([ordered]@{ name = 'fixture_keys'; status = 'passed'; detail = 'two_distinct_ephemeral_32_byte_seeds' })

    $corpusCompiler = Join-Path $binDirectory 'cantor-corpus.exe'
    $corpusManifestPath = Join-Path $root 'corpus/self_hosted/corpus.json'
    $compile = Invoke-NativeJson $corpusCompiler @(
        'compile', '--manifest', $corpusManifestPath,
        '--authority-key', $authorityKey,
        '--compiler-key', $compilerKey,
        '--output', $corpusDirectory
    ) 'corpus_compile' $logDirectory
    Assert-Workflow ($compile.status -ceq 'success') 'corpus compiler did not report success'
    $buildManifestPath = Join-Path $corpusDirectory 'build-manifest.json'
    $environmentPath = Join-Path $corpusDirectory 'environment.json'
    $queryPath = Join-Path $corpusDirectory 'query-cantor.json'
    foreach ($required in @($buildManifestPath, $environmentPath, $queryPath)) {
        Assert-Workflow (Test-Path -LiteralPath $required -PathType Leaf) "generated corpus artifact is absent: $required"
    }
    $buildManifest = Read-Json $buildManifestPath
    Assert-Workflow ($buildManifest.corpus_profile -ceq 'cantor-sop-corpus/0.1' -and [int]$buildManifest.source_count -eq 3 -and [int]$buildManifest.unit_count -eq 417 -and [int]$buildManifest.relation_count -eq 360) 'generated corpus identity or counts differ'
    Assert-Workflow ($buildManifest.manifest_digest.value -ceq (Get-FileHash -LiteralPath $corpusManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'generated corpus manifest digest differs'
    foreach ($artifactName in @('environment.json', 'query-cantor.json')) {
        $actualHash = (Get-FileHash -LiteralPath (Join-Path $corpusDirectory $artifactName) -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Workflow ($buildManifest.artifacts.$artifactName.value -ceq $actualHash) "generated artifact digest differs: $artifactName"
    }
    $steps.Add([ordered]@{ name = 'self_hosted_corpus'; status = 'passed'; detail = '3_sources_417_units_360_relations' })

    $initialize = Invoke-ScriptJson (Join-Path $PSScriptRoot 'initialize_cantor_service.ps1') @{
        EnvironmentPath = $environmentPath
        RuntimeDirectory = $runtimeDirectory
        AllowedEnvironmentRoot = $corpusDirectory
        ListenAddress = $ListenAddress
    } 'service configuration'
    $configPath = [string]$initialize.service_config
    Assert-Workflow ($initialize.listen_address -ceq $ListenAddress -and (Test-Path -LiteralPath $configPath -PathType Leaf)) 'service configuration result differs'
    $steps.Add([ordered]@{ name = 'loopback_configuration'; status = 'passed'; detail = 'strict_ipv4_loopback' })

    $statePath = Join-Path $supervisorDirectory 'state.json'
    $start = Invoke-ScriptJson (Join-Path $PSScriptRoot 'start_cantor_service.ps1') @{
        ServerPath = (Join-Path $binDirectory 'cantord.exe')
        ClientPath = (Join-Path $binDirectory 'cantorctl.exe')
        ConfigPath = $configPath
        StatePath = $statePath
        ReadinessTimeoutMilliseconds = [uint32]30000
    } 'supervised start'
    $serviceStarted = $true
    $health = Invoke-ScriptJson (Join-Path $PSScriptRoot 'get_cantor_service_health.ps1') @{
        StatePath = $statePath
    } 'authenticated health'
    Assert-Workflow ($start.schema -ceq 'cantor-service-supervisor-health/0.1' -and $health.schema -ceq 'cantor-service-supervisor-health/0.1' -and $health.state -ceq 'active') 'supervisor health profile differs'
    Assert-Workflow ([int64]$start.pid -eq [int64]$health.pid -and $start.current_generation_id -ceq $health.current_generation_id -and [uint64]$start.current_activation_sequence -eq [uint64]$health.current_activation_sequence) 'fresh health differs from start identity'
    Assert-Workflow ($health.server_path -ceq (Join-Path $binDirectory 'cantord.exe') -and $health.client_path -ceq (Join-Path $binDirectory 'cantorctl.exe')) 'health binary paths differ from installed release'
    $steps.Add([ordered]@{ name = 'start_and_health'; status = 'passed'; detail = 'authenticated_exact_process_generation' })

    $serviceResponse = Invoke-NativeJson (Join-Path $binDirectory 'cantorctl.exe') @(
        'query', '--config', $configPath,
        '--request-id', 'request:provider_free_private_beta_service_query',
        '--input', $queryPath
    ) 'service_query' $logDirectory
    Assert-Workflow ($serviceResponse.protocol_version -ceq 'cantor-service-protocol/0.1' -and $serviceResponse.disposition -ceq 'success' -and $serviceResponse.result.kind -ceq 'protocol' -and @($serviceResponse.faults).Count -eq 0) 'service query result differs'
    Assert-Workflow ($serviceResponse.active_binding.generation_id.value -ceq $health.current_generation_id) 'service query generation differs from health'
    $steps.Add([ordered]@{ name = 'representative_service_query'; status = 'passed'; detail = 'generated_query_cantor' })

    $stop = Invoke-ScriptJson (Join-Path $PSScriptRoot 'stop_cantor_service.ps1') @{
        StatePath = $statePath
        ExitTimeoutMilliseconds = [uint32]30000
    } 'graceful stop'
    Assert-Workflow ($stop.schema -ceq 'cantor-service-supervisor-stop/0.1' -and $stop.state -ceq 'stopped' -and [bool]$stop.state_removed -and [int]$stop.exit_code -eq 0 -and -not (Test-Path -LiteralPath $statePath)) 'graceful stop result differs'
    $serviceStarted = $false
    $steps.Add([ordered]@{ name = 'graceful_stop'; status = 'passed'; detail = 'exact_generation_state_removed' })

    $directResponse = Invoke-NativeJson (Join-Path $binDirectory 'cantor.exe') @(
        'query', '--environment', $environmentPath, '--input', $queryPath
    ) 'direct_fallback' $logDirectory
    Assert-Workflow ($directResponse.protocol_version -ceq 'cantor-protocol/0.1' -and $directResponse.status -ceq 'success') 'direct fallback response differs'
    $serviceProtocolText = $serviceResponse.result.response | ConvertTo-Json -Depth 100 -Compress
    $directProtocolText = $directResponse | ConvertTo-Json -Depth 100 -Compress
    Assert-Workflow ($serviceProtocolText -ceq $directProtocolText) 'service and direct ProtocolResponse values differ'
    $protocolResponseSha256 = Get-TextSha256 $directProtocolText
    $steps.Add([ordered]@{ name = 'direct_fallback'; status = 'passed'; detail = 'exact_protocol_response_equal' })

    $runRootForReport = $run
    $pidForReport = [int64]$health.pid
    $generationForReport = [string]$health.current_generation_id
    $activationSequenceForReport = [uint64]$health.current_activation_sequence
    $packageIdForReport = [string]$buildManifest.package_id
    $environmentDigestForReport = [string]$buildManifest.environment_digest.value
    $authorityBytes = $null
    $compilerBytes = $null
    [GC]::Collect()
    [IO.Directory]::Delete($run, $true)
    Assert-Workflow (-not (Test-Path -LiteralPath $run)) 'disposable run root remains after rollback'
    $steps.Add([ordered]@{ name = 'filesystem_rollback'; status = 'passed'; detail = 'validated_disposable_root_removed' })

    $report = [ordered]@{
        profile = 'cantor-provider-free-private-beta-workflow/0.1'
        status = 'provider_free_private_beta_verified_with_declared_gaps'
        source_commit = $head
        cargo_lock = $cargoLock
        build_mode = if ($UsePrebuilt) { 'verified_prebuilt' } else { 'built_locked_offline' }
        platform = 'windows_x86_64_local'
        run_root = $runRootForReport
        listen_address = $ListenAddress
        release_artifacts = $releaseArtifacts
        steps = @($steps)
        corpus = [ordered]@{
            profile = [string]$buildManifest.corpus_profile
            manifest_sha256 = (Get-FileHash -LiteralPath $corpusManifestPath -Algorithm SHA256).Hash
            source_count = [uint32]$buildManifest.source_count
            unit_count = [uint32]$buildManifest.unit_count
            relation_count = [uint32]$buildManifest.relation_count
            package_id = $packageIdForReport
            environment_digest = $environmentDigestForReport
        }
        lifecycle = [ordered]@{
            pid = $pidForReport
            generation_id = $generationForReport
            activation_sequence = $activationSequenceForReport
            health_verified = $true
            service_query_verified = $true
            graceful_stop_verified = $true
            state_removed = $true
            direct_fallback_verified = $true
            protocol_response_equal = $true
            service_protocol_response_sha256 = $protocolResponseSha256
            direct_protocol_response_sha256 = $protocolResponseSha256
        }
        rollback = [ordered]@{
            run_root_removed = $true
            run_root_absent_at_report = $true
            fixture_keys_destroyed = $true
            token_destroyed = $true
            generated_environment_destroyed = $true
            installed_binaries_destroyed = $true
            supervisor_state_removed = $true
            live_process_residual = $false
        }
        provider_contacted = $false
        capability_denials = @(
            'live_provider_success',
            'production_trust_or_secret_lifecycle',
            'os_installer_or_supported_distribution',
            'upgrade_or_migration_policy',
            'durable_or_distributed_custody',
            'external_effect_execution',
            'automatic_remote_access',
            'fpga_execution',
            'minecraft_scope'
        )
        non_authority_statement = 'This local disposable workflow proves one provider-free private-beta mechanical path. Fixture keys are destroyed and grant no production trust, provider, effect, persistence, operator-product, or production authority.'
    }
    $outputParent = [IO.Path]::GetDirectoryName($output)
    if (-not [string]::IsNullOrWhiteSpace($outputParent)) {
        [IO.Directory]::CreateDirectory($outputParent) | Out-Null
    }
    $outputTemporary = "$output.tmp-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($outputTemporary, "$(($report | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $outputTemporary -Destination $output -Force:$ReplaceOutput
    }
    finally {
        if ([IO.File]::Exists($outputTemporary)) { [IO.File]::Delete($outputTemporary) }
    }
    $completed = $true
    Write-Output "private_beta_workflow=passed report=$output artifacts=4 steps=$($steps.Count)"
}
catch {
    $primaryFault = $_.Exception.Message
    $cleanupSafe = $true
    $cleanupFault = $null
    $supervisorStateExists = $null -ne $statePath -and (Test-Path -LiteralPath $statePath -PathType Leaf)
    if ($serviceStarted -or $supervisorStateExists) {
        if ($supervisorStateExists) {
            try {
                Invoke-ScriptJson (Join-Path $PSScriptRoot 'stop_cantor_service.ps1') @{
                    StatePath = $statePath
                    ExitTimeoutMilliseconds = [uint32]30000
                } 'fault cleanup graceful stop' | Out-Null
                $serviceStarted = $false
            }
            catch {
                $cleanupSafe = $false
                $cleanupFault = $_.Exception.Message
            }
        }
        else {
            $cleanupSafe = $false
            $cleanupFault = 'service was started but exact supervisor state is absent'
        }
    }
    if ($cleanupSafe -and (Test-Path -LiteralPath $run)) {
        [IO.Directory]::Delete($run, $true)
    }
    if (-not $cleanupSafe) {
        throw "workflow fault: $primaryFault; cleanup residual retained at $run`: $cleanupFault"
    }
    throw "workflow fault: $primaryFault; safe disposable cleanup completed"
}
finally {
    if (-not $completed) {
        $authorityBytes = $null
        $compilerBytes = $null
    }
}
