[CmdletBinding()]
param(
    [string]$OutputDirectory = 'experiments/operator_configuration_diagnostic/artifacts',
    [switch]$UsePrebuilt,
    [switch]$ReplaceOutputs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputDirectoryPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
}
$readyName = 'operator_configuration_ready_v1.json'
$refusedName = 'operator_configuration_refused_v1.json'
$evidenceName = 'operator_configuration_diagnostic_evidence_v1.json'
$readyPath = Join-Path $outputDirectoryPath $readyName
$refusedPath = Join-Path $outputDirectoryPath $refusedName
$evidencePath = Join-Path $outputDirectoryPath $evidenceName
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = Join-Path $temporaryBase 'cantor-operator-config-diagnostic-p0-fixture'
$stagingPath = $null
$fixtureCreated = $false
$publicFixtureToken = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$invalidFixtureToken = 'invalid-public-fixture-authentication'
$nonAuthority = 'This provider-free preflight evidence proves only exact current startup-artifact validation before listener binding. It grants no configuration, secret, repair, migration, service, provider, effect, persistence, operator-product, or production authority.'

function Assert-Evidence([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function ConvertTo-CanonicalJsonBytes([object]$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")) + "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Write-CanonicalJson([string]$Path, [object]$Value) {
    [IO.File]::WriteAllBytes($Path, (ConvertTo-CanonicalJsonBytes $Value))
}

function Get-Identity([string]$Path, [string]$RelativePath) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Evidence (-not $item.PSIsContainer) "artifact is not a regular file: $RelativePath"
    Assert-Evidence (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "artifact is a reparse point: $RelativePath"
    Assert-Evidence ([uint64]$item.Length -gt 0) "artifact is empty: $RelativePath"
    [ordered]@{
        path = $RelativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-ByteIdentity([byte[]]$Bytes, [string]$RelativePath) {
    Assert-Evidence ($Bytes.Length -gt 0) "generated artifact is empty: $RelativePath"
    [ordered]@{
        path = $RelativePath.Replace('\', '/')
        bytes = [uint64]$Bytes.Length
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))
    }
}

function Compare-Bytes([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Invoke-ConfigurationCheck([string]$BinaryPath, [string]$ConfigPath) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $BinaryPath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('--check-config')
    $start.ArgumentList.Add($ConfigPath)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-Evidence ($process.Start()) 'failed to start cantord diagnostic process'
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [pscustomobject]@{
            exit_code = $process.ExitCode
            stdout_bytes = [Text.UTF8Encoding]::new($false).GetBytes($stdout)
            stderr_bytes = [Text.UTF8Encoding]::new($false).GetBytes($stderr)
        }
    }
    finally { $process.Dispose() }
}

function Assert-NoReportDisclosure([byte[]]$Bytes) {
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    foreach ($forbidden in @(
        $fixtureRoot,
        $publicFixtureToken,
        $invalidFixtureToken,
        'service.json',
        'activation.json',
        'token.txt',
        'environment.json',
        'fixture-only signed semantic coprocessor',
        'authentication token must contain exactly 64 hexadecimal characters'
    )) {
        Assert-Evidence (-not $text.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "retained diagnostic disclosed forbidden value: $forbidden"
    }
}

function Assert-BasicReport([byte[]]$Bytes, [string]$ExpectedStatus) {
    Assert-Evidence ($Bytes.Length -gt 1 -and $Bytes[-1] -eq 10 -and $Bytes[-2] -ne 13) 'diagnostic is not one LF-terminated JSON record'
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    Assert-Evidence (($text.Substring(0, $text.Length - 1)).IndexOf("`n", [StringComparison]::Ordinal) -lt 0) 'diagnostic contains more than one JSON line'
    $report = $text | ConvertFrom-Json
    Assert-Evidence ($report.profile -ceq 'cantor-operator-configuration-diagnostic/0.1') 'diagnostic profile differs'
    Assert-Evidence ($report.status -ceq $ExpectedStatus) 'diagnostic status differs'
    foreach ($field in $report.privacy.PSObject.Properties) {
        Assert-Evidence (-not [bool]$field.Value) "privacy or effect field is true: $($field.Name)"
    }
    if ($ExpectedStatus -ceq 'ready') {
        Assert-Evidence ($null -ne $report.ready_summary -and $null -eq $report.fault) 'ready report exclusivity differs'
    }
    else {
        Assert-Evidence ($null -eq $report.ready_summary -and $null -ne $report.fault) 'refused report exclusivity differs'
    }
    Assert-NoReportDisclosure $Bytes
}

function Remove-ExactDirectory([string]$Path, [string]$ExpectedParent, [string]$ExpectedLeaf) {
    if (-not [IO.Directory]::Exists($Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    $wantedParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\', '/')
    Assert-Evidence ($actualParent.Equals($wantedParent, [StringComparison]::OrdinalIgnoreCase)) 'cleanup parent differs'
    Assert-Evidence ($item.Name -ceq $ExpectedLeaf) 'cleanup leaf differs'
    Assert-Evidence ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'cleanup target is not one physical directory'
    [IO.Directory]::Delete($item.FullName, $true)
}

$profileRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
$driveRoot = [IO.Path]::GetPathRoot($outputDirectoryPath)
Assert-Evidence (-not $outputDirectoryPath.Equals($profileRoot, [StringComparison]::OrdinalIgnoreCase)) 'OutputDirectory must not be the user profile root'
Assert-Evidence (-not $outputDirectoryPath.Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) 'OutputDirectory must not be a drive root'
Assert-Evidence (-not $outputDirectoryPath.Equals($root, [StringComparison]::OrdinalIgnoreCase)) 'OutputDirectory must not be the repository root'

if (-not [IO.Directory]::Exists($outputDirectoryPath)) {
    $parent = [IO.Path]::GetDirectoryName($outputDirectoryPath)
    Assert-Evidence (-not [string]::IsNullOrWhiteSpace($parent) -and [IO.Directory]::Exists($parent)) 'OutputDirectory parent must already exist'
    $parentItem = Get-Item -LiteralPath $parent -Force
    Assert-Evidence ($parentItem.PSIsContainer -and ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory parent must be one physical directory'
    [IO.Directory]::CreateDirectory($outputDirectoryPath) | Out-Null
}
$outputItem = Get-Item -LiteralPath $outputDirectoryPath -Force
Assert-Evidence ($outputItem.PSIsContainer -and ($outputItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory must be one physical directory'
foreach ($destination in @($readyPath, $refusedPath, $evidencePath)) {
    Assert-Evidence (-not [IO.Directory]::Exists($destination)) 'an output path identifies a directory'
    if ([IO.File]::Exists($destination)) {
        Assert-Evidence $ReplaceOutputs 'output already exists; use ReplaceOutputs only after reviewing all three targets'
        $destinationItem = Get-Item -LiteralPath $destination -Force
        Assert-Evidence (($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'output file is a reparse point'
    }
}

$branch = (& git -C $root rev-parse --abbrev-ref HEAD).Trim()
$head = (& git -C $root rev-parse HEAD).Trim()
$upstream = (& git -C $root rev-parse '@{upstream}').Trim()
Assert-Evidence ($LASTEXITCODE -eq 0 -and $branch -ceq 'codex/self-hosted-corpus' -and $head -ceq $upstream) 'evidence generation requires the published codex/self-hosted-corpus HEAD'
& git -C $root diff --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean tracked working tree'
& git -C $root diff --cached --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean index'

if (-not $UsePrebuilt) {
    Push-Location $root
    try {
        & cargo build -p cantor_service --bin cantord --release --locked --offline
        Assert-Evidence ($LASTEXITCODE -eq 0) 'locked offline cantord release build failed'
    }
    finally { Pop-Location }
    $buildMode = 'built_locked_offline'
}
else {
    $buildMode = 'verified_prebuilt'
}

$cantordPath = Join-Path $root 'target/release/cantord.exe'
Assert-Evidence ([IO.File]::Exists($cantordPath)) 'release cantord binary is absent'
$cantordIdentity = Get-Identity $cantordPath 'target/release/cantord.exe'
$cargoLockIdentity = Get-Identity (Join-Path $root 'Cargo.lock') 'Cargo.lock'
Assert-Evidence (-not [IO.Directory]::Exists($fixtureRoot) -and -not [IO.File]::Exists($fixtureRoot)) 'fixed disposable fixture root already exists; inspect it rather than replacing it'

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $fixtureCreated = $true
    Push-Location $root
    try {
        & cargo run --quiet -p cantor_cli --example generate_demo --release --locked --offline -- $fixtureRoot | Out-Null
        Assert-Evidence ($LASTEXITCODE -eq 0) 'public signed fixture generation failed'
    }
    finally { Pop-Location }

    $environmentPath = Join-Path $fixtureRoot 'environment.json'
    $activationPath = Join-Path $fixtureRoot 'activation.json'
    $tokenPath = Join-Path $fixtureRoot 'token.txt'
    $configPath = Join-Path $fixtureRoot 'service.json'
    Assert-Evidence ([IO.File]::Exists($environmentPath)) 'generated fixture environment is absent'
    [IO.File]::WriteAllText($tokenPath, "$publicFixtureToken`n", [Text.UTF8Encoding]::new($false))
    $activation = [ordered]@{
        schema = 'cantor-environment-activation/0.1'
        sequence = [uint64]1
        environment_path = $environmentPath
        environment_file_sha256 = (Get-FileHash -LiteralPath $environmentPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-CanonicalJson $activationPath $activation
    $config = [ordered]@{
        schema = 'cantor-service-config/0.1'
        listen_address = '127.0.0.1:39841'
        activation_path = $activationPath
        allowed_environment_root = $fixtureRoot
        auth_token_path = $tokenPath
        max_frame_bytes = [uint64]1048576
        max_connections = [uint64]32
        read_timeout_ms = [uint64]5000
        write_timeout_ms = [uint64]5000
    }
    Write-CanonicalJson $configPath $config

    $readyFirst = Invoke-ConfigurationCheck $cantordPath $configPath
    $readyReplay = Invoke-ConfigurationCheck $cantordPath $configPath
    Assert-Evidence ($readyFirst.exit_code -eq 0 -and $readyReplay.exit_code -eq 0) 'ready diagnostic did not exit zero twice'
    Assert-Evidence ($readyFirst.stderr_bytes.Length -eq 0 -and $readyReplay.stderr_bytes.Length -eq 0) 'ready diagnostic wrote stderr'
    Assert-Evidence (Compare-Bytes $readyFirst.stdout_bytes $readyReplay.stdout_bytes) 'ready diagnostic replay bytes differ'
    Assert-BasicReport $readyFirst.stdout_bytes 'ready'

    [IO.File]::WriteAllText($tokenPath, "$invalidFixtureToken`n", [Text.UTF8Encoding]::new($false))
    $refused = Invoke-ConfigurationCheck $cantordPath $configPath
    Assert-Evidence ($refused.exit_code -eq 3) 'refused diagnostic did not exit three'
    Assert-Evidence ($refused.stderr_bytes.Length -eq 0) 'refused diagnostic wrote stderr'
    Assert-BasicReport $refused.stdout_bytes 'refused'

    $readyIdentity = Get-ByteIdentity $readyFirst.stdout_bytes "experiments/operator_configuration_diagnostic/artifacts/$readyName"
    $refusedIdentity = Get-ByteIdentity $refused.stdout_bytes "experiments/operator_configuration_diagnostic/artifacts/$refusedName"

    Remove-ExactDirectory $fixtureRoot $temporaryBase 'cantor-operator-config-diagnostic-p0-fixture'
    $fixtureCreated = $false
    Assert-Evidence (-not (Test-Path -LiteralPath $fixtureRoot)) 'disposable fixture root remains after cleanup'

    $evidence = [ordered]@{
        profile = 'cantor-operator-configuration-diagnostic-evidence/0.1'
        status = 'provider_free_configuration_diagnostic_verified_with_declared_gaps'
        source_commit = $head
        platform = 'windows_x86_64_local'
        build_mode = $buildMode
        cargo_lock = $cargoLockIdentity
        cantord = $cantordIdentity
        reports = @($readyIdentity, $refusedIdentity)
        executions = [ordered]@{
            ready_exit_code = [int32]$readyFirst.exit_code
            ready_replay_exit_code = [int32]$readyReplay.exit_code
            refused_exit_code = [int32]$refused.exit_code
            ready_replay_byte_equal = $true
            stdout_lf_terminated_each = $true
            domain_stderr_bytes_each = @([uint64]0, [uint64]0, [uint64]0)
        }
        cleanup = [ordered]@{
            fixture_root_removed = $true
            fixture_root_absent_at_publication = $true
            staging_removed_after_publication = $true
        }
        safety = [ordered]@{
            diagnostic_listener_bound = $false
            service_started = $false
            provider_contacted = $false
            remote_accessed = $false
            operator_inputs_mutated = $false
            production_secret_created = $false
            raw_fault_recorded = $false
        }
        capability_denials = @(
            'configuration_generation_or_repair'
            'production_secret_provisioning'
            'listener_or_service_availability'
            'provider_execution'
            'migration_or_upgrade'
            'durable_or_distributed_custody'
            'external_effect_execution'
            'automatic_remote_access'
            'fpga_execution'
            'minecraft_scope'
            'operator_product_or_production_readiness'
        )
        non_authority_statement = $nonAuthority
    }

    $stagingPath = Join-Path $outputDirectoryPath ('.cantor-operator-diagnostic-' + [guid]::NewGuid().ToString('N'))
    Assert-Evidence (-not (Test-Path -LiteralPath $stagingPath)) 'generated staging path already exists'
    [IO.Directory]::CreateDirectory($stagingPath) | Out-Null
    $stagedReady = Join-Path $stagingPath $readyName
    $stagedRefused = Join-Path $stagingPath $refusedName
    $stagedEvidence = Join-Path $stagingPath $evidenceName
    [IO.File]::WriteAllBytes($stagedReady, $readyFirst.stdout_bytes)
    [IO.File]::WriteAllBytes($stagedRefused, $refused.stdout_bytes)
    Write-CanonicalJson $stagedEvidence $evidence
    [IO.File]::Move($stagedReady, $readyPath, $true)
    [IO.File]::Move($stagedRefused, $refusedPath, $true)
    [IO.File]::Move($stagedEvidence, $evidencePath, $true)
    Remove-ExactDirectory $stagingPath $outputDirectoryPath ([IO.Path]::GetFileName($stagingPath))
    $stagingPath = $null
}
finally {
    if ($fixtureCreated) {
        Remove-ExactDirectory $fixtureRoot $temporaryBase 'cantor-operator-config-diagnostic-p0-fixture'
    }
    if (-not [string]::IsNullOrWhiteSpace($stagingPath)) {
        Remove-ExactDirectory $stagingPath $outputDirectoryPath ([IO.Path]::GetFileName($stagingPath))
    }
}

Write-Output "operator_configuration_diagnostic_evidence_written=true source_commit=$head ready_bytes=$((Get-Item -LiteralPath $readyPath).Length) refused_bytes=$((Get-Item -LiteralPath $refusedPath).Length) fixture_removed=true"
