[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EnvironmentPath,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeDirectory,

    [Parameter(Mandatory = $true)]
    [string]$CantordPath,

    [string]$AllowedEnvironmentRoot,

    [string]$ListenAddress = '127.0.0.1:39841'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$profileRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
$stagingPath = $null
$stagingCreated = $false
$published = $false
$expectedPublication = $null
$receipt = $null

function Assert-Bootstrap([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-PhysicalFile([string]$Path, [uint64]$MaximumBytes, [string]$Label) {
    Assert-Bootstrap ([IO.File]::Exists($Path)) "$Label must identify an existing file"
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Bootstrap (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label must identify one physical regular file"
    Assert-Bootstrap ([uint64]$item.Length -gt 0 -and [uint64]$item.Length -le $MaximumBytes) "$Label size is outside the admitted range"
    return $item
}

function Get-PhysicalDirectory([string]$Path, [string]$Label) {
    Assert-Bootstrap ([IO.Directory]::Exists($Path)) "$Label must identify an existing directory"
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Bootstrap ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label must identify one physical directory"
    return $item
}

function ConvertTo-JsonBytes([object]$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")) + "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Write-NewBytes([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

function Get-Identity([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Bootstrap (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'transaction artifact is not one physical file'
    [pscustomobject]@{
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Compare-Identity([string]$Path, [psobject]$Expected) {
    if (-not [IO.File]::Exists($Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    return [uint64]$item.Length -eq [uint64]$Expected.bytes -and
        (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ceq [string]$Expected.sha256
}

function Assert-ExactInventory([string]$DirectoryPath, [string[]]$ExpectedNames) {
    $actual = @(Get-ChildItem -LiteralPath $DirectoryPath -Force | ForEach-Object Name | Sort-Object)
    $expected = @($ExpectedNames | Sort-Object)
    Assert-Bootstrap (($actual -join ',') -ceq ($expected -join ',')) 'transaction artifact inventory differs'
    foreach ($name in $ExpectedNames) {
        $item = Get-Item -LiteralPath (Join-Path $DirectoryPath $name) -Force
        Assert-Bootstrap (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'transaction inventory contains a nonphysical file'
    }
}

function Invoke-ConfigurationDiagnostic([string]$BinaryPath, [string]$ConfigPath, [string]$Label) {
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
        Assert-Bootstrap ($process.Start()) "$Label could not start"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-Bootstrap ($process.ExitCode -eq 0) "$Label refused the candidate"
        Assert-Bootstrap ([Text.UTF8Encoding]::new($false).GetByteCount($stderr) -eq 0) "$Label wrote stderr"
        $stdoutBytes = [Text.UTF8Encoding]::new($false).GetBytes($stdout)
        Assert-Bootstrap ($stdoutBytes.Length -gt 1 -and $stdoutBytes[-1] -eq 10 -and $stdoutBytes[-2] -ne 13) "$Label output is not one LF-terminated record"
        Assert-Bootstrap (($stdout.Substring(0, $stdout.Length - 1)).IndexOf("`n", [StringComparison]::Ordinal) -lt 0) "$Label output contains more than one line"
        $diagnostic = $stdout | ConvertFrom-Json
        Assert-Bootstrap ($diagnostic.profile -ceq 'cantor-operator-configuration-diagnostic/0.1' -and $diagnostic.status -ceq 'ready') "$Label output is not one ready diagnostic"
        Assert-Bootstrap (-not [bool]$diagnostic.privacy.listener_bound -and -not [bool]$diagnostic.privacy.service_started -and -not [bool]$diagnostic.privacy.provider_contacted -and -not [bool]$diagnostic.privacy.remote_accessed) "$Label diagnostic effect boundary differs"
        return $diagnostic
    }
    finally { $process.Dispose() }
}

function Remove-ExactStagingDirectory([string]$Path, [string]$ParentPath, [string]$RuntimeLeaf) {
    if (-not [IO.Directory]::Exists($Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    $expectedParent = [IO.Path]::GetFullPath($ParentPath).TrimEnd('\', '/')
    Assert-Bootstrap ($actualParent.Equals($expectedParent, [StringComparison]::OrdinalIgnoreCase)) 'staging cleanup parent differs'
    Assert-Bootstrap ($item.Name -cmatch "^\.$([regex]::Escape($RuntimeLeaf))\.cantor-bootstrap-[a-f0-9]{32}$") 'staging cleanup leaf differs'
    Assert-Bootstrap ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'staging cleanup target is not one physical directory'
    [IO.Directory]::Delete($item.FullName, $true)
}

function Test-OwnedPublication([string]$DirectoryPath, [hashtable]$Expected) {
    if (-not [IO.Directory]::Exists($DirectoryPath)) { return $false }
    $item = Get-Item -LiteralPath $DirectoryPath -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $expectedNames = @('activation.json', 'cantord.token', 'service.json')
    $actualNames = @(Get-ChildItem -LiteralPath $DirectoryPath -Force | ForEach-Object Name | Sort-Object)
    if (($actualNames -join ',') -cne (($expectedNames | Sort-Object) -join ',')) { return $false }
    foreach ($name in $expectedNames) {
        if (-not (Compare-Identity (Join-Path $DirectoryPath $name) $Expected[$name])) { return $false }
    }
    return $true
}

foreach ($suppliedPath in @($EnvironmentPath, $RuntimeDirectory, $CantordPath, $AllowedEnvironmentRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($suppliedPath)) {
        Assert-Bootstrap (-not (($suppliedPath -split '[\\/]') -contains '..')) 'supplied paths must not contain parent traversal segments'
    }
}

$environmentFullPath = [IO.Path]::GetFullPath($EnvironmentPath)
$runtimeFullPath = [IO.Path]::GetFullPath($RuntimeDirectory)
$cantordFullPath = [IO.Path]::GetFullPath($CantordPath)
$environmentItem = Get-PhysicalFile $environmentFullPath ([uint64](64MB)) 'EnvironmentPath'
$cantordItem = Get-PhysicalFile $cantordFullPath ([uint64](64MB)) 'CantordPath'
$allowedRootPath = if ([string]::IsNullOrWhiteSpace($AllowedEnvironmentRoot)) {
    [IO.Path]::GetDirectoryName($environmentItem.FullName)
}
else { [IO.Path]::GetFullPath($AllowedEnvironmentRoot) }
$allowedRootItem = Get-PhysicalDirectory $allowedRootPath 'AllowedEnvironmentRoot'
$runtimeParentPath = [IO.Path]::GetDirectoryName($runtimeFullPath)
Assert-Bootstrap (-not [string]::IsNullOrWhiteSpace($runtimeParentPath)) 'RuntimeDirectory must have one existing parent'
$runtimeParentItem = Get-PhysicalDirectory $runtimeParentPath 'RuntimeDirectory parent'
$runtimeLeaf = [IO.Path]::GetFileName($runtimeFullPath)
Assert-Bootstrap ($runtimeLeaf -cmatch '^[A-Za-z0-9._-]{1,80}$' -and -not $runtimeLeaf.StartsWith('.', [StringComparison]::Ordinal)) 'RuntimeDirectory leaf is outside the admitted form'
$driveRoot = [IO.Path]::GetFullPath([IO.Path]::GetPathRoot($runtimeFullPath))
foreach ($broadRoot in @($driveRoot, $repositoryRoot, $profileRoot)) {
    Assert-Bootstrap (-not $runtimeFullPath.Equals($broadRoot, [StringComparison]::OrdinalIgnoreCase)) 'RuntimeDirectory must not be a broad protected root'
}
Assert-Bootstrap (-not [IO.Directory]::Exists($runtimeFullPath) -and -not [IO.File]::Exists($runtimeFullPath)) 'RuntimeDirectory must be absent for initial creation'
Assert-Bootstrap (-not $runtimeFullPath.Equals($environmentItem.FullName, [StringComparison]::OrdinalIgnoreCase) -and -not $runtimeFullPath.Equals($cantordItem.FullName, [StringComparison]::OrdinalIgnoreCase)) 'RuntimeDirectory collides with an input file'
$allowedPrefix = $allowedRootItem.FullName.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
Assert-Bootstrap ($environmentItem.FullName.Equals($allowedRootItem.FullName, [StringComparison]::OrdinalIgnoreCase) -or $environmentItem.FullName.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) 'EnvironmentPath must be contained by AllowedEnvironmentRoot'
try { $endpoint = [Net.IPEndPoint]::Parse($ListenAddress) }
catch { throw 'ListenAddress must be one explicit IP endpoint' }
Assert-Bootstrap ([Net.IPAddress]::IsLoopback($endpoint.Address) -and $endpoint.Port -gt 0) 'ListenAddress must be one nonzero loopback endpoint'

$stagingPath = Join-Path $runtimeParentItem.FullName (".$runtimeLeaf.cantor-bootstrap-" + [guid]::NewGuid().ToString('N'))
Assert-Bootstrap (-not (Test-Path -LiteralPath $stagingPath)) 'generated staging path already exists'
$tokenName = 'cantord.token'
$activationName = 'activation.json'
$configName = 'service.json'
$candidateName = '.candidate-service.json'
$stagingTokenPath = Join-Path $stagingPath $tokenName
$stagingActivationPath = Join-Path $stagingPath $activationName
$stagingConfigPath = Join-Path $stagingPath $configName
$candidateConfigPath = Join-Path $stagingPath $candidateName
$finalTokenPath = Join-Path $runtimeFullPath $tokenName
$finalActivationPath = Join-Path $runtimeFullPath $activationName
$finalConfigPath = Join-Path $runtimeFullPath $configName

try {
    [IO.Directory]::CreateDirectory($stagingPath) | Out-Null
    $stagingCreated = $true
    $stagingItem = Get-PhysicalDirectory $stagingPath 'generated staging directory'
    Assert-Bootstrap ($stagingItem.Parent.FullName.Equals($runtimeParentItem.FullName, [StringComparison]::OrdinalIgnoreCase)) 'staging directory is not a sibling of RuntimeDirectory'

    $tokenBytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    try { $token = [Convert]::ToHexString($tokenBytes).ToLowerInvariant() }
    finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($tokenBytes) }
    Write-NewBytes $stagingTokenPath ([Text.UTF8Encoding]::new($false).GetBytes("$token`n"))

    $environmentSha256 = (Get-FileHash -LiteralPath $environmentItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $activation = [ordered]@{
        schema = 'cantor-environment-activation/0.1'
        sequence = [uint64]1
        environment_path = $environmentItem.FullName
        environment_file_sha256 = $environmentSha256
    }
    Write-NewBytes $stagingActivationPath (ConvertTo-JsonBytes $activation)
    $candidateConfig = [ordered]@{
        schema = 'cantor-service-config/0.1'
        listen_address = $ListenAddress
        activation_path = $stagingActivationPath
        allowed_environment_root = $allowedRootItem.FullName
        auth_token_path = $stagingTokenPath
        max_frame_bytes = [uint64]1048576
        max_connections = [uint64]32
        read_timeout_ms = [uint64]5000
        write_timeout_ms = [uint64]5000
    }
    Write-NewBytes $candidateConfigPath (ConvertTo-JsonBytes $candidateConfig)
    $null = Invoke-ConfigurationDiagnostic $cantordItem.FullName $candidateConfigPath 'staged configuration diagnostic'
    [IO.File]::Delete($candidateConfigPath)

    $finalConfig = [ordered]@{
        schema = 'cantor-service-config/0.1'
        listen_address = $ListenAddress
        activation_path = $finalActivationPath
        allowed_environment_root = $allowedRootItem.FullName
        auth_token_path = $finalTokenPath
        max_frame_bytes = [uint64]1048576
        max_connections = [uint64]32
        read_timeout_ms = [uint64]5000
        write_timeout_ms = [uint64]5000
    }
    Write-NewBytes $stagingConfigPath (ConvertTo-JsonBytes $finalConfig)
    Assert-ExactInventory $stagingPath @($activationName, $tokenName, $configName)
    $expectedPublication = @{
        $activationName = Get-Identity $stagingActivationPath
        $tokenName = Get-Identity $stagingTokenPath
        $configName = Get-Identity $stagingConfigPath
    }

    [IO.Directory]::Move($stagingPath, $runtimeFullPath)
    $stagingCreated = $false
    $published = $true
    $null = Invoke-ConfigurationDiagnostic $cantordItem.FullName $finalConfigPath 'final configuration diagnostic'
    Assert-ExactInventory $runtimeFullPath @($activationName, $tokenName, $configName)
    Assert-Bootstrap (-not (Test-Path -LiteralPath $stagingPath)) 'staging directory remains after publication'

    $receipt = [ordered]@{
        profile = 'cantor-operator-bootstrap-transaction/0.1'
        status = 'initialized'
        service_config_path = $finalConfigPath
        activation_path = $finalActivationPath
        environment_path = $environmentItem.FullName
        listen_address = $ListenAddress
        checks = @(
            [ordered]@{ ordinal = [uint32]0; name = 'input_validation'; status = 'passed' }
            [ordered]@{ ordinal = [uint32]1; name = 'staged_diagnostic'; status = 'passed' }
            [ordered]@{ ordinal = [uint32]2; name = 'atomic_publication'; status = 'passed' }
            [ordered]@{ ordinal = [uint32]3; name = 'final_diagnostic'; status = 'passed' }
        )
        publication = [ordered]@{
            mode = 'same_parent_absent_directory_move'
            final_file_count = [uint32]3
            staging_absent = $true
        }
        secrecy = [ordered]@{
            token_path_recorded = $false
            token_content_recorded = $false
            token_hash_recorded = $false
            raw_diagnostic_recorded = $false
            environment_content_recorded = $false
            signing_material_recorded = $false
        }
        effects = [ordered]@{
            listener_bound = $false
            service_started = $false
            provider_contacted = $false
            remote_accessed = $false
            replacement_performed = $false
            repair_performed = $false
            migration_performed = $false
        }
        non_authority_statement = 'This initial-create transaction publishes one local bearer configuration that passes current pre-bind validation. It grants no replacement, repair, migration, production secret lifecycle, installation, delivery, service, provider, effect, operator-product, or production authority.'
    }
}
catch {
    $fault = $_.Exception.Message
    if ($published) {
        if (Test-OwnedPublication $runtimeFullPath $expectedPublication) {
            [IO.Directory]::Delete($runtimeFullPath, $true)
            $published = $false
            throw "bootstrap transaction refused after publication and rolled back its exact artifact set: $fault"
        }
        throw "bootstrap transaction refused after publication; changed residual preserved for operator review: $fault"
    }
    throw
}
finally {
    if ($stagingCreated) {
        Remove-ExactStagingDirectory $stagingPath $runtimeParentItem.FullName $runtimeLeaf
    }
}

$receipt | ConvertTo-Json -Depth 100 -Compress
