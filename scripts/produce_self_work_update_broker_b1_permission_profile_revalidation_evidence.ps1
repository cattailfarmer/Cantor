[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ScratchDirectory,

    [string]$SelectedExecutable = 'C:\Users\enjer\AppData\Roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceSnapshotUuid = '3654826b-14d1-4e96-81a4-ab27be83dcd8'
$predecessorCommit = '75aa325b0063416f088d76f60e702a9ed5f3f3a7'
$projectRoot = [IO.Path]::GetFullPath('C:\Project\Cantor')
$projectPrefix = $projectRoot.TrimEnd('\') + '\'

function Resolve-NewProjectPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowExistingEmptyDirectory
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "path must be a strict descendant of C:\Project\Cantor: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        if ($AllowExistingEmptyDirectory -and
            (Test-Path -LiteralPath $resolved -PathType Container) -and
            @(Get-ChildItem -LiteralPath $resolved -Force).Count -eq 0) {
            return $resolved
        }
        throw "path already exists: $resolved"
    }
    return $resolved
}

function Get-UpperSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [int]$TimeoutMilliseconds = 30000
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "process did not start: $Executable"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
        $process.Kill($true)
        throw "process timed out: $Executable"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    return [ordered]@{
        exit_code = $process.ExitCode
        stdout = $stdout
        stderr = $stderr
    }
}

function Send-AppServerMessage {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]$Message
    )
    $line = $Message | ConvertTo-Json -Depth 30 -Compress
    $Process.StandardInput.WriteLine($line)
    $Process.StandardInput.Flush()
}

function Read-AppServerUntilId {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$Id,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[object]]$Transcript
    )
    while ($true) {
        $line = $Process.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult()
        if ($null -eq $line) {
            throw "App Server stdout closed before response id $Id"
        }
        $message = $line | ConvertFrom-Json -Depth 100
        $Transcript.Add($message)
        if ($message.PSObject.Properties.Name -contains 'id' -and [int]$message.id -eq $Id) {
            if ($message.PSObject.Properties.Name -contains 'error') {
                throw "App Server response id $Id returned an error: $line"
            }
            return $message
        }
    }
}

$evidenceRoot = Resolve-NewProjectPath -Path $EvidenceDirectory -AllowExistingEmptyDirectory
$scratchRoot = Resolve-NewProjectPath -Path $ScratchDirectory

if (-not (Test-Path -LiteralPath $SelectedExecutable -PathType Leaf)) {
    throw "selected executable is absent: $SelectedExecutable"
}
$selectedItem = Get-Item -LiteralPath $SelectedExecutable
$selectedSha256 = Get-UpperSha256 -Path $SelectedExecutable
if ($selectedItem.Length -ne 242541872 -or $selectedSha256 -ne 'FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F') {
    throw 'selected executable identity differs'
}

if (-not (Test-Path -LiteralPath $evidenceRoot)) {
    New-Item -ItemType Directory -Path $evidenceRoot | Out-Null
}
New-Item -ItemType Directory -Path $scratchRoot | Out-Null
$standardOutput = Join-Path $scratchRoot 'standard'
$experimentalOutput = Join-Path $scratchRoot 'experimental'
$fixtureRoot = Join-Path $scratchRoot 'fixture'
New-Item -ItemType Directory -Path $standardOutput | Out-Null
New-Item -ItemType Directory -Path $experimentalOutput | Out-Null
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

$versionResult = Invoke-BoundedProcess -Executable $SelectedExecutable -Arguments @('--version') -WorkingDirectory $scratchRoot
if ($versionResult.exit_code -ne 0 -or $versionResult.stdout.Trim() -ne 'codex-cli 0.135.0' -or $versionResult.stderr.Length -ne 0) {
    throw 'selected executable version result differs'
}

$standardArguments = @('app-server', 'generate-json-schema', '--out', $standardOutput)
$standardResult = Invoke-BoundedProcess -Executable $SelectedExecutable -Arguments $standardArguments -WorkingDirectory $scratchRoot
if ($standardResult.exit_code -ne 0) {
    throw "standard schema generation failed: $($standardResult.stderr)"
}
$experimentalArguments = @('app-server', 'generate-json-schema', '--experimental', '--out', $experimentalOutput)
$experimentalResult = Invoke-BoundedProcess -Executable $SelectedExecutable -Arguments $experimentalArguments -WorkingDirectory $scratchRoot
if ($experimentalResult.exit_code -ne 0) {
    throw "experimental schema generation failed: $($experimentalResult.stderr)"
}

$standardSchemaSource = Join-Path $standardOutput 'codex_app_server_protocol.schemas.json'
$experimentalSchemaSource = Join-Path $experimentalOutput 'codex_app_server_protocol.schemas.json'
$standardSchemaEvidence = Join-Path $evidenceRoot 'standard_schema.json'
$experimentalSchemaEvidence = Join-Path $evidenceRoot 'experimental_schema.json'
[IO.File]::WriteAllBytes($standardSchemaEvidence, [IO.File]::ReadAllBytes($standardSchemaSource))
[IO.File]::WriteAllBytes($experimentalSchemaEvidence, [IO.File]::ReadAllBytes($experimentalSchemaSource))

$allowedPath = Join-Path $fixtureRoot 'allowed.txt'
$deniedPath = Join-Path $fixtureRoot 'denied.txt'
[IO.File]::WriteAllText($allowedPath, "SWA05_ALLOWED_READ_SENTINEL`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($deniedPath, "SWA05_DENIED_READ_SENTINEL`n", [Text.UTF8Encoding]::new($false))

$filesystemOverride = "permissions.swa05_probe.filesystem={':root'='deny',':minimal'='read','$fixtureRoot'='read','$deniedPath'='deny'}"
$appStart = [Diagnostics.ProcessStartInfo]::new()
$appStart.FileName = $SelectedExecutable
$appStart.WorkingDirectory = $fixtureRoot
$appStart.UseShellExecute = $false
$appStart.CreateNoWindow = $true
$appStart.RedirectStandardInput = $true
$appStart.RedirectStandardOutput = $true
$appStart.RedirectStandardError = $true
foreach ($argument in @(
    'app-server',
    '--strict-config',
    '-c', 'default_permissions="swa05_probe"',
    '-c', $filesystemOverride,
    '-c', 'permissions.swa05_probe.network.enabled=false',
    '-c', 'analytics.enabled=false'
)) {
    [void]$appStart.ArgumentList.Add($argument)
}

$appServer = [Diagnostics.Process]::new()
$appServer.StartInfo = $appStart
if (-not $appServer.Start()) {
    throw 'App Server did not start'
}
$transcript = [Collections.Generic.List[object]]::new()

try {
    Send-AppServerMessage -Process $appServer -Message ([ordered]@{
        method = 'initialize'
        id = 0
        params = [ordered]@{
            clientInfo = [ordered]@{
                name = 'cantor_swa05_probe'
                title = 'Cantor SWA-05 Probe'
                version = '0.1.0'
            }
            capabilities = [ordered]@{ experimentalApi = $true }
        }
    })
    [void](Read-AppServerUntilId -Process $appServer -Id 0 -Transcript $transcript)
    Send-AppServerMessage -Process $appServer -Message ([ordered]@{ method = 'initialized'; params = [ordered]@{} })
    Send-AppServerMessage -Process $appServer -Message ([ordered]@{ method = 'permissionProfile/list'; id = 1; params = [ordered]@{ cwd = $fixtureRoot } })
    [void](Read-AppServerUntilId -Process $appServer -Id 1 -Transcript $transcript)
    Send-AppServerMessage -Process $appServer -Message ([ordered]@{
        method = 'command/exec'
        id = 2
        params = [ordered]@{
            command = @('C:\Windows\System32\cmd.exe', '/d', '/c', 'type', $allowedPath)
            cwd = $fixtureRoot
            permissionProfile = 'swa05_probe'
            timeoutMs = 10000
        }
    })
    [void](Read-AppServerUntilId -Process $appServer -Id 2 -Transcript $transcript)
    Send-AppServerMessage -Process $appServer -Message ([ordered]@{
        method = 'command/exec'
        id = 3
        params = [ordered]@{
            command = @('C:\Windows\System32\cmd.exe', '/d', '/c', 'type', $deniedPath)
            cwd = $fixtureRoot
            permissionProfile = 'swa05_probe'
            timeoutMs = 10000
        }
    })
    [void](Read-AppServerUntilId -Process $appServer -Id 3 -Transcript $transcript)
}
finally {
    $appServer.StandardInput.Close()
    if (-not $appServer.WaitForExit(5000)) {
        $appServer.Kill($true)
        $appServer.WaitForExit()
    }
}
$appServerStderr = $appServer.StandardError.ReadToEnd()
if ($appServer.ExitCode -ne 0 -or $appServerStderr.Length -ne 0) {
    throw "App Server exit differs: exit=$($appServer.ExitCode) stderr=$appServerStderr"
}

$observation = [ordered]@{
    profile = 'cantor-self-work-update-broker-b1-permission-profile-observation/0.1'
    source_snapshot_uuid = $sourceSnapshotUuid
    predecessor_commit = $predecessorCommit
    historical_not_run = [ordered]@{
        profile = 'cantor-self-work-update-broker-b1-preflight-record/0.1'
        refusal_code = 'selected_schema_missing_read_scope_control'
        run_count = 0
        record_digest = 'b7d65c4877932aaf14a32e4e65d04f40e053af39435d56e8dedaad5d021816ad'
    }
    selected_executable = [ordered]@{
        path = $selectedItem.FullName
        bytes = [uint64]$selectedItem.Length
        sha256 = $selectedSha256
        version_output = $versionResult.stdout.Trim()
    }
    schema_generation = [ordered]@{
        standard = [ordered]@{
            argv = $standardArguments
            exit_code = $standardResult.exit_code
            stdout = $standardResult.stdout
            stderr = $standardResult.stderr
            evidence_file = 'standard_schema.json'
            bytes = [uint64](Get-Item -LiteralPath $standardSchemaEvidence).Length
            sha256 = Get-UpperSha256 -Path $standardSchemaEvidence
        }
        experimental = [ordered]@{
            argv = $experimentalArguments
            exit_code = $experimentalResult.exit_code
            stdout = $experimentalResult.stdout
            stderr = $experimentalResult.stderr
            evidence_file = 'experimental_schema.json'
            bytes = [uint64](Get-Item -LiteralPath $experimentalSchemaEvidence).Length
            sha256 = Get-UpperSha256 -Path $experimentalSchemaEvidence
        }
    }
    permission_profile = [ordered]@{
        id = 'swa05_probe'
        root_access = 'deny'
        minimal_access = 'read'
        fixture_root = $fixtureRoot
        fixture_access = 'read'
        denied_path = $deniedPath
        denied_access = 'deny'
        network_enabled = $false
        filesystem_override = $filesystemOverride
    }
    sentinels = [ordered]@{
        allowed_path = $allowedPath
        allowed_sha256 = Get-UpperSha256 -Path $allowedPath
        denied_path = $deniedPath
        denied_sha256 = Get-UpperSha256 -Path $deniedPath
    }
    transcript = $transcript.ToArray()
    boundaries = [ordered]@{
        writer_run_count = 0
        provider_contact_count = 0
        model_turn_count = 0
        mcp_call_count = 0
        git_command_count = 0
        remote_contact_count = 0
        d_drive_contact_count = 0
        product_mutation_count = 0
        cleanup_count = 0
        scratch_mutation_performed = $true
        service_network_observed = $false
        live_writer_allowed = $false
    }
}

$observationPath = Join-Path $evidenceRoot 'observation.json'
$json = ($observation | ConvertTo-Json -Depth 100).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($observationPath, $json, [Text.UTF8Encoding]::new($false))

$artifactPaths = @('experimental_schema.json', 'observation.json', 'standard_schema.json')
$artifacts = foreach ($artifactPath in $artifactPaths) {
    $fullPath = Join-Path $evidenceRoot $artifactPath
    [ordered]@{
        path = $artifactPath
        bytes = [uint64](Get-Item -LiteralPath $fullPath).Length
        sha256 = Get-UpperSha256 -Path $fullPath
    }
}
$manifest = [ordered]@{
    profile = 'cantor-self-work-update-broker-b1-permission-profile-evidence-manifest/0.1'
    source_snapshot_uuid = $sourceSnapshotUuid
    predecessor_commit = $predecessorCommit
    artifacts = @($artifacts)
}
$manifestPath = Join-Path $evidenceRoot 'manifest.json'
$manifestJson = ($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($manifestPath, $manifestJson, [Text.UTF8Encoding]::new($false))

$manifest
