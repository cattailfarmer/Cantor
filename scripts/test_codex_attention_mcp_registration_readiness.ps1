[CmdletBinding()]
param(
    [string]$ServerName = "cantor-attention",
    [string]$SshHost = "evo-x2",
    [string]$RemoteRoot = "C:\AI\services\cantor-attention-mcp",
    [string]$ExpectedBinarySha256 = "7d6bee8bbc0ac433012225f3921ca1979165582b75b6e63498411bd97f9a5a31",
    [string]$ExpectedConfigSha256 = "818a43df51b8bbfe4a7d8abe38458efbe4ad9c946dc0504d78f28e09f9ebf45c",
    [string]$ExpectedSharedSopAgentSha256 = "18ddea8f40cb3c4a75bb879379ea57ec85a60f6dd76fa75af9ca048117db4df8"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Text)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return ([Security.Cryptography.SHA256]::HashData($bytes) |
        ForEach-Object ToString x2) -join ""
}

function Assert-CanonicalDigest {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Name is not a lowercase canonical SHA-256 digest"
    }
}

Assert-CanonicalDigest -Name "ExpectedBinarySha256" -Value $ExpectedBinarySha256
Assert-CanonicalDigest -Name "ExpectedConfigSha256" -Value $ExpectedConfigSha256
Assert-CanonicalDigest -Name "ExpectedSharedSopAgentSha256" -Value $ExpectedSharedSopAgentSha256
if ($ServerName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw "ServerName is outside the closed MCP-name grammar"
}
if ($SshHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') {
    throw "SshHost is outside the closed host-alias grammar"
}
if ($RemoteRoot -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9._\\-]+$') {
    throw "RemoteRoot is outside the closed absolute Windows-path grammar"
}

$codexCommand = Get-Command codex.cmd -ErrorAction Stop
$sshCommand = Get-Command ssh.exe -ErrorAction Stop
$codexVersion = (& $codexCommand.Source --version | Out-String).Trim()
$inventory = (& $codexCommand.Source mcp list | Out-String).Replace("`r`n", "`n")
$escapedName = [Regex]::Escape($ServerName)
$nameCollision = $inventory -match "(?m)^$escapedName\s"
if ($nameCollision) {
    throw "MCP server name '$ServerName' is already configured; readiness cannot imply replacement"
}

$remoteBinary = "$RemoteRoot\cantor-attention-mcp.exe"
$remoteConfig = "$RemoteRoot\config.json"
$remoteManifest = "$RemoteRoot\deployment_manifest.json"
$remoteScript = @'
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$requestedRoot = "__REMOTE_ROOT__"
$resolvedRoot = (Resolve-Path -LiteralPath $requestedRoot).Path
if ($resolvedRoot -ne $requestedRoot) {
    throw "remote root identity mismatch"
}
$llama = Get-Process llama-server -ErrorAction Stop | Select-Object -First 1
$attention = @(Get-Process cantor-attention-mcp -ErrorAction SilentlyContinue)
[pscustomobject]@{
    computer = $env:COMPUTERNAME
    resolved_root = $resolvedRoot
    binary_bytes = (Get-Item -LiteralPath "__REMOTE_BINARY__").Length
    binary_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath "__REMOTE_BINARY__").Hash.ToLowerInvariant()
    config_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath "__REMOTE_CONFIG__").Hash.ToLowerInvariant()
    deployment_manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath "__REMOTE_MANIFEST__").Hash.ToLowerInvariant()
    attention_process_count = $attention.Count
    llama_pid = $llama.Id
    shared_sop_agent_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath C:\AI\services\sop-agent\sop_agent.py).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
'@
$remoteScript = $remoteScript.Replace("__REMOTE_ROOT__", $RemoteRoot)
$remoteScript = $remoteScript.Replace("__REMOTE_BINARY__", $remoteBinary)
$remoteScript = $remoteScript.Replace("__REMOTE_CONFIG__", $remoteConfig)
$remoteScript = $remoteScript.Replace("__REMOTE_MANIFEST__", $remoteManifest)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remoteScript))
$remoteLines = @(& $sshCommand.Source -T $SshHost powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded)
if ($LASTEXITCODE -ne 0) {
    throw "remote readiness observation failed with ssh exit code $LASTEXITCODE"
}
$remoteJson = $remoteLines | Where-Object { $_ -match '^\{.*\}$' } | Select-Object -Last 1
if (-not $remoteJson) {
    throw "remote readiness observation did not return one JSON object"
}
$remote = $remoteJson | ConvertFrom-Json

if ($remote.binary_sha256 -cne $ExpectedBinarySha256) {
    throw "remote adapter binary differs from the reviewed identity"
}
if ($remote.config_sha256 -cne $ExpectedConfigSha256) {
    throw "remote adapter config differs from the reviewed identity"
}
if ($remote.shared_sop_agent_sha256 -cne $ExpectedSharedSopAgentSha256) {
    throw "shared SOP agent changed across the reviewed boundary"
}
if ($remote.attention_process_count -ne 0) {
    throw "a cantor-attention-mcp process is already active; retry only after investigating ownership"
}

$launchArguments = @(
    "-T",
    $SshHost,
    $remoteBinary,
    "--config",
    $remoteConfig
)
$registrationCommand = "codex.cmd mcp add $ServerName -- ssh.exe " +
    (($launchArguments | ForEach-Object { $_ }) -join " ")
$removalCommand = "codex.cmd mcp remove $ServerName"

[pscustomobject]@{
    profile = "cantor-codex-attention-mcp-registration-readiness/0.1"
    status = "ready_without_registration"
    codex_path = $codexCommand.Source
    codex_version = $codexVersion
    server_name = $ServerName
    name_collision = $false
    inventory_sha256 = Get-Sha256Text -Text $inventory
    remote = $remote
    launch = [pscustomobject]@{
        program = $sshCommand.Source
        arguments = $launchArguments
    }
    registration_command = $registrationCommand
    removal_command = $removalCommand
    configuration_changed = $false
} | ConvertTo-Json -Depth 6
