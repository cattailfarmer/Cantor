[CmdletBinding()]
param(
    [string]$SshHost = "evo-x2",
    [string]$RemoteRoot = "C:\AI\services\cantor-reflection-loop",
    [string]$RemoteBinaryName = "cantor-reflection-loop-v15.exe",
    [string]$ExpectedLoopSha256 = "b1ba0fd7b9700b79ea40eb08de6e77e31207fb860dbeb01d00287c393e6741c3",
    [string]$ExpectedMcpSha256 = "37860b031a97b58de08cb669cf6b09b3bbac3db12c3fba3f198674231255deef",
    [string]$ExpectedMcpConfigSha256 = "818a43df51b8bbfe4a7d8abe38458efbe4ad9c946dc0504d78f28e09f9ebf45c",
    [string]$LocalOutput = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($SshHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') {
    throw "SshHost is outside the closed host-alias grammar"
}
if ($RemoteRoot -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9._\\-]+$') {
    throw "RemoteRoot is outside the closed absolute Windows-path grammar"
}
if ($RemoteBinaryName -cnotmatch '^[A-Za-z0-9._-]+\.exe$') {
    throw "RemoteBinaryName is outside the closed executable-leaf grammar"
}
foreach ($digest in @($ExpectedLoopSha256, $ExpectedMcpSha256, $ExpectedMcpConfigSha256)) {
    if ($digest -cnotmatch '^[0-9a-f]{64}$') {
        throw "Expected digest is not lowercase SHA-256"
    }
}

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$runIdentity = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$defaultOutput = [string]::IsNullOrWhiteSpace($LocalOutput)
if ($defaultOutput) {
    $LocalOutput = ".local\cantor-reflection-loop\script_run_$runIdentity.json"
}
$outputPath = [IO.Path]::GetFullPath((Join-Path $workspaceRoot $LocalOutput))
if (-not $outputPath.StartsWith($workspaceRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "LocalOutput must resolve beneath the Cantor workspace"
}
$outputParent = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    if (-not $defaultOutput) {
        throw "LocalOutput parent does not exist"
    }
    $null = New-Item -ItemType Directory -Path $outputParent -Force
}
if (Test-Path -LiteralPath $outputPath) {
    throw "LocalOutput already exists; choose a new evidence path"
}

$remoteBinary = "$RemoteRoot\$RemoteBinaryName"
$remoteProcessName = [IO.Path]::GetFileNameWithoutExtension($RemoteBinaryName)
$remoteMcp = "C:\AI\services\cantor-attention-mcp\cantor-attention-mcp.exe"
$remoteMcpConfig = "C:\AI\services\cantor-attention-mcp\config.json"
$remoteOutput = "$RemoteRoot\script_run_$runIdentity.json"

function Get-RemoteAudit {
    $auditScript = @"
`$ProgressPreference = 'SilentlyContinue'
`$llama = @(Get-Process -Name 'llama-server' -ErrorAction Stop)
if (`$llama.Count -ne 1) { throw 'expected exactly one llama-server process' }
`$adapterCount = @(Get-Process -Name 'cantor-attention-mcp' -ErrorAction SilentlyContinue).Count
`$loopCount = @(Get-Process -Name '$remoteProcessName' -ErrorAction SilentlyContinue).Count
`$loopPath = '$remoteBinary'
`$mcpPath = '$remoteMcp'
`$configPath = '$remoteMcpConfig'
[pscustomobject]@{
    llama_pid = `$llama[0].Id
    llama_start = `$llama[0].StartTime.ToString('o')
    adapter_processes = `$adapterCount
    loop_processes = `$loopCount
    loop_sha256 = (Get-FileHash -LiteralPath `$loopPath -Algorithm SHA256).Hash.ToLowerInvariant()
    mcp_sha256 = (Get-FileHash -LiteralPath `$mcpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    mcp_config_sha256 = (Get-FileHash -LiteralPath `$configPath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($auditScript))
    $raw = & ssh.exe -T $SshHost powershell.exe -NoProfile -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) {
        throw "remote process and digest audit failed"
    }
    return ($raw | ConvertFrom-Json)
}

$before = Get-RemoteAudit
if ($before.adapter_processes -ne 0 -or $before.loop_processes -ne 0) {
    throw "prototype dependencies are not idle before the run"
}
if ($before.loop_sha256 -cne $ExpectedLoopSha256 -or
    $before.mcp_sha256 -cne $ExpectedMcpSha256 -or
    $before.mcp_config_sha256 -cne $ExpectedMcpConfigSha256) {
    throw "remote deployment identity differs from the reviewed digest set"
}

$runArguments = @(
    "-T", $SshHost, $remoteBinary,
    "--base-url", "http://127.0.0.1:8081/v1",
    "--mcp-program", $remoteMcp,
    "--mcp-config", $remoteMcpConfig,
    "--case", "all",
    "--output", $remoteOutput,
    "--timeout-seconds", "180"
)
& ssh.exe @runArguments
$runExit = $LASTEXITCODE

$verifyArguments = @("-T", $SshHost, $remoteBinary, "verify", "--report", $remoteOutput)
$verificationRaw = & ssh.exe @verifyArguments
$verifyExit = $LASTEXITCODE

$after = Get-RemoteAudit
if ($after.llama_pid -ne $before.llama_pid -or $after.llama_start -ne $before.llama_start) {
    throw "llama.cpp process identity changed during the prototype run"
}
if ($after.adapter_processes -ne 0 -or $after.loop_processes -ne 0) {
    throw "an ephemeral prototype process remained after the run"
}
if ($after.loop_sha256 -cne $before.loop_sha256 -or
    $after.mcp_sha256 -cne $before.mcp_sha256 -or
    $after.mcp_config_sha256 -cne $before.mcp_config_sha256) {
    throw "deployment identity changed during the prototype run"
}

& scp.exe "${SshHost}:$($remoteOutput.Replace('\', '/'))" $outputPath
if ($LASTEXITCODE -ne 0) {
    throw "failed to retrieve the sanitized prototype report"
}
$report = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
$verification = $verificationRaw | ConvertFrom-Json
if ($runExit -ne 0 -or $verifyExit -ne 0 -or $report.status -ne "passed" -or $verification.status -ne "verified") {
    throw "prototype run or independent verification failed; report preserved at $outputPath"
}

[pscustomobject]@{
    profile = "cantor-reflection-loop-reproduction/0.1"
    status = "passed"
    report = $outputPath
    report_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    verification = $verification
    before = $before
    after = $after
    configuration_changed = $false
} | ConvertTo-Json -Depth 8
