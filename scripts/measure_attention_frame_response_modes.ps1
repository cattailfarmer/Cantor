[CmdletBinding()]
param(
    [string]$SshHost = "evo-x2",
    [string]$RemoteRoot = "C:\AI\services\cantor-attention-mcp",
    [double]$MinimumRatio = 3.0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($SshHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') {
    throw "SshHost is outside the closed host-alias grammar"
}
if ($RemoteRoot -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9._\\-]+$') {
    throw "RemoteRoot is outside the closed absolute Windows-path grammar"
}
if (-not [double]::IsFinite($MinimumRatio) -or $MinimumRatio -le 0) {
    throw "MinimumRatio must be finite and greater than zero"
}

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$readinessScript = Join-Path $PSScriptRoot "test_codex_attention_mcp_registration_readiness.ps1"
$readiness = & $readinessScript -SshHost $SshHost -RemoteRoot $RemoteRoot | ConvertFrom-Json
if ($readiness.status -ne "ready_without_registration" -or $readiness.configuration_changed) {
    throw "attention MCP deployment is not in the reviewed unregistered readiness state"
}

Push-Location $workspaceRoot
try {
    & cargo build -p cantor_attention_mcp --example live_probe --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "live_probe build failed"
    }
    $probe = Join-Path $workspaceRoot "target\debug\examples\live_probe.exe"
    $remoteBinary = "$RemoteRoot\cantor-attention-mcp.exe"
    $remoteConfig = "$RemoteRoot\config.json"
    $baseArguments = @(
        "ssh.exe", "-T", $SshHost, $remoteBinary, "--config", $remoteConfig, "--stimulus"
    )
    $cases = @(
        [pscustomobject]@{ case_id = "resolve"; stimulus = "What is Cantor?" },
        [pscustomobject]@{ case_id = "identity"; stimulus = "Identity boundary review; subject: cantor; claim: unsigned oracle authority." },
        [pscustomobject]@{ case_id = "transition"; stimulus = "Attention transition review for Cantor; before_frame is signed query boundary; after_frame is unsigned semantic authority." }
    )
    $measurements = foreach ($case in $cases) {
        $fullRaw = & $probe @baseArguments $case.stimulus
        if ($LASTEXITCODE -ne 0) {
            throw "full live probe failed for $($case.case_id)"
        }
        $frameRaw = & $probe @baseArguments $case.stimulus --response-mode frame
        if ($LASTEXITCODE -ne 0) {
            throw "frame live probe failed for $($case.case_id)"
        }
        $full = $fullRaw | ConvertFrom-Json
        $frame = $frameRaw | ConvertFrom-Json
        $fullBytes = [Text.Encoding]::UTF8.GetByteCount(
            ($full | ConvertTo-Json -Depth 20 -Compress)
        )
        $frameBytes = [Text.Encoding]::UTF8.GetByteCount(
            ($frame | ConvertTo-Json -Depth 20 -Compress)
        )
        $ratio = [math]::Round($fullBytes / $frameBytes, 4)
        if ($ratio -lt $MinimumRatio) {
            throw "$($case.case_id) response ratio $ratio is below required $MinimumRatio"
        }
        $framePropertyNames = @($frame.PSObject.Properties.Name)
        if ($framePropertyNames -contains "runtime" -or
            $framePropertyNames -contains "verification") {
            throw "$($case.case_id) frame response retained a full proof record"
        }
        if ((@($frame.attention_frame.sequence.operator) -join ",") -ne "FOCUS,BOUND,ADMIT,RETURN") {
            throw "$($case.case_id) frame operator sequence differs"
        }
        [pscustomobject]@{
            case_id = $case.case_id
            procedure_id = $full.runtime.procedure_id
            full_run_id = $full.runtime.run_id
            frame_run_id = $frame.attention_frame.sequence[3].evidence_id
            full_utf8_bytes = $fullBytes
            frame_utf8_bytes = $frameBytes
            ratio = $ratio
        }
    }
} finally {
    Pop-Location
}

$ratios = @($measurements.ratio)
[pscustomobject]@{
    profile = "cantor-attention-frame-response-mode-measurement/0.1"
    captured_at = (Get-Date).ToString("o")
    status = "passed"
    minimum_required_ratio = $MinimumRatio
    deployment_binary_sha256 = $readiness.remote.binary_sha256
    deployment_manifest_sha256 = $readiness.remote.deployment_manifest_sha256
    cases = @($measurements)
    summary = [pscustomobject]@{
        case_count = @($measurements).Count
        minimum_ratio = ($ratios | Measure-Object -Minimum).Minimum
        maximum_ratio = ($ratios | Measure-Object -Maximum).Maximum
    }
    configuration_changed = $false
} | ConvertTo-Json -Depth 6
