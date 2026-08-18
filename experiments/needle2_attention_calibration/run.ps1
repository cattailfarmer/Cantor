param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("health", "run", "verify")]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$EvidenceId
)

$ErrorActionPreference = "Stop"
$calibrationRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$runtimePython = "C:\AI\services\cantor-needle-runtime\.venv\Scripts\python.exe"
$controller = Join-Path $calibrationRoot "calibrate_attention_language.py"
$config = Join-Path $calibrationRoot "config.json"

if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
    throw "Pinned runtime Python was not found at $runtimePython"
}

$arguments = @($controller, "--config", $config, $Command)
if ($Command -eq "verify") {
    if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
        throw "verify requires a calibration UUID"
    }
    $arguments += @("--id", $EvidenceId)
}

& $runtimePython @arguments
exit $LASTEXITCODE
