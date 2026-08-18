param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("health", "list", "run", "evaluate", "verify")]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$Text,

    [switch]$RouteOnly
)

$ErrorActionPreference = "Stop"
$runtimeRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $runtimeRoot ".venv\Scripts\python.exe"
$controller = Join-Path $runtimeRoot "cantor_needle_runtime.py"
$config = Join-Path $runtimeRoot "config.json"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Needle runtime Python was not found at $python"
}

$arguments = @($controller, "--config", $config, $Command)
if ($Command -eq "run") {
    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "run requires stimulus text"
    }
    $arguments += @("--text", $Text)
    if ($RouteOnly) {
        $arguments += "--route-only"
    }
}
elseif ($Command -eq "verify") {
    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "verify requires a run or evaluation UUID"
    }
    $arguments += @("--id", $Text)
}

& $python @arguments
exit $LASTEXITCODE
