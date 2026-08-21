[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:8080/v1',
    [string]$Model = 'gpt-oss-20b',
    [string]$ExpectedModelPath = 'C:\Users\enjer\.lmstudio\models\lmstudio-community\gpt-oss-20b-GGUF\gpt-oss-20b-MXFP4.gguf',
    [ValidateRange(1, 8)]
    [int]$Trials = 2,
    [ValidateRange(0, 2)]
    [int]$Warmups = 1,
    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 180,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$experimentManifest = Join-Path $repositoryRoot 'experiments\llama_tool_reflection\Cargo.toml'
$executableSuffix = if ($IsWindows) { '.exe' } else { '' }
$statelessBinary = Join-Path $repositoryRoot "target\debug\cantor-compiler-mcp$executableSuffix"
$custodyBinary = Join-Path $repositoryRoot "target\debug\cantor-compiler-custody-mcp$executableSuffix"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $OutputPath = Join-Path $repositoryRoot "experiments\llama_tool_reflection\artifacts\lifecycle_tool_loop\run_$stamp.json"
}
else {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
}

Push-Location $repositoryRoot
try {
    & cargo build -p cantor_compiler_mcp -p cantor_compiler_custody_mcp --locked --offline
    if ($LASTEXITCODE -ne 0) {
        throw 'MCP subprocess build failed'
    }
    & cargo run --manifest-path $experimentManifest --bin cantor-lifecycle-tool-loop --locked --offline -- `
        --base-url $BaseUrl `
        --model $Model `
        --expected-model-path $ExpectedModelPath `
        --stateless-mcp-bin $statelessBinary `
        --custody-mcp-bin $custodyBinary `
        --output $OutputPath `
        --timeout-seconds $TimeoutSeconds `
        --trials $Trials `
        --warmups $Warmups
    $measurementExit = $LASTEXITCODE
}
finally {
    Pop-Location
}

Write-Output "lifecycle_tool_loop_output=$OutputPath"
exit $measurementExit
