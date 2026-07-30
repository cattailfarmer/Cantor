[CmdletBinding()]
param(
    [string]$ServerPath,
    [string]$ModelPath = 'C:\Users\enjer\.lmstudio\models\lmstudio-community\gpt-oss-20b-GGUF\gpt-oss-20b-MXFP4.gguf',
    [int]$Port = 8080
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $PSScriptRoot '..\.local\llama.cpp\b10181\llama-server.exe'
}

$resolvedServer = (Resolve-Path -LiteralPath $ServerPath).Path
$resolvedModel = (Resolve-Path -LiteralPath $ModelPath).Path
$serverDirectory = Split-Path -Parent $resolvedServer
$env:PATH = "$serverDirectory;$env:PATH"

Write-Host "Starting llama.cpp on http://127.0.0.1:$Port with model $resolvedModel"
& $resolvedServer `
    --model $resolvedModel `
    --alias 'gpt-oss-20b' `
    --host '127.0.0.1' `
    --port $Port `
    --jinja `
    --flash-attn on `
    --n-gpu-layers 99 `
    --ctx-size 8192 `
    --parallel 1
