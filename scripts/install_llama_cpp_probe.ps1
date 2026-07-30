[CmdletBinding()]
param(
    [string]$Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $PSScriptRoot '..\.local\llama.cpp\b10181'
}

$releaseTag = 'b10181'
$serverArchive = 'llama-b10181-bin-win-cuda-12.4-x64.zip'
$serverSha256 = '5eefa7164e1969620e1337114a211c93be7b6b5631e3032a1a26b89df8e80020'
$runtimeArchive = 'cudart-llama-bin-win-cuda-12.4-x64.zip'
$runtimeSha256 = '8c79a9b226de4b3cacfd1f83d24f962d0773be79f1e7b75c6af4ded7e32ae1d6'
$releaseBase = "https://github.com/ggml-org/llama.cpp/releases/download/$releaseTag"

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$downloadPath = Join-Path $destinationPath '.downloads'
New-Item -ItemType Directory -Force -Path $destinationPath, $downloadPath | Out-Null

$archives = @(
    @{
        Name = $serverArchive
        Hash = $serverSha256
    },
    @{
        Name = $runtimeArchive
        Hash = $runtimeSha256
    }
)

foreach ($archive in $archives) {
    $archivePath = Join-Path $downloadPath $archive.Name
    if (-not (Test-Path -LiteralPath $archivePath)) {
        Write-Host "Downloading $($archive.Name)..."
        Invoke-WebRequest -Uri "$releaseBase/$($archive.Name)" -OutFile $archivePath
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $archive.Hash) {
        throw "SHA-256 mismatch for $($archive.Name): expected $($archive.Hash), received $actualHash"
    }

    Write-Host "Verified $($archive.Name); extracting..."
    Expand-Archive -LiteralPath $archivePath -DestinationPath $destinationPath -Force
}

$serverPath = Join-Path $destinationPath 'llama-server.exe'
if (-not (Test-Path -LiteralPath $serverPath)) {
    throw "The verified archives did not produce $serverPath"
}

Write-Host "Installed pinned llama.cpp server at $serverPath"
