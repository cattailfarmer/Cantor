param(
    [Parameter(Mandatory = $true)]
    [string]$ActivationPath,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentPath,

    [Parameter(Mandatory = $true)]
    [UInt64]$Sequence
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$activationFullPath = [IO.Path]::GetFullPath($ActivationPath)
$environmentFullPath = [IO.Path]::GetFullPath($EnvironmentPath)
if (-not [IO.File]::Exists($activationFullPath)) {
    throw "ActivationPath must identify an existing activation descriptor"
}
if (-not [IO.File]::Exists($environmentFullPath)) {
    throw "EnvironmentPath must identify an existing environment file"
}
$current = Get-Content -LiteralPath $activationFullPath -Raw | ConvertFrom-Json
if ($current.schema -ne "cantor-environment-activation/0.1") {
    throw "Existing activation descriptor uses an unsupported schema"
}
if ($Sequence -le [UInt64]$current.sequence) {
    throw "Sequence must be greater than the current activation sequence"
}

$activation = [ordered]@{
    schema = "cantor-environment-activation/0.1"
    sequence = $Sequence
    environment_path = $environmentFullPath
    environment_file_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $environmentFullPath).Hash.ToLowerInvariant()
}
$temporary = "$activationFullPath.tmp-$([guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText(
        $temporary,
        "$($activation | ConvertTo-Json -Depth 5)`n",
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporary -Destination $activationFullPath -Force
}
finally {
    if ([IO.File]::Exists($temporary)) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

$activation | ConvertTo-Json
