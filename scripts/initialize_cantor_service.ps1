param(
    [Parameter(Mandatory = $true)]
    [string]$EnvironmentPath,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeDirectory,

    [string]$AllowedEnvironmentRoot,

    [string]$ListenAddress = "127.0.0.1:39841",

    [switch]$Replace
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$environmentFullPath = [IO.Path]::GetFullPath($EnvironmentPath)
if (-not [IO.File]::Exists($environmentFullPath)) {
    throw "EnvironmentPath must identify an existing file"
}
$runtimeFullPath = [IO.Path]::GetFullPath($RuntimeDirectory)
[IO.Directory]::CreateDirectory($runtimeFullPath) | Out-Null
$allowedRoot = if ([string]::IsNullOrWhiteSpace($AllowedEnvironmentRoot)) {
    [IO.Path]::GetDirectoryName($environmentFullPath)
}
else {
    [IO.Path]::GetFullPath($AllowedEnvironmentRoot)
}
if (-not [IO.Directory]::Exists($allowedRoot)) {
    throw "AllowedEnvironmentRoot must identify an existing directory"
}
$rootPrefix = $allowedRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (
    -not $environmentFullPath.Equals($allowedRoot, [StringComparison]::OrdinalIgnoreCase) -and
    -not $environmentFullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
) {
    throw "EnvironmentPath must be contained by AllowedEnvironmentRoot"
}

$tokenPath = [IO.Path]::Combine($runtimeFullPath, "cantord.token")
$activationPath = [IO.Path]::Combine($runtimeFullPath, "activation.json")
$configPath = [IO.Path]::Combine($runtimeFullPath, "service.json")
$targets = @($tokenPath, $activationPath, $configPath)
if (-not $Replace -and ($targets | Where-Object { [IO.File]::Exists($_) })) {
    throw "Service artifacts already exist; use -Replace only after reviewing the target directory"
}

$random = [Security.Cryptography.RandomNumberGenerator]::Create()
$tokenBytes = [byte[]]::new(32)
try {
    $random.GetBytes($tokenBytes)
}
finally {
    $random.Dispose()
}
$token = ([BitConverter]::ToString($tokenBytes)).Replace("-", "").ToLowerInvariant()

$activation = [ordered]@{
    schema = "cantor-environment-activation/0.1"
    sequence = 1
    environment_path = $environmentFullPath
    environment_file_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $environmentFullPath).Hash.ToLowerInvariant()
}
$config = [ordered]@{
    schema = "cantor-service-config/0.1"
    listen_address = $ListenAddress
    activation_path = $activationPath
    allowed_environment_root = $allowedRoot
    auth_token_path = $tokenPath
    max_frame_bytes = 1048576
    max_connections = 32
    read_timeout_ms = 5000
    write_timeout_ms = 5000
}

function Write-AtomicUtf8 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    $temporary = "$Path.tmp-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if ([IO.File]::Exists($temporary)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

Write-AtomicUtf8 -Path $tokenPath -Text "$token`n"
Write-AtomicUtf8 -Path $activationPath -Text "$($activation | ConvertTo-Json -Depth 5)`n"
Write-AtomicUtf8 -Path $configPath -Text "$($config | ConvertTo-Json -Depth 5)`n"

[ordered]@{
    service_config = $configPath
    activation = $activationPath
    token = $tokenPath
    environment = $environmentFullPath
    listen_address = $ListenAddress
} | ConvertTo-Json
