[CmdletBinding()]
param(
    [ValidateSet('test', 'clippy')]
    [string]$Action = 'test',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distro = 'Ubuntu-24.04',

    [string]$TargetDir = '/home/pinky/.cache/cantor-workspace-verification',

    [ValidateRange(1, 1048576)]
    [uint64]$MinimumFreeGiB = 20,

    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$profile = 'cantor-bounded-workspace-verification/0.1'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceManifest = Join-Path $repositoryRoot 'Cargo.toml'
if (-not (Test-Path -LiteralPath $workspaceManifest -PathType Leaf)) {
    throw "repository root does not contain Cargo.toml: $repositoryRoot"
}

if ($TargetDir -notmatch '^/home/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$' -or
    $TargetDir.EndsWith('/') -or
    ($TargetDir -split '/') -contains '..') {
    throw 'TargetDir must be a conservative absolute /home/USER path without a trailing slash or parent traversal'
}

$volumeRoot = [System.IO.Path]::GetPathRoot($repositoryRoot)
$driveName = $volumeRoot.Substring(0, 1)
$drive = Get-PSDrive -Name $driveName -PSProvider FileSystem
$freeBytes = [uint64]$drive.Free
$minimumFreeBytes = [decimal]$MinimumFreeGiB * 1GB

$cargoCommand = switch ($Action) {
    'test' {
        'cargo test --workspace --all-features --locked --no-fail-fast --quiet -- --test-threads=1'
    }
    'clippy' {
        'RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --all-features --locked --quiet'
    }
}

$temporaryDir = "$TargetDir-tmp"
$verificationBin = "$TargetDir-bin"
$bashCommand = @(
    'set -euo pipefail'
    "mkdir -p '$TargetDir' '$temporaryDir' '$verificationBin'"
    "ln -sf /usr/bin/python3 '$verificationBin/python'"
    "export PATH='$verificationBin':`$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    "export TMPDIR='$temporaryDir'"
    "export CARGO_TARGET_DIR='$TargetDir'"
    'export CARGO_BUILD_JOBS=1'
    $cargoCommand
) -join '; '

$plan = [ordered]@{
    profile = $profile
    repository_root = $repositoryRoot
    action = $Action
    execute = [bool]$Execute
    distro = $Distro
    target_dir = $TargetDir
    temporary_dir = $temporaryDir
    verification_bin = $verificationBin
    system_volume = $volumeRoot
    free_bytes = $freeBytes
    minimum_free_gib = $MinimumFreeGiB
    minimum_free_bytes = [uint64]$minimumFreeBytes
    cargo_build_jobs = 1
    test_threads = 1
    remote_hosts = @()
    destructive_actions = @()
    automatic_cleanup = $false
    bash_command = $bashCommand
}

$plan | ConvertTo-Json -Depth 4

if ($freeBytes -lt $minimumFreeBytes) {
    throw "capacity_fault: $freeBytes free bytes is below the declared threshold $minimumFreeBytes"
}

if (-not $Execute) {
    return
}

$installedDistros = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Trim("`0 ") } | Where-Object { $_ }
if ($LASTEXITCODE -ne 0) {
    throw 'wsl_fault: unable to list installed distributions'
}
if ($installedDistros -notcontains $Distro) {
    throw "wsl_fault: distribution is not installed: $Distro"
}

& wsl.exe -d $Distro --cd $repositoryRoot -- bash -lc $bashCommand
$childExitCode = $LASTEXITCODE
if ($childExitCode -ne 0) {
    throw "verification_fault: child exited with status $childExitCode"
}
return
