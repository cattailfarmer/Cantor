[CmdletBinding()]
param(
    [ValidateSet('test', 'clippy')]
    [string]$Action = 'test',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distro = 'Ubuntu-24.04',

    [string]$TargetDir = '/home/pinky/.cache/cantor-workspace-verification',

    [ValidateRange(1, 1048576)]
    [uint64]$MinimumFreeGiB = 40,

    [ValidateRange(1, 1048575)]
    [uint64]$ReserveFreeGiB = 8,

    [ValidateRange(1, 10)]
    [uint16]$MonitorIntervalSeconds = 2,

    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$profile = 'cantor-bounded-workspace-verification/0.2'
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
$reserveFreeBytes = [decimal]$ReserveFreeGiB * 1GB
if ($minimumFreeBytes -le $reserveFreeBytes) {
    throw 'MinimumFreeGiB must be strictly greater than ReserveFreeGiB'
}
$capacitySufficient = $freeBytes -ge $minimumFreeBytes
$windowsVolumeMount = "/mnt/$($driveName.ToLowerInvariant())"

$cargoCommand = switch ($Action) {
    'test' {
        'run_with_capacity_guard cargo test --workspace --all-features --locked --no-fail-fast --quiet -- --test-threads=1'
    }
    'clippy' {
        'run_with_capacity_guard cargo clippy --workspace --all-targets --all-features --locked --quiet'
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
    'export CARGO_INCREMENTAL=0'
    'export CARGO_PROFILE_TEST_DEBUG=0'
    'export CARGO_PROFILE_DEV_DEBUG=0'
    'export LC_ALL=C'
    $(if ($Action -eq 'clippy') { 'export RUSTFLAGS="-D warnings"' })
    'run_with_capacity_guard() {'
    '  "$@" &'
    '  child_pid=$!'
    '  while kill -0 "$child_pid" 2>/dev/null; do'
    "    available_bytes=`$(df -PB1 '$windowsVolumeMount' | awk 'NR == 2 { print `$4 }')"
    '    if ! [[ "$available_bytes" =~ ^[0-9]+$ ]]; then'
    '      kill -INT "$child_pid" 2>/dev/null || true'
    '      wait "$child_pid" 2>/dev/null || true'
    "      echo 'capacity_monitor_fault: unable to read numeric available bytes from $windowsVolumeMount' >&2"
    '      return 74'
    '    fi'
    "    if [ `$available_bytes -lt '$([uint64]$reserveFreeBytes)' ]; then"
    '      kill -INT "$child_pid" 2>/dev/null || true'
    '      wait "$child_pid" 2>/dev/null || true'
    "      echo 'capacity_guard_fault: available bytes crossed below reserve $([uint64]$reserveFreeBytes)' >&2"
    '      return 73'
    '    fi'
    "    sleep '$MonitorIntervalSeconds'"
    '  done'
    '  wait "$child_pid"'
    '}'
    $cargoCommand
) | Where-Object { $_ }
$bashCommand = $bashCommand -join "`n"
$bashCommandBytes = [System.Text.Encoding]::UTF8.GetBytes($bashCommand)
$bashTransportPayload = [Convert]::ToBase64String($bashCommandBytes)
$bashTransportCommand =
    "set -o pipefail; printf '%s' '$bashTransportPayload' | base64 --decode | bash"

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
    windows_volume_mount = $windowsVolumeMount
    free_bytes = $freeBytes
    minimum_free_gib = $MinimumFreeGiB
    minimum_free_bytes = [uint64]$minimumFreeBytes
    reserve_free_gib = $ReserveFreeGiB
    reserve_free_bytes = [uint64]$reserveFreeBytes
    monitor_interval_seconds = $MonitorIntervalSeconds
    capacity_sufficient = $capacitySufficient
    cargo_build_jobs = 1
    test_threads = 1
    cargo_incremental = 0
    cargo_profile_test_debug = 0
    cargo_profile_dev_debug = 0
    capacity_guard_exit_code = 73
    capacity_monitor_exit_code = 74
    remote_hosts = @()
    destructive_actions = @()
    automatic_cleanup = $false
    bash_command = $bashCommand
    bash_transport_encoding = 'utf8-base64'
    bash_transport_payload = $bashTransportPayload
    bash_transport_command = $bashTransportCommand
}

$plan | ConvertTo-Json -Depth 4

if (-not $Execute) {
    return
}

if (-not $capacitySufficient) {
    throw "capacity_fault: $freeBytes free bytes is below the declared startup threshold $minimumFreeBytes"
}

$installedDistros = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Trim("`0 ") } | Where-Object { $_ }
if ($LASTEXITCODE -ne 0) {
    throw 'wsl_fault: unable to list installed distributions'
}
if ($installedDistros -notcontains $Distro) {
    throw "wsl_fault: distribution is not installed: $Distro"
}

& wsl.exe -d $Distro --cd $repositoryRoot -- bash -lc $bashTransportCommand
$childExitCode = $LASTEXITCODE
if ($childExitCode -eq 73) {
    throw 'capacity_guard_fault: child interrupted after crossing the declared runtime reserve'
}
if ($childExitCode -eq 74) {
    throw 'capacity_monitor_fault: child interrupted after capacity observation became unreadable'
}
if ($childExitCode -ne 0) {
    throw "verification_fault: child exited with status $childExitCode"
}
return
