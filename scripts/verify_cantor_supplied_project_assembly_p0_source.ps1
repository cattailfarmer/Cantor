param(
    [string]$LiveRoot = "C:\Project\Cantor",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($LiveRoot)
$expectedHead = "82a3e19b839fd4e937ecb1f366859289364529c0"
$protectedRelative = "narrative/turns/1786911720465_minecraftgenie_scope_handoff_negotiation.sop"
$protectedBytes = 1805
$protectedSha256 = "5b806e8d078c03d189021d0bb458ea42ade3508e04677387d9ab9966dadc6f07"
$expected = @(
    [ordered]@{ path = "crates/cantor_scribe/src/project.rs"; bytes = 7643; sha256 = "b6a98980486796c8e75c09f7832ce783d0c4115c88932e1b652a04e6fce9ec8a" },
    [ordered]@{ path = "crates/cantor_scribe/tests/authoring.rs"; bytes = 6740; sha256 = "3789d8b9c6fbc8638aff528afa10ee71729ad9d751a9aaa3134b8a4487aadaf9" },
    [ordered]@{ path = "crates/cantor_scribe/examples/study/project.json"; bytes = 501; sha256 = "7a789b8fc156d1b8c070aa43a04fb5b8a83cf2d0a7edabfee36b9580c5955233" },
    [ordered]@{ path = "crates/cantor_scribe/examples/study/foundation.sop"; bytes = 874; sha256 = "6e711afa4821d840481486b0191120c7b290f2d97d4e4026df17ae382a408779" },
    [ordered]@{ path = "crates/cantor_scribe/examples/study/site.sop"; bytes = 1496; sha256 = "573a72b31b7e4aac0a8fbff87393318b1f095e9fe97704a0b6559d36690d1aee" }
)

if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "live source root is absent: $root" }
$head = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $expectedHead) { throw "live source head differs: $head" }

$observed = @()
$selectedByteCount = [int64]0
foreach ($item in $expected) {
    $path = Join-Path $root ([string]$item.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "selected live source is absent: $($item.path)" }
    $bytes = (Get-Item -LiteralPath $path).Length
    $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bytes -ne [int64]$item.bytes -or $sha256 -cne [string]$item.sha256) { throw "selected live source identity differs: $($item.path)" }
    $observed += [ordered]@{ path = [string]$item.path; bytes = [int64]$bytes; sha256 = [string]$sha256 }
    $selectedByteCount += [int64]$bytes
}

$protectedPath = Join-Path $root $protectedRelative
if (-not (Test-Path -LiteralPath $protectedPath -PathType Leaf)) { throw "protected foreign narrative is absent" }
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) { throw "protected foreign narrative identity differs" }

$trackedStatus = @(& git -C $root status --short --untracked-files=no)
if ($LASTEXITCODE -ne 0) { throw "live tracked status observation failed" }
$manifest = [ordered]@{
    profile = "cantor-supplied-project-assembly-source-custody/0.1"
    source_snapshot_uuid = "62cc9a0e-635b-4c96-8587-9a5cfc663fc2"
    live_source_head = $head
    selected_files = $observed
    selected_file_count = $observed.Count
    selected_byte_count = $selectedByteCount
    protected_foreign_file = [ordered]@{ path = $protectedRelative; bytes = [int64]$observedProtectedBytes; sha256 = $observedProtectedSha256 }
    tracked_delta_count = $trackedStatus.Count
    live_source_mutations = 0
    promoted_external_effects = 0
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $fullOutput = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $fullOutput
    if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($fullOutput, (($manifest | ConvertTo-Json -Depth 8 -Compress) + "`n"), $utf8)
}

Write-Output ("cantor_supplied_project_source_verified=true files={0} bytes={1} tracked_deltas={2} live_source_mutations=0 effects=0" -f $manifest.selected_file_count, $manifest.selected_byte_count, $manifest.tracked_delta_count)
