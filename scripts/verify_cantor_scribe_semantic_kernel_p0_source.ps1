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
    [ordered]@{ path = "crates/cantor_scribe/src/lib.rs"; bytes = 1191; sha256 = "f25148ebf2b02578896ec1bdd7b06992b95144b305f85b6253880b61fdb2c89b" },
    [ordered]@{ path = "crates/cantor_scribe/src/model.rs"; bytes = 5236; sha256 = "59120bac5b0a41520ac872501271369ef073a1cd7b9797b80f0d52e0f2daf3d4" },
    [ordered]@{ path = "crates/cantor_scribe/src/digest.rs"; bytes = 3113; sha256 = "384767363e22bdf7ee79032a3db76e3ea1b427434f8c75ce41251e802001898e" },
    [ordered]@{ path = "crates/cantor_scribe/src/validate.rs"; bytes = 20069; sha256 = "009514f39dfd200b31c0cfddacbd3f040779e63bb53b340429728808c1d75fa5" },
    [ordered]@{ path = "crates/cantor_scribe/src/source.rs"; bytes = 24462; sha256 = "00cf008de63a2c08f91be1a3de573cea96facb637014c8e771887c0bc9cf79ff" },
    [ordered]@{ path = "crates/cantor_scribe/src/error.rs"; bytes = 1303; sha256 = "70f0574205accf53b8db2f92be4874c47a50590680bcd88d275e8ff4da58b566" }
)

if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "live source root is absent: $root"
}

$head = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $expectedHead) {
    throw "live source head differs: $head"
}

$observed = @()
$selectedByteCount = [int64]0
foreach ($item in $expected) {
    $path = Join-Path $root ([string]$item.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "selected live source is absent: $($item.path)"
    }
    $bytes = (Get-Item -LiteralPath $path).Length
    $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bytes -ne [int64]$item.bytes -or $sha256 -cne [string]$item.sha256) {
        throw "selected live source identity differs: $($item.path)"
    }
    $observed += [ordered]@{
        path = [string]$item.path
        bytes = [int64]$bytes
        sha256 = [string]$sha256
    }
    $selectedByteCount += [int64]$bytes
}

$protectedPath = Join-Path $root $protectedRelative
if (-not (Test-Path -LiteralPath $protectedPath -PathType Leaf)) {
    throw "protected foreign narrative is absent"
}
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) {
    throw "protected foreign narrative identity differs"
}

$trackedStatus = @(& git -C $root status --short --untracked-files=no)
if ($LASTEXITCODE -ne 0) { throw "live tracked status observation failed" }
$manifest = [ordered]@{
    profile = "cantor-scribe-semantic-kernel-source-custody/0.1"
    source_snapshot_uuid = "b02fd0c7-c996-41b9-b0fa-d0d3d0f07cfa"
    live_source_head = $head
    selected_files = $observed
    selected_file_count = $observed.Count
    selected_byte_count = $selectedByteCount
    protected_foreign_file = [ordered]@{
        path = $protectedRelative
        bytes = [int64]$observedProtectedBytes
        sha256 = $observedProtectedSha256
    }
    tracked_delta_count = $trackedStatus.Count
    live_source_mutations = 0
    promoted_external_effects = 0
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $fullOutput = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $fullOutput
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($fullOutput, (($manifest | ConvertTo-Json -Depth 8 -Compress) + "`n"), $utf8)
}

Write-Output ("cantor_scribe_semantic_kernel_source_verified=true files={0} bytes={1} tracked_deltas={2} live_source_mutations=0 effects=0" -f $manifest.selected_file_count, $manifest.selected_byte_count, $manifest.tracked_delta_count)
