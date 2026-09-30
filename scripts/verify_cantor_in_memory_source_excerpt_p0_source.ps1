param(
    [string]$LiveRoot = "C:\Project\Cantor",
    [string]$RepositoryRoot = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$liveRootPath = [IO.Path]::GetFullPath($LiveRoot)
$repositoryRootPath = [IO.Path]::GetFullPath($RepositoryRoot)
$liveHeadExpected = "82a3e19b839fd4e937ecb1f366859289364529c0"
$predecessor = "abc8734e01f8c3b591db4b84e4d545951f6075b2"
$protectedRelative = "narrative/turns/1786911720465_minecraftgenie_scope_handoff_negotiation.sop"
$protectedBytes = 1805
$protectedSha256 = "5b806e8d078c03d189021d0bb458ea42ade3508e04677387d9ab9966dadc6f07"
$liveExpected = @(
    [ordered]@{ path = "crates/cantor_scribe/src/model.rs"; bytes = 5236; sha256 = "59120bac5b0a41520ac872501271369ef073a1cd7b9797b80f0d52e0f2daf3d4" },
    [ordered]@{ path = "crates/cantor_scribe/src/storage.rs"; bytes = 31837; sha256 = "77202146f7414425f59836ae3ceeb3f1a74fa235d88736c371697f8aae9c33cd" },
    [ordered]@{ path = "crates/cantor_scribe/tests/snapshot.rs"; bytes = 8908; sha256 = "89140e3150c87203d386639e0d87539041e2abd4fb6556b16aca91495dce12c4" }
)
$predecessorExpected = @(
    [ordered]@{ path = "crates/cantor_sop_project/src/lib.rs"; bytes = 13305; sha256 = "8546718ca291dd7aa9f4e24fe05a751a992f2181edae09158e70adeac789c99e" },
    [ordered]@{ path = "crates/cantor_sop_query/src/lib.rs"; bytes = 16379; sha256 = "bd9ccb596ca57eb30aa1a061bd969ca5c52f5cbf63c42abaac2a9fdd141faa18" },
    [ordered]@{ path = "crates/cantor_sop_semantics/src/model.rs"; bytes = 6271; sha256 = "f3fcb06cfad746b2e07f5e513085352858da4b62dccb872ed024e73a6190ad7f" }
)

function Get-GitBlobIdentity([string]$Root, [string]$Revision, [string]$RelativePath) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = "git"
    $info.Arguments = ('-C "{0}" cat-file blob "{1}:{2}"' -f $Root, $Revision, $RelativePath)
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw "git cat-file did not start" }
    $memory = New-Object IO.MemoryStream
    try {
        $process.StandardOutput.BaseStream.CopyTo($memory)
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "git cat-file failed for ${Revision}:${RelativePath}: $errorText" }
        $bytes = $memory.ToArray()
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
        return [ordered]@{ bytes = [int64]$bytes.Length; sha256 = $digest }
    } finally { $memory.Dispose(); $process.Dispose() }
}

$liveHead = (& git -C $liveRootPath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $liveHead -cne $liveHeadExpected) { throw "live source head differs: $liveHead" }
$repositoryHead = (& git -C $repositoryRootPath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "promotion repository head is unreadable" }
& git -C $repositoryRootPath merge-base --is-ancestor $predecessor $repositoryHead
if ($LASTEXITCODE -ne 0) { throw "published predecessor is not an ancestor of promotion head" }

$observed = @(); $selectedBytes = [int64]0
foreach ($item in $liveExpected) {
    $path = Join-Path $liveRootPath ([string]$item.path)
    $bytes = (Get-Item -LiteralPath $path).Length
    $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bytes -ne [int64]$item.bytes -or $sha256 -cne [string]$item.sha256) { throw "selected live source identity differs: $($item.path)" }
    $observed += [ordered]@{ origin = "live"; path = [string]$item.path; bytes = [int64]$bytes; sha256 = $sha256 }
    $selectedBytes += [int64]$bytes
}
foreach ($item in $predecessorExpected) {
    $identity = Get-GitBlobIdentity $repositoryRootPath $predecessor ([string]$item.path)
    if ([int64]$identity.bytes -ne [int64]$item.bytes -or [string]$identity.sha256 -cne [string]$item.sha256) { throw "selected predecessor source identity differs: $($item.path)" }
    $observed += [ordered]@{ origin = "predecessor"; path = [string]$item.path; bytes = [int64]$identity.bytes; sha256 = [string]$identity.sha256 }
    $selectedBytes += [int64]$identity.bytes
}
$protectedPath = Join-Path $liveRootPath $protectedRelative
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) { throw "protected foreign narrative identity differs" }
$trackedStatus = @(& git -C $liveRootPath status --short --untracked-files=no)
if ($LASTEXITCODE -ne 0) { throw "live tracked status observation failed" }
$manifest = [ordered]@{
    profile = "cantor-in-memory-source-excerpt-source-custody/0.1"; source_snapshot_uuid = "b8349a92-5828-4012-bb53-84025774c15a"
    live_source_head = $liveHead; published_predecessor = $predecessor; selected_files = $observed
    selected_file_count = $observed.Count; selected_byte_count = $selectedBytes
    protected_foreign_file = [ordered]@{ path = $protectedRelative; bytes = [int64]$observedProtectedBytes; sha256 = $observedProtectedSha256 }
    live_tracked_delta_count = $trackedStatus.Count; live_source_mutations = 0; promoted_external_effects = 0
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $fullOutput = [IO.Path]::GetFullPath($OutputPath); $parent = Split-Path -Parent $fullOutput
    if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($fullOutput, (($manifest | ConvertTo-Json -Depth 8 -Compress) + "`n"), $utf8)
}
Write-Output ("cantor_in_memory_source_excerpt_source_verified=true files={0} bytes={1} live_tracked_deltas={2} live_source_mutations=0 effects=0" -f $manifest.selected_file_count, $manifest.selected_byte_count, $manifest.live_tracked_delta_count)
