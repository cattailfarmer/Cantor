param(
    [string]$LiveRoot = "C:\Project\Cantor",
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$liveRootPath = [IO.Path]::GetFullPath($LiveRoot)
$repositoryRootPath = [IO.Path]::GetFullPath($RepositoryRoot)
$liveHeadExpected = "82a3e19b839fd4e937ecb1f366859289364529c0"
$predecessor = "06e49668e6881320412151c130518667043fb55d"
$sourceUuid = "5ae031ce-6922-4583-85c8-0d3f8e23bd7b"
$protectedRelative = "narrative/turns/1786911720465_minecraftgenie_scope_handoff_negotiation.sop"
$protectedBytes = 1805
$protectedSha256 = "5b806e8d078c03d189021d0bb458ea42ade3508e04677387d9ab9966dadc6f07"
$expected = @(
    [ordered]@{ path = "crates/cantor_sop_project/src/lib.rs"; bytes = 15520; sha256 = "4a7a1950b63daf14559ef2b860848c120c73bf97e7ad6c0d9d4108ab8af14802" },
    [ordered]@{ path = "crates/cantor_sop_query/src/lib.rs"; bytes = 13809; sha256 = "be01d6e7d02599b902c5ce9e6af83444d9118a8aca429d8715f3919998066ad8" },
    [ordered]@{ path = "crates/cantor_sop_excerpt/src/lib.rs"; bytes = 7886; sha256 = "bf286ae02bb3933119d63bb92b66f2f76fecea686f1e1741c83ac99a5793c09d" },
    [ordered]@{ path = "crates/cantor_instance_contract/src/lib.rs"; bytes = 20118; sha256 = "47f3524439cc221e37bfdf5b391d95fbb25f575466bc930cde621accfe4b0c97" }
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

$manifestPath = Join-Path $repositoryRootPath "experiments/cantor_composed_read_only_semantic_inspection_p0/source_custody_manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-composed-read-only-semantic-inspection-source-custody/0.1" -or $manifest.source_snapshot_uuid -cne $sourceUuid -or $manifest.live_source_head -cne $liveHeadExpected -or $manifest.published_predecessor -cne $predecessor) { throw "source custody identity differs" }
if ([int]$manifest.selected_file_count -ne 4 -or [int64]$manifest.selected_byte_count -ne 57333 -or [int]$manifest.live_source_mutations -ne 0 -or [int]$manifest.promoted_external_effects -ne 0) { throw "source custody counters differ" }
if (@($manifest.selected_files).Count -ne $expected.Count) { throw "selected source membership differs" }
$selectedBytes = [int64]0
for ($index = 0; $index -lt $expected.Count; $index++) {
    $item = $expected[$index]
    $retained = @($manifest.selected_files)[$index]
    $identity = Get-GitBlobIdentity $repositoryRootPath $predecessor ([string]$item.path)
    if ([int64]$identity.bytes -ne [int64]$item.bytes -or [string]$identity.sha256 -cne [string]$item.sha256) { throw "selected predecessor source identity differs: $($item.path)" }
    if ($retained.origin -cne "predecessor" -or $retained.path -cne [string]$item.path -or [int64]$retained.bytes -ne [int64]$item.bytes -or $retained.sha256 -cne [string]$item.sha256) { throw "retained source coordinate differs: $($item.path)" }
    $selectedBytes += [int64]$identity.bytes
}
if ($selectedBytes -ne 57333) { throw "selected source byte total differs" }
$protectedPath = Join-Path $liveRootPath $protectedRelative
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) { throw "protected foreign narrative identity differs" }
if ($manifest.protected_foreign_file.path -cne $protectedRelative -or [int64]$manifest.protected_foreign_file.bytes -ne $protectedBytes -or $manifest.protected_foreign_file.sha256 -cne $protectedSha256) { throw "retained protected identity differs" }
Write-Output "cantor_composed_read_only_semantic_inspection_source_verified=true files=4 bytes=57333 live_source_mutations=0 effects=0"
