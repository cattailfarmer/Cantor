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
$predecessor = "71a927a6af74466b1510688599dcf157ad4ee4aa"
$sourceUuid = "21d00b4c-142e-4432-a4dd-41613488aa23"
$protectedRelative = "narrative/turns/1786911720465_minecraftgenie_scope_handoff_negotiation.sop"
$protectedBytes = 1805
$protectedSha256 = "5b806e8d078c03d189021d0bb458ea42ade3508e04677387d9ab9966dadc6f07"
$expected = @(
    [ordered]@{ path = "crates/cantor_sop_inspect/src/lib.rs"; bytes = 16987; sha256 = "5cae18e1d96adb8023452e0fc658281b2f0f6fae6c74f311c58574e840006f84" },
    [ordered]@{ path = "crates/cantor_sop_semantics/src/error.rs"; bytes = 1060; sha256 = "1e336b2d8bdbcd70b043af1a16fc4f915224cef210de90a6190722ac24f6e5b5" },
    [ordered]@{ path = "crates/cantor_sop_semantics/src/digest.rs"; bytes = 3197; sha256 = "15364de06bd5849a0995f263a50175b130cac2884bb8907bf5c52115845b2d2a" },
    [ordered]@{ path = "Cargo.toml"; bytes = 1534; sha256 = "6f67bb8caa17f6ac162a5619284700bc6b3d8825e39cb5c050229c1ec7af0ebd" }
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

$manifestPath = Join-Path $repositoryRootPath "experiments/cantor_semantic_inspection_wire_p0/source_custody_manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-wire-source-custody/0.1" -or $manifest.source_snapshot_uuid -cne $sourceUuid -or $manifest.live_source_head -cne $liveHeadExpected -or $manifest.published_predecessor -cne $predecessor) { throw "source custody identity differs" }
if ([int]$manifest.selected_file_count -ne 4 -or [int64]$manifest.selected_byte_count -ne 22778 -or [int]$manifest.live_source_mutations -ne 0 -or [int]$manifest.promoted_external_effects -ne 0) { throw "source custody counters differ" }
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
if ($selectedBytes -ne 22778) { throw "selected source byte total differs" }
$protectedPath = Join-Path $liveRootPath $protectedRelative
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) { throw "protected foreign narrative identity differs" }
if ($manifest.protected_foreign_file.path -cne $protectedRelative -or [int64]$manifest.protected_foreign_file.bytes -ne $protectedBytes -or $manifest.protected_foreign_file.sha256 -cne $protectedSha256) { throw "retained protected identity differs" }
Write-Output "cantor_semantic_inspection_wire_source_verified=true files=4 bytes=22778 live_source_mutations=0 effects=0"
