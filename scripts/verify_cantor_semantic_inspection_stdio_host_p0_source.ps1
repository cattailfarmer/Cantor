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
$predecessor = "623991664624a982785e6662a9e3d5cd5bca40ee"
$sourceUuid = "83e194a8-122e-47ea-aec8-a35b5317d3b2"
$protectedRelative = "narrative/turns/1786911720465_minecraftgenie_scope_handoff_negotiation.sop"
$protectedBytes = 1805
$protectedSha256 = "5b806e8d078c03d189021d0bb458ea42ade3508e04677387d9ab9966dadc6f07"
$expected = @(
    [ordered]@{ path = "crates/cantor_sop_inspect_wire/Cargo.toml"; bytes = 536; sha256 = "e7b3e546074a19fa8f552d5db60e6237ca26bf50c327c4fb385f600208522971" },
    [ordered]@{ path = "crates/cantor_sop_inspect_wire/src/lib.rs"; bytes = 9704; sha256 = "5c2895fe0995a9403c5f8fdac3e4f507f6a7a7de8c5902507bdbac3f792bca07" },
    [ordered]@{ path = "crates/cantor_sop_inspect/src/lib.rs"; bytes = 16987; sha256 = "5cae18e1d96adb8023452e0fc658281b2f0f6fae6c74f311c58574e840006f84" },
    [ordered]@{ path = "Cargo.toml"; bytes = 1572; sha256 = "1c337eb4403f8c7a0c78d459e885e19c972ffbe98e5795f6e5753d6d9d81ac19" }
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

$manifestPath = Join-Path $repositoryRootPath "experiments/cantor_semantic_inspection_stdio_host_p0/source_custody_manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-stdio-host-source-custody/0.1" -or $manifest.source_snapshot_uuid -cne $sourceUuid -or $manifest.live_source_head -cne $liveHeadExpected -or $manifest.published_predecessor -cne $predecessor) { throw "source custody identity differs" }
if ([int]$manifest.selected_file_count -ne 4 -or [int64]$manifest.selected_byte_count -ne 28799 -or [int]$manifest.live_source_mutations -ne 0 -or [int]$manifest.promoted_external_effects -ne 0) { throw "source custody counters differ" }
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
if ($selectedBytes -ne 28799) { throw "selected source byte total differs" }
$protectedPath = Join-Path $liveRootPath $protectedRelative
$observedProtectedBytes = (Get-Item -LiteralPath $protectedPath).Length
$observedProtectedSha256 = (Get-FileHash -LiteralPath $protectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedProtectedBytes -ne $protectedBytes -or $observedProtectedSha256 -cne $protectedSha256) { throw "protected foreign narrative identity differs" }
if ($manifest.protected_foreign_file.path -cne $protectedRelative -or [int64]$manifest.protected_foreign_file.bytes -ne $protectedBytes -or $manifest.protected_foreign_file.sha256 -cne $protectedSha256) { throw "retained protected identity differs" }
Write-Output "cantor_semantic_inspection_stdio_host_source_verified=true files=4 bytes=28799 live_source_mutations=0 effects=0"
