param(
    [string]$SourceRoot = "C:\Project\Cantor",
    [string]$ManifestPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$integrationRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $integrationRoot "experiments\eclipse_cantor_instance_foundation_p0\semantic_custody_manifest.json"
}
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

function Get-StringSetHash([string[]]$Values) {
    $ordered = @(Get-OrdinalUnique $Values)
    $text = if ($ordered.Count -eq 0) { "" } else { ($ordered -join "`n") + "`n" }
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-OrdinalUnique([string[]]$Values) {
    $set = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) { [void]$set.Add($value) }
    return @($set)
}

function Invoke-GitLines([string[]]$Arguments) {
    $priorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = @(& git @Arguments 2>$null)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exitCode -ne 0) { throw "Git inventory command failed with exit $exitCode" }
    return $lines
}

if ($manifest.profile -ne "cantor-eclipse-semantic-custody/0.1") { throw "custody profile differs" }
if ($manifest.source_snapshot_uuid -ne "670483d0-3f70-49b5-8d7c-d924065ce004") { throw "source UUID differs" }
if ($manifest.specification_uuid -ne "d7e6055f-d40e-46c4-a757-2db3b77c7108") { throw "specification UUID differs" }
if ($manifest.source_head -ne (((Invoke-GitLines @("-C", $source, "rev-parse", "HEAD")) -join "`n").Trim())) { throw "source HEAD differs" }
if ($manifest.published_target_head -ne "80f2ef9a8c1709e9e0dc12d70fc340a53919eec2") { throw "target predecessor differs" }
if ($manifest.selection_policy.authority -ne "inventory_only_no_promotion_no_execution") { throw "inventory authority differs" }
foreach ($counter in $manifest.live_counters.PSObject.Properties) { if ([int64]$counter.Value -ne 0) { throw "live counter is nonzero: $($counter.Name)" } }

$untracked = @(Get-OrdinalUnique @(Invoke-GitLines @("-c", "core.quotepath=false", "-C", $source, "ls-files", "--others", "--exclude-standard") | ForEach-Object { $_.Replace("\", "/") }))
$tracked = @(Get-OrdinalUnique @(Invoke-GitLines @("-c", "core.quotepath=false", "-C", $source, "status", "--porcelain=v1", "-uno")))
if ([int64]$manifest.source_status.untracked_path_count -ne $untracked.Count) { throw "untracked path count differs" }
if ($manifest.source_status.untracked_path_list_sha256 -ne (Get-StringSetHash $untracked)) { throw "untracked path inventory differs" }
if ([int64]$manifest.source_status.tracked_status_count -ne $tracked.Count) { throw "tracked status count differs" }
if ($manifest.source_status.tracked_status_sha256 -ne (Get-StringSetHash $tracked)) { throw "tracked status inventory differs" }

$seen = @{}
$lines = @()
$previous = ""
foreach ($artifact in @($manifest.artifacts)) {
    $path = [string]$artifact.relative_path
    if ([IO.Path]::IsPathRooted($path) -or $path.Contains("\") -or $path -match '(^|/)\.\.(/|$)') { throw "nonportable artifact path: $path" }
    if ($seen.ContainsKey($path)) { throw "duplicate artifact path: $path" }
    if (-not [string]::IsNullOrEmpty($previous) -and [string]::CompareOrdinal($previous, $path) -ge 0) { throw "artifacts are not strictly sorted" }
    $seen[$path] = $true
    $previous = $path
    $full = Join-Path $source $path
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw "artifact is not a regular file: $path" }
    if ([int64]$artifact.bytes -ne [int64]$item.Length) { throw "artifact size differs: $path" }
    $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne [string]$artifact.sha256) { throw "artifact hash differs: $path" }
    if (@("tracked_integration_delta", "kernel_candidate", "instance_adapter", "package", "governance_source") -notcontains [string]$artifact.classification) { throw "artifact classification differs: $path" }
    $lines += "{0}|{1}|{2}|{3}|{4}" -f $path, $artifact.origin, $artifact.classification, $artifact.bytes, $artifact.sha256
}
if ([int64]$manifest.artifact_count -ne $seen.Count) { throw "artifact count differs" }
if ($manifest.artifact_inventory_sha256 -ne (Get-StringSetHash $lines)) { throw "artifact inventory digest differs" }
Write-Output ("semantic_custody_verified=true artifacts={0} untracked={1} inventory_sha256={2}" -f $seen.Count, $untracked.Count, $manifest.artifact_inventory_sha256)
