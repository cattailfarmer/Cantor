param(
    [string]$SourceRoot = "C:\Project\Cantor",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$integrationRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $integrationRoot "experiments\eclipse_cantor_instance_foundation_p0\semantic_custody_manifest.json"
}
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$expectedSourceHead = "82a3e19b839fd4e937ecb1f366859289364529c0"
$publishedTargetHead = "80f2ef9a8c1709e9e0dc12d70fc340a53919eec2"

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

function Get-UntrackedPaths {
    $paths = @(Invoke-GitLines @("-c", "core.quotepath=false", "-C", $source, "ls-files", "--others", "--exclude-standard") | ForEach-Object { $_.Replace("\", "/") })
    return @(Get-OrdinalUnique $paths)
}

function Get-TrackedStatus {
    $lines = @(Invoke-GitLines @("-c", "core.quotepath=false", "-C", $source, "status", "--porcelain=v1", "-uno"))
    return @(Get-OrdinalUnique $lines)
}

function Get-SourceStatus {
    $untracked = @(Get-UntrackedPaths)
    $tracked = @(Get-TrackedStatus)
    return [ordered]@{
        tracked_status_count = $tracked.Count
        tracked_status_sha256 = Get-StringSetHash $tracked
        untracked_path_count = $untracked.Count
        untracked_path_list_sha256 = Get-StringSetHash $untracked
        untracked_paths = $untracked
    }
}

function Test-SemanticCandidate([string]$RelativePath) {
    $path = $RelativePath.Replace("\", "/")
    $lower = $path.ToLowerInvariant()
    foreach ($segment in @("/__pycache__/", "/.pytest_cache/", "/target/", "/build/", "/bin/", "/obj/", "/.gradle/", "/.metadata/")) {
        if (("/" + $lower).Contains($segment)) { return $false }
    }
    $extension = [IO.Path]::GetExtension($lower)
    if (@(".pyc", ".pyo", ".class", ".jar", ".zip", ".exe", ".dll", ".pdb", ".db", ".sqlite", ".sqlite3") -contains $extension) { return $false }
    if (@("agents.md", "cargo.toml", "cargo.lock", "crates/cantor_core/src/lib.rs", "scribe.md", "scribe_current.md") -contains $lower) { return $true }
    if ($lower.StartsWith("crates/cantor_scribe/")) { return $true }
    if ($lower.StartsWith("scripts/scribe_") -or $lower.StartsWith("scripts/test_scribe_") -or $lower.StartsWith("scripts/sop_")) { return $true }
    if ($lower.StartsWith("eclipse/")) { return $true }
    if (($lower.StartsWith("apps/") -or $lower.StartsWith("packages/")) -and $lower -match "scribe|eclipse") { return $true }
    foreach ($root in @("source_documents/", "specifications/", "justifications/", "plans/", "proofs/", "solutions/", "feature_support/", "docs/", "narrative/")) {
        if ($lower.StartsWith($root) -and ($lower -match "scribe|eclipse|01a09eef")) { return $true }
    }
    return $false
}

function Get-Classification([string]$RelativePath) {
    $lower = $RelativePath.ToLowerInvariant()
    if (@("agents.md", "cargo.toml", "cargo.lock", "crates/cantor_core/src/lib.rs") -contains $lower) { return "tracked_integration_delta" }
    if ($lower.StartsWith("crates/cantor_scribe/") -or $lower.StartsWith("scripts/scribe_runtime/") -or $lower -match "^scripts/scribe_(operation_tool|recipe_operation|inquire)") { return "kernel_candidate" }
    if ($lower.StartsWith("eclipse/") -or $lower.StartsWith("apps/") -or $lower -match "^scripts/scribe_.*(delivery|inspection|workbench)") { return "instance_adapter" }
    if ($lower.StartsWith("packages/")) { return "package" }
    return "governance_source"
}

function Get-Artifact([string]$RelativePath, [string]$Origin) {
    $normalized = $RelativePath.Replace("\", "/")
    if ([IO.Path]::IsPathRooted($normalized) -or $normalized -match '(^|/)\.\.(/|$)') { throw "nonportable selected path: $normalized" }
    $full = Join-Path $source $normalized
    $item = Get-Item -LiteralPath $full -Force
    if (-not $item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        return [ordered]@{
            relative_path = $normalized
            origin = $Origin
            classification = Get-Classification $normalized
            bytes = [int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    throw "selected semantic path is not a regular file: $normalized"
}

$sourceHead = ((Invoke-GitLines @("-C", $source, "rev-parse", "HEAD")) -join "`n").Trim()
if ($sourceHead -ne $expectedSourceHead) { throw "source checkout HEAD differs: $sourceHead" }
$targetHead = ((Invoke-GitLines @("-C", $integrationRoot, "rev-parse", "HEAD")) -join "`n").Trim()
if ($targetHead -ne $publishedTargetHead) { throw "integration predecessor differs: $targetHead" }
$before = Get-SourceStatus

$selected = [ordered]@{}
foreach ($path in $before.untracked_paths) {
    if (Test-SemanticCandidate $path) { $selected[$path] = "untracked_live_source" }
}
foreach ($path in @("AGENTS.md", "Cargo.toml", "Cargo.lock", "crates/cantor_core/src/lib.rs")) {
    $selected[$path] = "tracked_live_delta"
}
$artifacts = @(Get-OrdinalUnique @($selected.Keys) | ForEach-Object { Get-Artifact $_ $selected[$_] })

$classificationCounts = [ordered]@{}
foreach ($artifact in $artifacts) {
    $key = $artifact.classification
    if ($classificationCounts.Contains($key)) { $classificationCounts[$key]++ } else { $classificationCounts[$key] = 1 }
}
$excludedRootCounts = [ordered]@{}
foreach ($path in $before.untracked_paths) {
    if (-not (Test-SemanticCandidate $path)) {
        $root = ($path -split "/")[0]
        if ($excludedRootCounts.Contains($root)) { $excludedRootCounts[$root]++ } else { $excludedRootCounts[$root] = 1 }
    }
}
$artifactLines = @($artifacts | ForEach-Object { "{0}|{1}|{2}|{3}|{4}" -f $_.relative_path, $_.origin, $_.classification, $_.bytes, $_.sha256 })
$after = Get-SourceStatus
foreach ($key in @("tracked_status_count", "tracked_status_sha256", "untracked_path_count", "untracked_path_list_sha256")) {
    if ($before[$key] -ne $after[$key]) { throw "source checkout changed during custody inventory: $key" }
}

$manifest = [ordered]@{
    profile = "cantor-eclipse-semantic-custody/0.1"
    source_snapshot_uuid = "670483d0-3f70-49b5-8d7c-d924065ce004"
    specification_uuid = "d7e6055f-d40e-46c4-a757-2db3b77c7108"
    source_repository = "https://github.com/cattailfarmer/Cantor"
    source_head = $sourceHead
    published_target_head = $targetHead
    source_status = [ordered]@{
        tracked_status_count = $before.tracked_status_count
        tracked_status_sha256 = $before.tracked_status_sha256
        untracked_path_count = $before.untracked_path_count
        untracked_path_list_sha256 = $before.untracked_path_list_sha256
    }
    selection_policy = [ordered]@{
        version = "eclipse-semantic-candidates/0.1"
        generated_roots_excluded_by_default = @("evidence", "distributions", "workspaces", "worker_projects", "tmp", "target", ".local")
        authority = "inventory_only_no_promotion_no_execution"
    }
    artifact_count = $artifacts.Count
    artifact_inventory_sha256 = Get-StringSetHash $artifactLines
    classification_counts = $classificationCounts
    excluded_root_counts = $excludedRootCounts
    live_counters = [ordered]@{ processes = 0; providers = 0; remote_calls = 0; effects = 0; installations = 0; updates = 0; synthetic_trials = 0 }
    artifacts = $artifacts
}
$parent = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
$json = $manifest | ConvertTo-Json -Depth 12 -Compress
[IO.File]::WriteAllText($OutputPath, $json + "`n", (New-Object Text.UTF8Encoding($false)))
Write-Output ("semantic_custody_built=true artifacts={0} untracked={1} inventory_sha256={2}" -f $artifacts.Count, $before.untracked_path_count, $manifest.artifact_inventory_sha256)
