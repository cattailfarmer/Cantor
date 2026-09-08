[CmdletBinding()]
param(
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-current-build-host-pilot-p0-package-8e37e3e7'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedCommit = '8e37e3e701d41d61328f89296ae77b8ea3707812'
$expectedRef = 'refs/heads/codex/self-hosted-corpus'
$remoteRoot = 'C:/AI/services/cantor-current-pilot-48479932'
$buildParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$packagePath = [IO.Path]::GetFullPath($PackageRoot)
if (-not $packagePath.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'PackageRoot must remain beneath D:\CantorBuilds' }
if (Test-Path -LiteralPath $packagePath) { throw 'PackageRoot already exists; package construction never overwrites' }

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$head = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
$tracking = (& git.exe -C $repositoryRoot rev-parse origin/codex/self-hosted-corpus).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $expectedCommit -or $tracking -cne $expectedCommit) { throw 'published source lineage is not the pinned formation bookend' }
$rustStatus = @(& git.exe -C $repositoryRoot status --porcelain=v1 --untracked-files=all -- Cargo.toml Cargo.lock crates)
if ($LASTEXITCODE -ne 0 -or $rustStatus.Count -ne 0) { throw 'Rust source surface is not clean at the pinned commit' }

$buildId = [guid]::NewGuid().Guid
$scratch = [IO.Path]::GetFullPath((Join-Path $buildParent "evox2-current-build-package-$buildId"))
if (-not $scratch.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe scratch path' }
$archive = Join-Path $scratch 'source.tar'
$sourceRoot = Join-Path $scratch 'source'
$releaseRoot = Join-Path $repositoryRoot 'target\release'
$binaryNames = @('cantor.exe', 'cantor-b1-production-broker-projection-evidence-verify.exe')
$previousOffline = $env:CARGO_NET_OFFLINE
$previousIncremental = $env:CARGO_INCREMENTAL
try {
    New-Item -ItemType Directory -Path $scratch, $sourceRoot -Force | Out-Null
    & git.exe -C $repositoryRoot archive --format=tar --output=$archive $expectedCommit
    if ($LASTEXITCODE -ne 0) { throw 'failed to archive pinned source commit' }
    & tar.exe -xf $archive -C $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'failed to extract pinned source archive' }

    foreach ($name in $binaryNames) {
        $candidate = [IO.Path]::GetFullPath((Join-Path $releaseRoot $name))
        if (-not $candidate.StartsWith($releaseRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe release binary path' }
        if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
    }
    $env:CARGO_NET_OFFLINE = 'true'
    $env:CARGO_INCREMENTAL = '0'
    & cargo.exe build --manifest-path (Join-Path $sourceRoot 'Cargo.toml') --target-dir (Join-Path $repositoryRoot 'target') --release --locked --offline --bin cantor --bin cantor-b1-production-broker-projection-evidence-verify
    if ($LASTEXITCODE -ne 0) { throw 'fresh locked-offline release build failed' }

    $binRoot = Join-Path $packagePath 'bin'
    $evidenceDestination = Join-Path $packagePath 'evidence\a8'
    New-Item -ItemType Directory -Path $binRoot, $evidenceDestination -Force | Out-Null
    foreach ($name in $binaryNames) { Copy-Item -LiteralPath (Join-Path $releaseRoot $name) -Destination (Join-Path $binRoot $name) }
    $evidenceSource = Join-Path $repositoryRoot 'experiments\b1_production_broker_projection_correspondence_p0\implementation_provider_free_evidence'
    $evidenceFiles = @(Get-ChildItem -LiteralPath $evidenceSource -File | Sort-Object Name)
    if ($evidenceFiles.Count -ne 34) { throw 'retained A8 evidence cardinality changed' }
    foreach ($file in $evidenceFiles) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $evidenceDestination $file.Name) }

    $artifacts = @()
    foreach ($entry in @(
        @('bin/cantor.exe', 'current_cantor_query', 'target/release/cantor.exe'),
        @('bin/cantor-b1-production-broker-projection-evidence-verify.exe', 'current_a8_evidence_verifier', 'target/release/cantor-b1-production-broker-projection-evidence-verify.exe')
    )) {
        $path = Join-Path $packagePath $entry[0]
        $item = Get-Item -LiteralPath $path
        $artifacts += [ordered]@{
            relative_path = $entry[0]
            role = $entry[1]
            bytes = [int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            executable = $true
            source_locator = $entry[2]
        }
    }
    foreach ($file in $evidenceFiles) {
        $relative = 'evidence/a8/' + $file.Name
        $path = Join-Path $packagePath $relative
        $item = Get-Item -LiteralPath $path
        $artifacts += [ordered]@{
            relative_path = $relative
            role = 'retained_a8_evidence'
            bytes = [int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            executable = $false
            source_locator = 'experiments/b1_production_broker_projection_correspondence_p0/implementation_provider_free_evidence/' + $file.Name
        }
    }
    $aggregate = [int64]0
    foreach ($artifact in $artifacts) {
        $aggregate += [int64]$artifact.bytes
        if ($aggregate -gt 1073741824) { throw 'package aggregate bytes exceed bound' }
    }
    $manifest = [ordered]@{
        profile = 'cantor-evox2-current-build-pilot-deployment-manifest/0.1'
        manifest_uuid = '768b0ac7-c1f6-4781-ab9d-d0c1bf9098f4'
        source_commit = $expectedCommit
        source_ref = $expectedRef
        target_host = 'EVO-X2'
        remote_root = $remoteRoot
        protected_roots = @('C:/AI/services/cantor-attention-mcp', 'C:/AI/services/cantor-needle-runtime', 'C:/AI/services/sop-agent')
        artifact_count = $artifacts.Count
        aggregate_bytes = $aggregate
        artifacts = $artifacts
        allowed_executions = @('a8_evidence_replay', 'optional_cantor_public_query_replay')
        manifest_sha256 = ''
    }
    $canonical = $manifest | ConvertTo-Json -Depth 20 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $manifest.manifest_sha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('cantor-evox2-current-build-pilot-deployment-manifest-v1' + [char]0 + $canonical)) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
    [IO.File]::WriteAllText((Join-Path $packagePath 'deployment_manifest.json'), (($manifest | ConvertTo-Json -Depth 20 -Compress) + "`n"), [Text.UTF8Encoding]::new($false))

    $verification = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_package.ps1') -PackageRoot $packagePath | ConvertFrom-Json
    [pscustomobject]@{
        profile = 'cantor-evox2-current-build-pilot-package-build/0.1'
        status = 'passed'
        source_commit = $expectedCommit
        package_root = $packagePath
        manifest_uuid = $manifest.manifest_uuid
        manifest_sha256 = $manifest.manifest_sha256
        artifact_count = $artifacts.Count
        aggregate_bytes = $aggregate
        verification = $verification
    } | ConvertTo-Json -Depth 8
} finally {
    $env:CARGO_NET_OFFLINE = $previousOffline
    $env:CARGO_INCREMENTAL = $previousIncremental
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
