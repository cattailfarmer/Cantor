[CmdletBinding()]
param([string] $PackageRoot = 'D:\CantorBuilds\evox2-plan-only-build-job-p0-package-4fdd29cb')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedCommit = '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'
$expectedRef = 'refs/heads/codex/self-hosted-corpus'
$buildParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$packagePath = [IO.Path]::GetFullPath($PackageRoot)
if (-not $packagePath.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'PackageRoot must remain beneath D:\CantorBuilds' }
if (Test-Path -LiteralPath $packagePath) { throw 'PackageRoot already exists; package construction never overwrites' }

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$head = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
$tracking = (& git.exe -C $repositoryRoot rev-parse origin/codex/self-hosted-corpus).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $tracking) { throw 'local and fetched canonical lineage differ' }
& git.exe -C $repositoryRoot merge-base --is-ancestor $expectedCommit $head
if ($LASTEXITCODE -ne 0) { throw 'published lineage does not descend from the pinned core bookend' }
$rustStatus = @(& git.exe -C $repositoryRoot status --porcelain=v1 --untracked-files=all -- Cargo.toml Cargo.lock crates)
if ($LASTEXITCODE -ne 0 -or $rustStatus.Count -ne 0) { throw 'Rust source surface is not clean at the pinned bookend' }

$scratch = [IO.Path]::GetFullPath((Join-Path $buildParent ('evox2-plan-only-package-' + [guid]::NewGuid().Guid)))
$sourceRoot = Join-Path $scratch 'source'
$archivePath = Join-Path $scratch 'source.tar'
$targetRoot = Join-Path $buildParent 'evox2-plan-only-build-job-p0-target'
$releaseRoot = Join-Path $targetRoot 'release'
$previousOffline = $env:CARGO_NET_OFFLINE
$previousJobs = $env:CARGO_BUILD_JOBS
$previousIncremental = $env:CARGO_INCREMENTAL
$previousRustFlags = $env:RUSTFLAGS
try {
    New-Item -ItemType Directory -Path $scratch, $sourceRoot -Force | Out-Null
    & git.exe -C $repositoryRoot archive --format=tar --output=$archivePath $expectedCommit
    if ($LASTEXITCODE -ne 0) { throw 'pinned source archive failed' }
    $archiveItem = Get-Item -LiteralPath $archivePath
    if ($archiveItem.Length -le 0 -or $archiveItem.Length -gt 268435456) { throw 'source archive bound mismatch' }
    $archiveSha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    & tar.exe -xf $archivePath -C $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'pinned source extraction failed' }

    foreach ($name in @('cantor-evox2-plan-only-build-job.exe', 'cantor-evox2-plan-only-build-job-verify.exe')) {
        $candidate = Join-Path $releaseRoot $name
        if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
    }
    $env:CARGO_NET_OFFLINE = 'true'
    $env:CARGO_BUILD_JOBS = '1'
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTFLAGS = '-C overflow-checks=yes'
    & cargo.exe build --manifest-path (Join-Path $sourceRoot 'Cargo.toml') --target-dir $targetRoot --release --locked --offline --bin cantor-evox2-plan-only-build-job --bin cantor-evox2-plan-only-build-job-verify
    if ($LASTEXITCODE -ne 0) { throw 'fresh locked-offline planner build failed' }

    $binRoot = Join-Path $packagePath 'bin'
    $evidenceRoot = Join-Path $packagePath 'evidence'
    New-Item -ItemType Directory -Path $binRoot, $evidenceRoot -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $releaseRoot 'cantor-evox2-plan-only-build-job.exe') -Destination $binRoot
    Copy-Item -LiteralPath (Join-Path $releaseRoot 'cantor-evox2-plan-only-build-job-verify.exe') -Destination $binRoot

    $request = [ordered]@{
        profile = 'cantor-evox2-plan-only-build-job/0.1'
        request_uuid = '56d04713-7953-4e7e-aa9d-37f1027626b8'
        predecessor_canonical_uuid = '4cf12917-73e8-4505-9228-f94d981143bd'
        predecessor_bookend_commit = 'd805681daee0d6846574875e25b6e1e41c9207bc'
        source_commit = $expectedCommit
        source_archive_sha256 = $archiveSha
        repository_remote_ref = 'https://github.com/cattailfarmer/Cantor'
        target_host = 'EVO-X2'
        target_os = 'windows-x86_64'
        future_workspace_root = 'C:/AI/workspaces/cantor-build-4fdd29cb'
        future_target_root = 'C:/AI/builds/cantor-build-4fdd29cb'
        cargo_profile = 'locked-offline-serialized/0.1'
        requested_checks = @('workspace_debug', 'workspace_release', 'workspace_clippy', 'workspace_format')
        bounds = [ordered]@{ maximum_archive_bytes = 268435456; maximum_files = 16384; maximum_stdout_bytes = 262144; maximum_operation_count = 7; timeout_seconds = 7200; cargo_build_jobs = 1 }
        authority_denials = @('source_transfer', 'source_extract', 'toolchain_observe', 'toolchain_install', 'dependency_fetch', 'workspace_write', 'process_execute', 'git_mutation', 'commit', 'push', 'provider_call', 'model_inference', 'service_change', 'external_network', 'security_policy_change')
        request_sha256 = ''
    }
    $unsigned = $request | ConvertTo-Json -Depth 20 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $request.request_sha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('cantor.evox2-plan-only-build-job.request.v1' + [char]0 + $unsigned)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    [IO.File]::WriteAllText((Join-Path $packagePath 'request.json'), ($request | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false))

    $evidenceCopies = @(
        @('specifications/Cantor_EVO_X2_Plan_Only_Build_Job_P0.sop', 'specification.sop'),
        @('proofs/Cantor_EVO_X2_Plan_Only_Build_Job_P0_Local_Core_Implementation_Proof.sop', 'local-core-implementation-proof.sop'),
        @('proofs/Cantor_EVO_X2_Plan_Only_Build_Job_P0_Local_Core_Publication_Proof.sop', 'local-core-publication-proof.sop'),
        @('feature_support/Cantor_EVO_X2_Plan_Only_Build_Job_P0_Local_Core_Coverage.sop', 'local-core-coverage.sop'),
        @('narrative/registries/Cantor_EVO_X2_Plan_Only_Build_Job_P0_Local_Core_Phase_Checkpoint.sop', 'local-core-phase-checkpoint.sop'),
        @('experiments/evox2_plan_only_build_job_p0/local_core_evidence_manifest.json', 'local-core-evidence-manifest.json')
    )
    foreach ($copy in $evidenceCopies) { Copy-Item -LiteralPath (Join-Path $sourceRoot $copy[0]) -Destination (Join-Path $evidenceRoot $copy[1]) }

    $roles = [ordered]@{
        'bin/cantor-evox2-plan-only-build-job.exe' = 'compiler'
        'bin/cantor-evox2-plan-only-build-job-verify.exe' = 'verifier'
        'request.json' = 'exact_request'
        'evidence/specification.sop' = 'canonical_specification'
        'evidence/local-core-implementation-proof.sop' = 'implementation_proof'
        'evidence/local-core-publication-proof.sop' = 'publication_proof'
        'evidence/local-core-coverage.sop' = 'requirement_coverage'
        'evidence/local-core-phase-checkpoint.sop' = 'phase_checkpoint'
        'evidence/local-core-evidence-manifest.json' = 'local_core_evidence'
    }
    $artifacts = @()
    $aggregate = [int64] 0
    foreach ($relative in $roles.Keys) {
        $item = Get-Item -LiteralPath (Join-Path $packagePath $relative)
        $aggregate += [int64] $item.Length
        $artifacts += [ordered]@{ relative_path = $relative; role = $roles[$relative]; bytes = [int64] $item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    if ($aggregate -le 0 -or $aggregate -gt 16777216) { throw 'package aggregate exceeds bound' }
    $manifest = [ordered]@{
        profile = 'cantor-evox2-plan-only-build-job-deployment-manifest/0.1'
        manifest_uuid = 'c630bbd9-d718-40cd-87fd-39e753b4923f'
        canonical_uuid = '3482e2ce-817c-4788-b185-35adaad414f7'
        source_commit = $expectedCommit
        source_ref = $expectedRef
        target_host = 'EVO-X2'
        remote_root = 'C:/AI/services/cantor-build-planner-d805681d'
        future_workspace_root = 'C:/AI/workspaces/cantor-build-4fdd29cb'
        future_target_root = 'C:/AI/builds/cantor-build-4fdd29cb'
        artifact_count = 9
        aggregate_bytes = $aggregate
        artifacts = $artifacts
        allowed_executions = @('compiler_process_1', 'compiler_process_2', 'verifier_process_1', 'verifier_process_2')
        authority_grants = @()
        manifest_sha256 = ''
    }
    $unsignedManifest = $manifest | ConvertTo-Json -Depth 20 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $manifest.manifest_sha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('cantor-evox2-plan-only-build-job-deployment-manifest-v1' + [char]0 + $unsignedManifest)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    [IO.File]::WriteAllText((Join-Path $packagePath 'deployment_manifest.json'), ($manifest | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false))
    & (Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_package.ps1') -PackageRoot $packagePath
} finally {
    $env:CARGO_NET_OFFLINE = $previousOffline
    $env:CARGO_BUILD_JOBS = $previousJobs
    $env:CARGO_INCREMENTAL = $previousIncremental
    $env:RUSTFLAGS = $previousRustFlags
    if (Test-Path -LiteralPath $scratch) {
        [IO.Directory]::Delete(('\\?\' + $scratch), $true)
    }
}
