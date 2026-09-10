[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ImplementationCommit,
    [Parameter(Mandatory = $true)]
    [string] $PublicationBookendCommit,
    [string] $PackageRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sourceCommit = '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'
$sourceArchiveSha256 = '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d'
$implementationBookend = 'f87734eab7b93f7ccb2370667cbb88089d72201d'
$buildParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ($ImplementationCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ImplementationCommit must be lower-hex40' }
if ($PublicationBookendCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'PublicationBookendCommit must be lower-hex40' }
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Join-Path $buildParent ('evox2-scratch-build-executor-p0-package-' + $ImplementationCommit.Substring(0, 8))
}
$package = [IO.Path]::GetFullPath($PackageRoot)
if (-not $package.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'PackageRoot must remain beneath D:\CantorBuilds' }
if (Test-Path -LiteralPath $package) { throw 'PackageRoot already exists; package construction never overwrites' }

$head = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
$tracking = (& git.exe -C $repositoryRoot rev-parse origin/codex/self-hosted-corpus).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $PublicationBookendCommit -or $tracking -cne $PublicationBookendCommit) { throw 'local and fetched canonical lineage must equal PublicationBookendCommit' }
$bookendLine = ((& git.exe -C $repositoryRoot rev-list --parents -n 1 $PublicationBookendCommit) | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'publication bookend lineage unavailable' }
$bookendParts = @($bookendLine -split ' ' | Where-Object { $_.Length -gt 0 })
if ($bookendParts.Count -ne 2 -or $bookendParts[0] -cne $PublicationBookendCommit -or $bookendParts[1] -cne $ImplementationCommit) { throw 'publication bookend must be the immediate single-parent child of ImplementationCommit' }
& git.exe -C $repositoryRoot merge-base --is-ancestor $implementationBookend $ImplementationCommit
if ($LASTEXITCODE -ne 0) { throw 'implementation lineage does not descend from the package-core bookend' }
$status = @(& git.exe -C $repositoryRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) { throw 'publication-bookended repository is not clean' }

$scratch = [IO.Path]::GetFullPath((Join-Path $buildParent ('evox2-scratch-build-package-stage-' + [guid]::NewGuid().Guid)))
if (-not $scratch.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'scratch root escaped build parent' }
$implementationArchive = Join-Path $scratch 'implementation.tar'
$sourceRoot = Join-Path $scratch 'source'
$sourceArchive = Join-Path $scratch 'source.tar'
$targetRoot = [IO.Path]::GetFullPath('D:\CantorBuilds\evox2-scratch-build-executor-p0-target')
$releaseRoot = Join-Path $targetRoot 'release'
$previousOffline = $env:CARGO_NET_OFFLINE
$previousJobs = $env:CARGO_BUILD_JOBS
$previousIncremental = $env:CARGO_INCREMENTAL
$previousTests = $env:RUST_TEST_THREADS
$previousStack = $env:RUST_MIN_STACK

function Copy-CanonicalRepositoryJson([string] $Source, [string] $Destination) {
    $bytes = [IO.File]::ReadAllBytes($Source)
    if ($bytes.Length -lt 2 -or ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) { throw 'repository JSON byte boundary differs' }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $raw = $utf8.GetString($bytes)
    if ($raw.EndsWith("`r`n", [StringComparison]::Ordinal)) {
        $canonical = $raw.Substring(0, $raw.Length - 2)
    } elseif ($raw.EndsWith("`n", [StringComparison]::Ordinal)) {
        $canonical = $raw.Substring(0, $raw.Length - 1)
    } else {
        throw 'repository JSON requires exactly one terminal line ending'
    }
    if ($canonical.Length -eq 0 -or $canonical.EndsWith("`r", [StringComparison]::Ordinal) -or $canonical.EndsWith("`n", [StringComparison]::Ordinal)) { throw 'repository JSON terminal line-ending cardinality differs' }
    [IO.File]::WriteAllText($Destination, $canonical, [Text.UTF8Encoding]::new($false))
}

try {
    New-Item -ItemType Directory -Path $scratch, $sourceRoot | Out-Null
    & git.exe -C $repositoryRoot archive --format=tar --output=$implementationArchive $ImplementationCommit
    if ($LASTEXITCODE -ne 0) { throw 'implementation archive construction failed' }
    & tar.exe -xf $implementationArchive -C $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'implementation archive extraction failed' }
    & git.exe -C $repositoryRoot archive --format=tar --output=$sourceArchive $sourceCommit
    if ($LASTEXITCODE -ne 0) { throw 'pinned source archive construction failed' }
    $sourceItem = Get-Item -LiteralPath $sourceArchive
    if ($sourceItem.Length -le 0 -or $sourceItem.Length -gt 268435456 -or (Get-FileHash -LiteralPath $sourceArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceArchiveSha256) { throw 'pinned source archive identity differs' }

    $binaryNames = @(
        'cantor-evox2-scratch-build-commission.exe',
        'cantor-evox2-scratch-build-commission-verify.exe',
        'cantor-evox2-scratch-build-receipt-verify.exe',
        'cantor-evox2-scratch-build-package-verify.exe',
        'cantor-evox2-scratch-build-executor.exe',
        'cantor-evox2-scratch-build-operation-runner.exe',
        'cantor-evox2-scratch-build-package-compose.exe'
    )
    foreach ($name in $binaryNames) {
        $candidate = [IO.Path]::GetFullPath((Join-Path $releaseRoot $name))
        if (-not $candidate.StartsWith($releaseRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'release binary escaped target root' }
        if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
    }
    $env:CARGO_NET_OFFLINE = 'true'
    $env:CARGO_BUILD_JOBS = '1'
    $env:CARGO_INCREMENTAL = '0'
    $env:RUST_TEST_THREADS = '1'
    $env:RUST_MIN_STACK = '33554432'
    & cargo.exe build --manifest-path (Join-Path $sourceRoot 'Cargo.toml') --target-dir $targetRoot --release --locked --offline --bin cantor-evox2-scratch-build-commission --bin cantor-evox2-scratch-build-commission-verify --bin cantor-evox2-scratch-build-receipt-verify --bin cantor-evox2-scratch-build-package-verify --bin cantor-evox2-scratch-build-executor --bin cantor-evox2-scratch-build-operation-runner --bin cantor-evox2-scratch-build-package-compose
    if ($LASTEXITCODE -ne 0) { throw 'fresh locked-offline package binary build failed' }

    $binRoot = Join-Path $package 'bin'
    $scriptRoot = Join-Path $package 'scripts'
    $evidenceRoot = Join-Path $package 'evidence'
    New-Item -ItemType Directory -Path $binRoot, $scriptRoot, $evidenceRoot | Out-Null
    foreach ($name in $binaryNames | Where-Object { $_ -cne 'cantor-evox2-scratch-build-package-compose.exe' }) {
        Copy-Item -LiteralPath (Join-Path $releaseRoot $name) -Destination (Join-Path $binRoot $name)
    }
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'scripts\invoke-cantor-evox2-scratch-build-once.ps1') -Destination $scriptRoot
    Copy-CanonicalRepositoryJson (Join-Path $sourceRoot 'experiments\evox2_plan_only_build_job_p0\live_evidence_2026-09-08_09cf6304\request.json') (Join-Path $package 'request.json')
    Copy-CanonicalRepositoryJson (Join-Path $sourceRoot 'experiments\evox2_plan_only_build_job_p0\live_evidence_2026-09-08_09cf6304\plan-1.json') (Join-Path $package 'plan.json')
    Copy-CanonicalRepositoryJson (Join-Path $sourceRoot 'experiments\evox2_plan_only_build_job_p0\live_evidence_2026-09-08_09cf6304\verification-1.json') (Join-Path $package 'plan_verification.json')
    Copy-Item -LiteralPath $sourceArchive -Destination (Join-Path $package 'source.tar')
    foreach ($copy in @(
        @('specifications\Cantor_EVO_X2_Scratch_Build_Executor_P0.sop', 'specification.sop'),
        @('solutions\Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop', 'solution.sop'),
        @('plans\Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop', 'plan.sop'),
        @('narrative\research\Cantor_EVO_X2_Scratch_Build_Executor_P0_Data_Design_2026-09-09.sop', 'data-design.sop'),
        @('narrative\research\Cantor_EVO_X2_Scratch_Build_Executor_P0_Acyclic_Package_Design_2026-09-09.sop', 'acyclic-package-design.sop'),
        @('proofs\Cantor_EVO_X2_Scratch_Build_Executor_P0_Local_Core_Implementation_Proof.sop', 'local-core-implementation-proof.sop'),
        @('proofs\Cantor_EVO_X2_Scratch_Build_Executor_P0_Local_Core_Publication_Proof.sop', 'local-core-publication-proof.sop'),
        @('feature_support\Cantor_EVO_X2_Scratch_Build_Executor_P0_Local_Core_Coverage.sop', 'local-core-coverage.sop'),
        @('experiments\evox2_scratch_build_executor_p0\local_core_evidence_manifest.json', 'local-core-evidence-manifest.json')
    )) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $copy[0]) -Destination (Join-Path $evidenceRoot $copy[1])
    }

    $compiler = Join-Path $binRoot 'cantor-evox2-scratch-build-commission.exe'
    $composer = Join-Path $releaseRoot 'cantor-evox2-scratch-build-package-compose.exe'
    Push-Location -LiteralPath $package
    try {
        $commandSet = ((& $compiler command-set) | Out-String).TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0) { throw 'command-set compilation failed' }
        [IO.File]::WriteAllText((Join-Path $package 'command_set.json'), $commandSet, [Text.UTF8Encoding]::new($false))
        $manifest = ((& $composer manifest --implementation-commit $ImplementationCommit) | Out-String).TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0) { throw 'implementation manifest composition failed' }
        [IO.File]::WriteAllText((Join-Path $package 'implementation_manifest.json'), $manifest, [Text.UTF8Encoding]::new($false))
        $commission = ((& $compiler implementation_manifest.json command_set.json) | Out-String).TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0) { throw 'commission compilation failed' }
        [IO.File]::WriteAllText((Join-Path $package 'commission.json'), $commission, [Text.UTF8Encoding]::new($false))
        $envelope = ((& $composer envelope implementation_manifest.json command_set.json commission.json) | Out-String).TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0) { throw 'deployment envelope composition failed' }
        [IO.File]::WriteAllText((Join-Path $package 'deployment_envelope.json'), $envelope, [Text.UTF8Encoding]::new($false))
        $verificationRaw = ((& (Join-Path $binRoot 'cantor-evox2-scratch-build-package-verify.exe') implementation_manifest.json command_set.json commission.json deployment_envelope.json) | Out-String).TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0) { throw 'complete package verification failed' }
        $verification = $verificationRaw | ConvertFrom-Json
        if ($verification.status -cne 'passed' -or [int] $verification.artifact_count -ne 21 -or [int] $verification.package_file_count -ne 24 -or [int] $verification.authority_grants -ne 0 -or [int] $verification.effects -ne 0) { throw 'complete package verification semantics differ' }
    } finally {
        Pop-Location
    }
    [ordered]@{
        profile = 'cantor-evox2-scratch-build-package-construction/0.1'
        status = 'passed'
        implementation_commit = $ImplementationCommit
        publication_bookend_commit = $PublicationBookendCommit
        package_root = $package
        source_archive_sha256 = $sourceArchiveSha256
        artifact_count = 21
        package_file_count = 24
        implementation_manifest_sha256 = [string] $verification.implementation_manifest_sha256
        commission_sha256 = [string] $verification.commission_sha256
        command_set_sha256 = [string] $verification.command_set_sha256
        package_aggregate_bytes = [int64] $verification.package_aggregate_bytes
        authority_grants = 0
        remote_calls = 0
        effects = 0
    } | ConvertTo-Json -Depth 10 -Compress
} finally {
    $env:CARGO_NET_OFFLINE = $previousOffline
    $env:CARGO_BUILD_JOBS = $previousJobs
    $env:CARGO_INCREMENTAL = $previousIncremental
    $env:RUST_TEST_THREADS = $previousTests
    $env:RUST_MIN_STACK = $previousStack
    if (Test-Path -LiteralPath $scratch) { [IO.Directory]::Delete(('\\?\' + $scratch), $true) }
}
