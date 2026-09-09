[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $PackageRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packagePath = (Resolve-Path -LiteralPath $PackageRoot).Path
$packageItem = Get-Item -LiteralPath $packagePath
if (-not $packageItem.PSIsContainer -or ($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'package root boundary refused' }

$manifestPath = Join-Path $packagePath 'deployment_manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'deployment manifest missing' }
$manifestItem = Get-Item -LiteralPath $manifestPath
if ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'deployment manifest link refused' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-plan-only-build-job-deployment-manifest/0.1' 'profile'
Assert-Equal $manifest.manifest_uuid 'c630bbd9-d718-40cd-87fd-39e753b4923f' 'manifest_uuid'
Assert-Equal $manifest.canonical_uuid '3482e2ce-817c-4788-b185-35adaad414f7' 'canonical_uuid'
Assert-Equal $manifest.source_commit '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271' 'source_commit'
Assert-Equal $manifest.source_ref 'refs/heads/codex/self-hosted-corpus' 'source_ref'
Assert-Equal $manifest.target_host 'EVO-X2' 'target_host'
Assert-Equal $manifest.remote_root 'C:/AI/services/cantor-build-planner-d805681d' 'remote_root'
Assert-Equal $manifest.future_workspace_root 'C:/AI/workspaces/cantor-build-4fdd29cb' 'future_workspace_root'
Assert-Equal $manifest.future_target_root 'C:/AI/builds/cantor-build-4fdd29cb' 'future_target_root'
if (@($manifest.artifacts).Count -ne 9 -or [int64] $manifest.artifact_count -ne 9) { throw 'artifact count mismatch' }
if ([int64] $manifest.aggregate_bytes -le 0 -or [int64] $manifest.aggregate_bytes -gt 16777216) { throw 'aggregate bound mismatch' }
if (@($manifest.authority_grants).Count -ne 0) { throw 'package authority grant admitted' }
$expectedExecutions = @('compiler_process_1', 'compiler_process_2', 'verifier_process_1', 'verifier_process_2')
if ((@($manifest.allowed_executions) -join [char]0) -cne ($expectedExecutions -join [char]0)) { throw 'allowed execution set mismatch' }

$seen = @{}
$aggregate = [int64] 0
foreach ($artifact in $manifest.artifacts) {
    $relative = [string] $artifact.relative_path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative.Contains('\')) { throw 'nonportable artifact path' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'duplicate artifact path' }
    $seen[$key] = $true
    $path = Join-Path $packagePath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($null -ne $item.PSObject.Properties['LinkType'] -and -not [string]::IsNullOrEmpty([string] $item.LinkType))) { throw "linked artifact $relative" }
    if ($item.Length -ne [int64] $artifact.bytes) { throw "byte mismatch $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "hash mismatch $relative" }
    $aggregate += [int64] $item.Length
}
if ($aggregate -ne [int64] $manifest.aggregate_bytes) { throw 'aggregate byte mismatch' }

$expectedPaths = @(
    'bin/cantor-evox2-plan-only-build-job.exe',
    'bin/cantor-evox2-plan-only-build-job-verify.exe',
    'request.json',
    'evidence/specification.sop',
    'evidence/local-core-implementation-proof.sop',
    'evidence/local-core-publication-proof.sop',
    'evidence/local-core-coverage.sop',
    'evidence/local-core-phase-checkpoint.sop',
    'evidence/local-core-evidence-manifest.json'
)
if (($seen.Keys | Sort-Object) -join [char]0 -cne (($expectedPaths | ForEach-Object { $_.ToUpperInvariant() } | Sort-Object) -join [char]0)) { throw 'artifact membership mismatch' }
$actualFiles = @(Get-ChildItem -LiteralPath $packagePath -Recurse -Force -File)
if ($actualFiles.Count -ne 10) { throw 'package file cardinality mismatch' }
foreach ($item in Get-ChildItem -LiteralPath $packagePath -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'package reparse point refused' }
}

$unsignedManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$unsignedManifest.manifest_sha256 = ''
$canonicalManifest = $unsignedManifest | ConvertTo-Json -Depth 20 -Compress
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $expectedManifestSha = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('cantor-evox2-plan-only-build-job-deployment-manifest-v1' + [char]0 + $canonicalManifest)) | ForEach-Object { $_.ToString('x2') })
} finally { $sha.Dispose() }
Assert-Equal $manifest.manifest_sha256 $expectedManifestSha 'manifest_sha256'

$requestPath = Join-Path $packagePath 'request.json'
$requestRaw = [IO.File]::ReadAllText($requestPath, [Text.Encoding]::UTF8)
$request = $requestRaw | ConvertFrom-Json
if (@($request.PSObject.Properties).Count -ne 16) { throw 'request field count mismatch' }
Assert-Equal $request.profile 'cantor-evox2-plan-only-build-job/0.1' 'request profile'
Assert-Equal $request.request_uuid '56d04713-7953-4e7e-aa9d-37f1027626b8' 'request_uuid'
Assert-Equal $request.predecessor_canonical_uuid '4cf12917-73e8-4505-9228-f94d981143bd' 'predecessor_canonical_uuid'
Assert-Equal $request.predecessor_bookend_commit 'd805681daee0d6846574875e25b6e1e41c9207bc' 'predecessor_bookend_commit'
Assert-Equal $request.source_commit $manifest.source_commit 'request source_commit'
Assert-Equal $request.repository_remote_ref 'https://github.com/cattailfarmer/Cantor' 'repository_remote_ref'
Assert-Equal $request.target_host 'EVO-X2' 'request target_host'
Assert-Equal $request.target_os 'windows-x86_64' 'target_os'
Assert-Equal $request.future_workspace_root $manifest.future_workspace_root 'request future_workspace_root'
Assert-Equal $request.future_target_root $manifest.future_target_root 'request future_target_root'
Assert-Equal $request.cargo_profile 'locked-offline-serialized/0.1' 'cargo_profile'
if ([string] $request.source_archive_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'source archive digest form mismatch' }
$checks = @('workspace_debug', 'workspace_release', 'workspace_clippy', 'workspace_format')
if ((@($request.requested_checks) -join [char]0) -cne ($checks -join [char]0)) { throw 'requested checks mismatch' }
$denials = @('source_transfer', 'source_extract', 'toolchain_observe', 'toolchain_install', 'dependency_fetch', 'workspace_write', 'process_execute', 'git_mutation', 'commit', 'push', 'provider_call', 'model_inference', 'service_change', 'external_network', 'security_policy_change')
if ((@($request.authority_denials) -join [char]0) -cne ($denials -join [char]0)) { throw 'request denial set mismatch' }
if ([int64] $request.bounds.maximum_archive_bytes -ne 268435456 -or [int64] $request.bounds.maximum_files -ne 16384 -or [int64] $request.bounds.maximum_stdout_bytes -ne 262144 -or [int64] $request.bounds.maximum_operation_count -ne 7 -or [int64] $request.bounds.timeout_seconds -ne 7200 -or [int64] $request.bounds.cargo_build_jobs -ne 1) { throw 'request bounds mismatch' }
$unsignedRequest = $requestRaw | ConvertFrom-Json
$unsignedRequest.request_sha256 = ''
$canonicalRequest = $unsignedRequest | ConvertTo-Json -Depth 20 -Compress
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $expectedRequestSha = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('cantor.evox2-plan-only-build-job.request.v1' + [char]0 + $canonicalRequest)) | ForEach-Object { $_.ToString('x2') })
} finally { $sha.Dispose() }
Assert-Equal $request.request_sha256 $expectedRequestSha 'request_sha256'
if (($request | ConvertTo-Json -Depth 20 -Compress) -cne $requestRaw) { throw 'request raw bytes are noncanonical' }

[pscustomobject]@{
    profile = 'cantor-evox2-plan-only-build-job-package-verification/0.1'
    status = 'passed'
    source_commit = [string] $manifest.source_commit
    source_archive_sha256 = [string] $request.source_archive_sha256
    manifest_uuid = [string] $manifest.manifest_uuid
    manifest_sha256 = [string] $manifest.manifest_sha256
    artifact_count = 9
    aggregate_bytes = $aggregate
    authority_grants = 0
    effects = 0
} | ConvertTo-Json -Compress
