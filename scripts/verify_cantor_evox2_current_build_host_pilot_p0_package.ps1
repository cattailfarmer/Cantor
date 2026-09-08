[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedCommit = '8e37e3e701d41d61328f89296ae77b8ea3707812'
$expectedRef = 'refs/heads/codex/self-hosted-corpus'
$expectedHost = 'EVO-X2'
$expectedRemoteRoot = 'C:/AI/services/cantor-current-pilot-48479932'
$manifestDomain = 'cantor-evox2-current-build-pilot-deployment-manifest-v1'
$expectedManifestFields = @(
    'profile', 'manifest_uuid', 'source_commit', 'source_ref', 'target_host', 'remote_root',
    'protected_roots', 'artifact_count', 'aggregate_bytes', 'artifacts', 'allowed_executions', 'manifest_sha256'
)
$expectedArtifactFields = @('relative_path', 'role', 'bytes', 'sha256', 'executable', 'source_locator')
$expectedProtectedRoots = @(
    'C:/AI/services/cantor-attention-mcp',
    'C:/AI/services/cantor-needle-runtime',
    'C:/AI/services/sop-agent'
)
$expectedExecutions = @('a8_evidence_replay', 'optional_cantor_public_query_replay')

function Assert-Exact([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Get-Sha256Text([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

function Assert-ExactFieldOrder($Object, [string[]] $Fields, [string] $Name) {
    $actual = @($Object.PSObject.Properties.Name)
    Assert-Exact ($actual.Count -eq $Fields.Count) "$Name field count changed"
    for ($index = 0; $index -lt $Fields.Count; $index++) {
        Assert-Exact ($actual[$index] -ceq $Fields[$index]) "$Name field order changed"
    }
}

function Assert-RelativePath([string] $Value) {
    Assert-Exact ($Value.Length -ge 1 -and $Value.Length -le 256) 'relative path length is invalid'
    Assert-Exact ($Value -cmatch '^[A-Za-z0-9._/-]+$') 'relative path grammar is invalid'
    Assert-Exact (-not $Value.StartsWith('/', [StringComparison]::Ordinal)) 'absolute relative path refused'
    Assert-Exact (-not $Value.EndsWith('/', [StringComparison]::Ordinal)) 'directory relative path refused'
    foreach ($segment in $Value.Split('/')) {
        Assert-Exact ($segment.Length -gt 0 -and $segment -cne '.' -and $segment -cne '..') 'relative path segment is invalid'
        Assert-Exact (-not $segment.EndsWith('.', [StringComparison]::Ordinal) -and -not $segment.EndsWith(' ', [StringComparison]::Ordinal)) 'relative path trailing character refused'
    }
}

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$rootItem = Get-Item -LiteralPath $root
Assert-Exact ($rootItem.PSIsContainer -and -not ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'package root must be a direct directory'
$manifestPath = Join-Path $root 'deployment_manifest.json'
Assert-Exact (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'deployment manifest is missing'
$manifestItem = Get-Item -LiteralPath $manifestPath
Assert-Exact (-not ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'deployment manifest cannot be a link'
$manifestRaw = Get-Content -LiteralPath $manifestPath -Raw
Assert-Exact ($manifestRaw.EndsWith("`n", [StringComparison]::Ordinal) -and -not $manifestRaw.EndsWith("`r`n", [StringComparison]::Ordinal)) 'deployment manifest transport must end in one LF'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$trackedManifestPath = Join-Path $repositoryRoot 'experiments\evox2_current_build_host_pilot_p0\implementation_package_manifest.json'
Assert-Exact (Test-Path -LiteralPath $trackedManifestPath -PathType Leaf) 'tracked implementation package manifest is missing'
$trackedManifestRaw = Get-Content -LiteralPath $trackedManifestPath -Raw
Assert-Exact ($trackedManifestRaw -ceq $manifestRaw) 'package manifest differs from tracked implementation evidence'
$manifest = $manifestRaw | ConvertFrom-Json
Assert-ExactFieldOrder $manifest $expectedManifestFields 'manifest'
Assert-Exact ($manifest.profile -ceq 'cantor-evox2-current-build-pilot-deployment-manifest/0.1') 'manifest profile changed'
Assert-Exact ($manifest.manifest_uuid -ceq '768b0ac7-c1f6-4781-ab9d-d0c1bf9098f4') 'manifest UUID changed'
Assert-Exact ($manifest.source_commit -ceq $expectedCommit -and $manifest.source_ref -ceq $expectedRef) 'source lineage changed'
Assert-Exact ($manifest.target_host -ceq $expectedHost -and $manifest.remote_root -ceq $expectedRemoteRoot) 'deployment target changed'
Assert-Exact (@($manifest.protected_roots).Count -eq $expectedProtectedRoots.Count) 'protected root count changed'
for ($index = 0; $index -lt $expectedProtectedRoots.Count; $index++) {
    Assert-Exact ($manifest.protected_roots[$index] -ceq $expectedProtectedRoots[$index]) 'protected root identity changed'
}
Assert-Exact (@($manifest.allowed_executions).Count -eq $expectedExecutions.Count) 'allowed execution count changed'
for ($index = 0; $index -lt $expectedExecutions.Count; $index++) {
    Assert-Exact ($manifest.allowed_executions[$index] -ceq $expectedExecutions[$index]) 'allowed execution identity changed'
}

$artifacts = @($manifest.artifacts)
Assert-Exact ($artifacts.Count -eq [int]$manifest.artifact_count -and $artifacts.Count -eq 36) 'artifact count changed'
Assert-Exact ($artifacts.Count -le 128) 'artifact count exceeds bound'
$seen = @{}
$aggregate = [int64]0
$binaryRoles = @{}
$evidenceCount = 0
$manifestPaths = @()
foreach ($artifact in $artifacts) {
    Assert-ExactFieldOrder $artifact $expectedArtifactFields 'artifact'
    $relative = [string]$artifact.relative_path
    Assert-RelativePath $relative
    $key = $relative.ToUpperInvariant()
    Assert-Exact (-not $seen.ContainsKey($key)) 'duplicate case-folded artifact path'
    $seen[$key] = $true
    $manifestPaths += $relative
    $bytes = [int64]$artifact.bytes
    Assert-Exact ($bytes -ge 1 -and $bytes -le 67108864) 'artifact byte count exceeds bound'
    Assert-Exact ([string]$artifact.sha256 -cmatch '^[0-9a-f]{64}$') 'artifact digest grammar changed'
    Assert-Exact ([string]$artifact.source_locator -cmatch '^[A-Za-z0-9._/-]{1,512}$') 'source locator grammar changed'
    Assert-Exact ($artifact.executable -is [bool]) 'artifact executable flag is not Boolean'
    $role = [string]$artifact.role
    Assert-Exact (@('current_cantor_query', 'current_a8_evidence_verifier', 'retained_a8_evidence') -ccontains $role) 'artifact role is not admitted in P0 package'
    if ($role -ceq 'retained_a8_evidence') {
        Assert-Exact (-not $artifact.executable) 'evidence artifact cannot be executable'
        $evidenceCount++
    } else {
        Assert-Exact $artifact.executable 'selected binary must be executable'
        Assert-Exact (-not $binaryRoles.ContainsKey($role)) 'duplicate selected binary role'
        $binaryRoles[$role] = $relative
    }
    $path = Join-Path $root $relative
    Assert-Exact (Test-Path -LiteralPath $path -PathType Leaf) 'manifest artifact is missing'
    $item = Get-Item -LiteralPath $path
    Assert-Exact (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'linked artifact refused'
    Assert-Exact ($item.Length -eq $bytes) 'artifact bytes changed'
    Assert-Exact ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$artifact.sha256) 'artifact digest changed'
    $aggregate += $bytes
    Assert-Exact ($aggregate -le 1073741824) 'aggregate bytes exceed bound'
}
Assert-Exact ($evidenceCount -eq 34 -and $binaryRoles.Count -eq 2) 'package role cardinality changed'
Assert-Exact ($binaryRoles.current_cantor_query -ceq 'bin/cantor.exe') 'Cantor query binary path changed'
Assert-Exact ($binaryRoles.current_a8_evidence_verifier -ceq 'bin/cantor-b1-production-broker-projection-evidence-verify.exe') 'A8 verifier path changed'
Assert-Exact ($aggregate -eq [int64]$manifest.aggregate_bytes) 'aggregate bytes changed'

$actualFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
    Assert-Exact (-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'linked package file refused'
    $_.FullName.Substring($root.Length + 1).Replace('\', '/')
} | Sort-Object)
$expectedFiles = @($manifestPaths + 'deployment_manifest.json' | Sort-Object)
Assert-Exact ($actualFiles.Count -eq $expectedFiles.Count) 'package contains missing or extra files'
for ($index = 0; $index -lt $expectedFiles.Count; $index++) {
    Assert-Exact ($actualFiles[$index] -ceq $expectedFiles[$index]) 'package membership changed'
}

$providedDigest = [string]$manifest.manifest_sha256
Assert-Exact ($providedDigest -cmatch '^[0-9a-f]{64}$') 'manifest digest grammar changed'
$manifest.manifest_sha256 = ''
$canonical = $manifest | ConvertTo-Json -Depth 20 -Compress
$actualDigest = Get-Sha256Text ($manifestDomain + [char]0 + $canonical)
Assert-Exact ($actualDigest -ceq $providedDigest) 'manifest self digest changed'

[pscustomobject]@{
    profile = 'cantor-evox2-current-build-pilot-package-verification/0.1'
    status = 'verified'
    source_commit = $expectedCommit
    manifest_sha256 = $providedDigest
    artifact_count = $artifacts.Count
    evidence_count = $evidenceCount
    aggregate_bytes = $aggregate
    remote_root = $expectedRemoteRoot
} | ConvertTo-Json -Compress
