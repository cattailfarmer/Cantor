[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-scratch-build-executor-p0-package-f5b904fc',
    [switch] $AllowCopiedPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$evidence = Get-Content -LiteralPath (Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\package_construction_evidence.json') -Raw | ConvertFrom-Json
$package = [IO.Path]::GetFullPath($PackageRoot)
$buildParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
if (-not $package.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'package verification root escaped build parent' }
$packageItem = Get-Item -LiteralPath $package -Force
if (-not $packageItem.PSIsContainer -or ($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'package verification root boundary differs' }

if ($evidence.profile -cne 'cantor-evox2-scratch-build-package-construction-evidence/0.1' -or $evidence.evidence_uuid -cne 'e8c20413-1efb-4447-8480-c716dddce462' -or $evidence.canonical_uuid -cne '935e020f-8c6f-49e4-b355-63eabd3b778b' -or $evidence.implementation_commit -cne 'f5b904fc8cf48b34672dead0596e9de6e706f38b' -or $evidence.publication_bookend_commit -cne '8b8304d9192f9741598a65c88ec48ec463121d43') { throw 'package construction evidence identity differs' }
$evidencePackage = [IO.Path]::GetFullPath(([string] $evidence.package_root).Replace('/', '\'))
$expectedPackage = [IO.Path]::GetFullPath('D:\CantorBuilds\evox2-scratch-build-executor-p0-package-f5b904fc')
if ($evidencePackage -cne $expectedPackage) { throw 'package construction evidence root differs' }
if (-not $AllowCopiedPackage -and $package -cne $evidencePackage) { throw 'package verification root is not the admitted package' }
if ([int] $evidence.package_artifacts -ne 21 -or [int] $evidence.package_files -ne 24 -or @($evidence.files).Count -ne 24 -or [int] $evidence.commission_authority_grants -ne 5 -or [int] $evidence.construction_authority_grants -ne 0 -or [int] $evidence.adversarial_copy_successes -ne 1 -or [int] $evidence.adversarial_copy_refusals -ne 4) { throw 'package construction evidence cardinality differs' }
if (-not [bool] $evidence.package_constructed -or -not [bool] $evidence.package_verified -or [bool] $evidence.live_effects_authorized -or [bool] $evidence.physical_build_performed -or [int] $evidence.provider_requests -ne 0 -or [int] $evidence.remote_calls -ne 0 -or [int] $evidence.effects -ne 0) { throw 'package construction evidence claim differs' }

$seen = @{}
$rows = @()
[int64] $aggregate = 0
foreach ($file in @($evidence.files)) {
    $relative = [string] $file.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative.Contains('\')) { throw 'package evidence file coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'package evidence duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $package $relative.Replace('/', '\')
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $file.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $file.sha256) { throw "package evidence file identity differs: $relative" }
    $aggregate += [int64] $item.Length
    $rows += "$relative|$($item.Length)|$([string] $file.sha256)"
}
$actualFiles = @(Get-ChildItem -LiteralPath $package -Recurse -Force | Where-Object { -not $_.PSIsContainer })
if ($actualFiles.Count -ne 24 -or $aggregate -ne [int64] $evidence.aggregate_bytes) { throw 'package evidence actual cardinality differs' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $setSha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($rows -join "`n"))) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
if ($setSha256 -cne [string] $evidence.package_set_sha256) { throw 'package evidence set digest differs' }

Push-Location -LiteralPath $package
try {
    $raw = ((& .\bin\cantor-evox2-scratch-build-package-verify.exe implementation_manifest.json command_set.json commission.json deployment_envelope.json) | Out-String).TrimEnd("`r", "`n")
    if ($LASTEXITCODE -ne 0) { throw 'independent package verifier refused' }
} finally { Pop-Location }
$verification = $raw | ConvertFrom-Json
if ($verification.status -cne 'passed' -or [int] $verification.artifact_count -ne 21 -or [int] $verification.package_file_count -ne 24 -or [int64] $verification.package_aggregate_bytes -ne [int64] $evidence.aggregate_bytes -or $verification.implementation_manifest_sha256 -cne $evidence.implementation_manifest_sha256 -or $verification.commission_sha256 -cne $evidence.commission_sha256 -or $verification.command_set_sha256 -cne $evidence.command_set_sha256 -or [int] $verification.authority_grants -ne 5 -or [int] $verification.effects -ne 0) { throw 'independent package verifier correspondence differs' }

"cantor_evox2_scratch_build_package_construction_verified=true files=24 artifacts=21 aggregate=$aggregate set_sha256=$setSha256 commission_grants=5 construction_grants=0 provider_requests=0 remote_calls=0 effects=0 live_effects_authorized=false physical_build_performed=false"
