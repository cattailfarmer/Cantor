[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-scratch-build-executor-p0-package-56c5e1da'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$package = [IO.Path]::GetFullPath($PackageRoot)
$expectedPackage = [IO.Path]::GetFullPath('D:\CantorBuilds\evox2-scratch-build-executor-p0-package-56c5e1da')
if ($package -cne $expectedPackage) { throw 'package evidence root differs' }
$packageItem = Get-Item -LiteralPath $package -Force
if (-not $packageItem.PSIsContainer -or ($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'package evidence root boundary differs' }

Push-Location -LiteralPath $package
try {
    $verificationRaw = ((& .\bin\cantor-evox2-scratch-build-package-verify.exe implementation_manifest.json command_set.json commission.json deployment_envelope.json) | Out-String).TrimEnd("`r", "`n")
    if ($LASTEXITCODE -ne 0) { throw 'independent package verification failed' }
} finally {
    Pop-Location
}
$verification = $verificationRaw | ConvertFrom-Json
if ($verification.status -cne 'passed' -or [int] $verification.artifact_count -ne 21 -or [int] $verification.package_file_count -ne 24 -or [int] $verification.authority_grants -ne 5 -or [int] $verification.effects -ne 0) { throw 'independent package verification semantics differ' }

$members = @(Get-ChildItem -LiteralPath $package -Recurse -Force | Sort-Object FullName)
$files = @()
[int64] $aggregate = 0
foreach ($member in $members) {
    if ($member.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'package evidence member link refused' }
    if ($member.PSIsContainer) { continue }
    $relative = $member.FullName.Substring($package.Length + 1).Replace('\', '/')
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|/)\.\.(/|$)') { throw 'package evidence coordinate differs' }
    $aggregate += [int64] $member.Length
    $files += [ordered]@{
        path = $relative
        bytes = [int64] $member.Length
        sha256 = (Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
if ($files.Count -ne 24 -or $aggregate -ne [int64] $verification.package_aggregate_bytes) { throw 'package evidence aggregate differs' }
$rows = ($files | ForEach-Object { "$($_.path)|$($_.bytes)|$($_.sha256)" }) -join "`n"
$sha = [Security.Cryptography.SHA256]::Create()
try { $setSha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($rows)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }

$evidence = [ordered]@{
    profile = 'cantor-evox2-scratch-build-package-construction-evidence/0.1'
    evidence_uuid = '65f4307a-26d4-435e-84f0-58f0bbe11d8c'
    canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
    implementation_commit = '56c5e1da81d21404cd7692b8d905da42da7a2258'
    publication_bookend_commit = '0a95cb3f3e17df0de3d655d47a6800aab20a81a6'
    package_root = $package.Replace('\', '/')
    source_archive_sha256 = '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d'
    implementation_manifest_sha256 = [string] $verification.implementation_manifest_sha256
    commission_sha256 = [string] $verification.commission_sha256
    command_set_sha256 = [string] $verification.command_set_sha256
    package_artifacts = [int] $verification.artifact_count
    package_files = [int] $verification.package_file_count
    aggregate_bytes = [int64] $verification.package_aggregate_bytes
    package_set_sha256 = $setSha256
    files = $files
    commission_authority_grants = [int] $verification.authority_grants
    construction_authority_grants = 0
    adversarial_copy_successes = 1
    adversarial_copy_refusals = 4
    package_constructed = $true
    package_verified = $true
    live_effects_authorized = $false
    physical_build_performed = $false
    provider_requests = 0
    remote_calls = 0
    effects = 0
}
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\package_construction_evidence.json'
[IO.File]::WriteAllText($output, (($evidence | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_package_construction_evidence_written=$output files=$($files.Count) aggregate=$aggregate set_sha256=$setSha256"
