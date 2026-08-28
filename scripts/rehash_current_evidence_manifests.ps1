param([switch]$VerifyOnly)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$frozen = @(
  "crates/cantor_ecosystem/evidence/phase3_topology_forms_evidence_manifest_0_1.json",
  "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest_0_1.json",
  "crates/cantor_ecosystem/evidence/windows_platform_preflight_forms_evidence_manifest_0_2.json"
)
$manifestPaths = @{}
@("crates", "experiments") | ForEach-Object {
  Get-ChildItem -LiteralPath (Join-Path $repositoryRoot $_) -Recurse -Filter "*evidence_manifest*.json"
} | ForEach-Object {
    $relative = $_.FullName.Substring($repositoryRoot.Length + 1).Replace("\", "/")
    $candidate = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    if (
      $frozen -notcontains $relative -and
      $null -ne $candidate.PSObject.Properties["artifacts"] -and
      $null -ne $candidate.artifacts
    ) {
      $manifestPaths[$relative] = $_.FullName
    }
  }
$states = @{}
$script:references = 0
$script:stale = 0

function Resolve-ArtifactPath([string]$ManifestPath, [string]$ArtifactPath) {
  if ([IO.Path]::IsPathRooted($ArtifactPath) -or $ArtifactPath -match '(^|[\\/])\.\.([\\/]|$)') {
    throw "nonportable evidence artifact: $ManifestPath -> $ArtifactPath"
  }
  $rootCandidate = Join-Path $repositoryRoot $ArtifactPath
  if (Test-Path -LiteralPath $rootCandidate -PathType Leaf) {
    return (Get-Item -LiteralPath $rootCandidate).FullName
  }
  $localCandidate = Join-Path (Split-Path -Parent $ManifestPath) $ArtifactPath
  if (Test-Path -LiteralPath $localCandidate -PathType Leaf) {
    return (Get-Item -LiteralPath $localCandidate).FullName
  }
  throw "evidence artifact is absent from repository-root and manifest-local resolution: $ManifestPath -> $ArtifactPath"
}

function Read-ArtifactSha256($Artifact, [string]$ManifestPath) {
  if ($Artifact.sha256 -is [string]) {
    return [string]$Artifact.sha256
  }
  if (
    $null -ne $Artifact.sha256 -and
    $Artifact.sha256.algorithm -ceq "sha256" -and
    $Artifact.sha256.value -is [string]
  ) {
    return [string]$Artifact.sha256.value
  }
  throw "unsupported evidence SHA256 form: $ManifestPath -> $($Artifact.path)"
}

function Set-ArtifactSha256($Artifact, [string]$ActualHash, [string]$ManifestPath) {
  if ($Artifact.sha256 -is [string]) {
    $Artifact.sha256 = $ActualHash
    return
  }
  if (
    $null -ne $Artifact.sha256 -and
    $Artifact.sha256.algorithm -ceq "sha256" -and
    $Artifact.sha256.value -is [string]
  ) {
    $Artifact.sha256.value = $ActualHash.ToLowerInvariant()
    return
  }
  throw "unsupported evidence SHA256 form: $ManifestPath -> $($Artifact.path)"
}

function Update-Manifest([string]$RelativePath) {
  if ($states[$RelativePath] -eq "done") { return }
  if ($states[$RelativePath] -eq "visiting") { throw "evidence manifest cycle: $RelativePath" }
  $states[$RelativePath] = "visiting"
  $fullPath = $manifestPaths[$RelativePath]
  $manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
  $manifestChanged = $false
  if ($null -eq $manifest.PSObject.Properties["artifacts"] -or $null -eq $manifest.artifacts) {
    throw "current evidence manifest lacks artifacts: $RelativePath"
  }
  foreach ($artifact in @($manifest.artifacts)) {
    $artifactPath = [string]$artifact.path
    $resolvedDependency = Resolve-ArtifactPath $fullPath $artifactPath
    $dependency = $resolvedDependency.Substring($repositoryRoot.Length + 1).Replace("\", "/")
    if ($manifestPaths.ContainsKey($dependency)) { Update-Manifest $dependency }
  }
  foreach ($artifact in @($manifest.artifacts)) {
    $artifactPath = [string]$artifact.path
    $item = Get-Item -LiteralPath (Resolve-ArtifactPath $fullPath $artifactPath)
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
    $expectedHash = Read-ArtifactSha256 $artifact $fullPath
    $artifactStale = [long]$artifact.bytes -ne $item.Length -or $expectedHash.ToUpperInvariant() -ne $actualHash
    $script:references++
    if ($VerifyOnly) {
      if ($artifactStale) {
        $script:stale++
      }
    } elseif ($artifactStale) {
      $artifact.bytes = $item.Length
      Set-ArtifactSha256 $artifact $actualHash $fullPath
      $manifestChanged = $true
    }
  }
  if (-not $VerifyOnly -and $manifestChanged) {
    if ($null -ne $manifest.PSObject.Properties["generated_at_utc"]) {
      $manifest.generated_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    [IO.File]::WriteAllText(
      $fullPath,
      "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
      [Text.UTF8Encoding]::new($false)
    )
  }
  $states[$RelativePath] = "done"
}

foreach ($relative in @($manifestPaths.Keys | Sort-Object)) { Update-Manifest $relative }
if ($VerifyOnly -and $script:stale -ne 0) {
  throw "stale evidence records: $($script:stale) across $($manifestPaths.Count) manifests and $($script:references) references"
}
Write-Output "current_manifests=$($manifestPaths.Count) artifact_references=$($script:references) stale=$($script:stale)"
