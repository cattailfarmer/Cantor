[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/sop_boot_session_admission_p0/artifacts/sop_boot_session_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullPath = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path $root $ManifestPath)) }
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -ne 'cantor-sop-boot-session-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -ne 'd3e5f80b-9e83-4911-8582-05b77c0fb2ee' -or
    $manifest.canonical_uuid -ne 'a4dff0f3-9381-4c9e-b580-bcde9d3122a5' -or
    $manifest.source_uuid -ne '521e430b-1371-44ad-8364-f1420fd43c25' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
$required = @(
    'crates/cantor_core/src/sop_boot_session.rs',
    'crates/cantor_core/tests/sop_boot_session.rs',
    'specifications/Cantor_SOP_Boot_Session_Admission_P0.sop',
    'proofs/Cantor_SOP_Boot_Session_Admission_P0_Proof.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/Cantor_SOP_Bootable_Self_Working_Agent_Target_Source.sop'
)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$verified = 0
foreach ($artifact in @($manifest.artifacts)) {
    $relativePath = [string]$artifact.path
    if (-not $seen.Add($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|/)\.\.(/|$)') { throw "duplicate or nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    if ([uint64]$artifact.bytes -ne [uint64]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -ne $hash) { throw "artifact identity differs: $relativePath" }
    $verified++
}
foreach ($path in $required) { if (-not $seen.Contains($path)) { throw "required path absent: $path" } }
if ($manifest.non_authority_statement -notmatch 'no SOP byte observation' -or $manifest.non_authority_statement -notmatch 'workspace access') { throw 'non-authority differs' }
Write-Output "sop_boot_session_evidence_verified artifacts=$verified"
