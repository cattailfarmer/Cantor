[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/nested_outer_host_identity_p0/artifacts/nested_outer_host_identity_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullManifestPath = if ([IO.Path]::IsPathRooted($ManifestPath)) {
    [IO.Path]::GetFullPath($ManifestPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $ManifestPath))
}
$manifest = Get-Content -LiteralPath $fullManifestPath -Raw | ConvertFrom-Json

if ($manifest.profile -ne 'cantor-nested-outer-host-identity-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -ne '665919b1-aa6d-4abc-b5ca-6f24820c0578' -or
    $manifest.canonical_uuid -ne '762ca2d3-c279-4e73-ad1c-990f31950a28' -or
    $manifest.source_uuid -ne '6fa07b14-4a49-495c-834f-be2b7dd0f7ea' -or
    $manifest.current_target_source_uuid -ne '521e430b-1371-44ad-8364-f1420fd43c25' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') {
    throw 'evidence manifest identity differs'
}

$requiredPaths = @(
    'crates/cantor_core/src/nested_host_identity.rs',
    'crates/cantor_core/tests/nested_host_identity.rs',
    'specifications/Cantor_Nested_Outer_Host_Identity_P0.sop',
    'proofs/Cantor_Nested_Outer_Host_Identity_P0_Proof.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/Cantor_SOP_Bootable_Self_Working_Agent_Target_Source.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop'
)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$verified = 0
foreach ($artifact in @($manifest.artifacts)) {
    $relativePath = [string]$artifact.path
    if (-not $seen.Add($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or
        $relativePath -match '(^|/)\.\.(/|$)') {
        throw "duplicate or nonportable evidence path: $relativePath"
    }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "evidence path is not one physical file: $relativePath"
    }
    $actualHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    if ([uint64]$artifact.bytes -ne [uint64]$item.Length -or
        ([string]$artifact.sha256).ToUpperInvariant() -ne $actualHash) {
        throw "evidence identity differs: $relativePath"
    }
    $verified++
}
foreach ($requiredPath in $requiredPaths) {
    if (-not $seen.Contains($requiredPath)) {
        throw "required evidence path is absent: $requiredPath"
    }
}
if ($manifest.non_authority_statement -notmatch 'no process observation or launch' -or
    $manifest.non_authority_statement -notmatch 'workspace mutation') {
    throw 'evidence non-authority statement differs'
}

Write-Output "nested_outer_host_identity_evidence_verified artifacts=$verified refusals_preserved=true"
