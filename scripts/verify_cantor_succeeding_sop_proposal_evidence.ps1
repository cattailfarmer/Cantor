[CmdletBinding()]
param([string]$ManifestPath = 'experiments/succeeding_sop_proposal_p0/artifacts/succeeding_sop_proposal_evidence_manifest.json')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullPath = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path $root $ManifestPath)) }
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-succeeding-sop-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -cne 'a4d093f6-ab42-42fc-9c9f-3c0f189df791' -or
    $manifest.canonical_uuid -cne 'cb503c5b-bbf6-433b-b65f-31683d73a7ac' -or
    $manifest.source_snapshot_uuid -cne 'd47aca42-00c5-4352-b0af-ce0ea186d795' -or
    $manifest.satisfaction_signature_uuid -cne '2b6b2279-2480-4eab-9f9d-df3a07efd95b' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
& git -C $root cat-file -e "$($manifest.source_commit)^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'manifest source commit is absent' }

$required = @(
    'crates/cantor_core/src/bin/cantor-succeeding-sop-proposal.rs',
    'crates/cantor_core/src/succeeding_sop_proposal.rs',
    'crates/cantor_core/tests/succeeding_sop_proposal.rs',
    'experiments/succeeding_sop_proposal_p0/artifacts/controlled_provider_free_verification.json',
    'narrative/registries/Cantor_Succeeding_SOP_Proposal_P0_Satisfaction_Signature.sop',
    'proofs/Cantor_Succeeding_SOP_Proposal_P0_Implementation_Proof.sop',
    'source_documents/2026-08-24_cantor_succeeding_sop_proposal_p0/Cantor_Succeeding_SOP_Proposal_P0_Source.sop',
    'specifications/Cantor_Succeeding_SOP_Proposal_P0.sop'
)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$verified = 0
foreach ($artifact in @($manifest.artifacts)) {
    $relativePath = [string]$artifact.path
    if (-not $seen.Add($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|/)\.\.(/|$)') { throw "duplicate or nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    $actual = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    if ([uint64]$artifact.bytes -ne [uint64]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -cne $actual) { throw "artifact identity differs: $relativePath" }
    $verified++
}
foreach ($path in $required) { if (-not $seen.Contains($path)) { throw "required artifact absent: $path" } }

$controlled = Get-Content -LiteralPath (Join-Path $root 'experiments/succeeding_sop_proposal_p0/artifacts/controlled_provider_free_verification.json') -Raw | ConvertFrom-Json
if ($controlled.profile -cne 'cantor-succeeding-sop-controlled-verification/0.1' -or
    $controlled.evidence_uuid -cne '96afcd79-8ea7-48bd-96b3-1deadcba4ca6' -or
    $controlled.status -cne 'provider_free_machine_verification_passed' -or
    [int]$controlled.focused.wsl_debug_passed -ne 26 -or
    [int]$controlled.focused.wsl_overflow_checked_release_passed -ne 26 -or
    [int]$controlled.focused.new_SWA_06A_tests -ne 8 -or
    [bool]$controlled.boundaries.provider_contacted -or
    [bool]$controlled.boundaries.model_called -or
    [bool]$controlled.boundaries.source_written -or
    [bool]$controlled.boundaries.sop_activated -or
    [int]$controlled.live_provider.trials -ne 0 -or
    [int]$controlled.windows_release_application_control.operating_system_error -ne 4551 -or
    [bool]$controlled.windows_release_application_control.bypass_attempted) { throw 'controlled evidence differs' }

$module = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/succeeding_sop_proposal.rs') -Raw
$cli = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/bin/cantor-succeeding-sop-proposal.rs') -Raw
foreach ($forbidden in @('std::fs','std::process::Command','TcpStream','UdpSocket','unsafe {','SystemTime','std::env::var')) {
    if ($module.Contains($forbidden) -or $cli.Contains($forbidden)) { throw "forbidden production surface: $forbidden" }
}
if ($cli.Contains('create_dir') -or $cli.Contains('fs::write')) { throw 'CLI output-path surface differs' }
if ($manifest.non_authority_statement -notmatch 'no live model authorship' -or
    $manifest.non_authority_statement -notmatch 'no.*SOP activation') { throw 'manifest non-authority differs' }

Write-Output "succeeding_sop_proposal_evidence_verified artifacts=$verified provider_trials=0"
