[CmdletBinding()]
param([string]$ManifestPath = 'experiments/succeeding_sop_review_admission_p0/artifacts/succeeding_sop_review_admission_evidence_manifest.json')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullPath = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path $root $ManifestPath)) }
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-succeeding-sop-review-admission-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -cne '3ad46486-55fb-4f52-b89b-d6d5eb752192' -or
    $manifest.canonical_uuid -cne 'ff7c9404-2676-4c41-ae98-419445b6ec45' -or
    $manifest.source_snapshot_uuid -cne '5755947d-04e7-41b9-9373-691541a1b5de' -or
    $manifest.satisfaction_signature_uuid -cne 'a3f20717-42b2-47e5-a186-2f03a30d0883' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
& git -C $root cat-file -e "$($manifest.source_commit)^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'manifest source commit is absent' }

$required = @(
    'crates/cantor_core/src/bin/cantor-succeeding-sop-review-admission.rs',
    'crates/cantor_core/src/succeeding_sop_review_admission.rs',
    'crates/cantor_core/tests/succeeding_sop_review_admission.rs',
    'experiments/succeeding_sop_review_admission_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Succeeding_SOP_Review_Admission_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPReviewAdmissionP0CompletionReview.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Review_Admission_P0_Satisfaction_Signature.sop',
    'proofs/Cantor_Succeeding_SOP_Review_Admission_P0_Implementation_Proof.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_review_admission_p0/Cantor_Succeeding_SOP_Review_Admission_P0_Source.sop',
    'specifications/Cantor_Succeeding_SOP_Review_Admission_P0.sop'
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

$controlledPath = Join-Path $root 'experiments/succeeding_sop_review_admission_p0/artifacts/controlled_provider_free_verification.json'
$controlled = Get-Content -LiteralPath $controlledPath -Raw | ConvertFrom-Json
if ($controlled.profile -cne 'cantor-succeeding-sop-review-admission-controlled-verification/0.1' -or
    $controlled.evidence_uuid -cne '981398a2-3dc4-4a46-b675-fda1c0db97e8' -or
    $controlled.status -cne 'provider_free_review_signature_admission_verified' -or
    $controlled.implementation.satisfaction_signature_protocol_uuid -cne 'ad10f10f-d506-48ef-a805-f8b0a133766c' -or
    $controlled.implementation.status -cne 'cryptographically_verified_awaiting_physical_activation' -or
    $controlled.implementation.authority -cne 'review_signature_correspondence_only' -or
    [int]$controlled.focused.wsl_debug_passed -ne 35 -or
    [int]$controlled.focused.wsl_overflow_checked_release_passed -ne 35 -or
    [int]$controlled.focused.new_SWA_06B1_tests -ne 9 -or
    [int]$controlled.focused.reused_predecessor_tests -ne 26 -or
    [int]$controlled.focused.failed -ne 0 -or
    [int]$controlled.workspace.debug_result_groups -ne 196 -or
    [int]$controlled.workspace.debug_passed -ne 1222 -or
    [int]$controlled.workspace.debug_failed -ne 0 -or
    [int]$controlled.workspace.debug_ignored -ne 3 -or
    [string]$controlled.workspace.debug_transcript_sha256 -cne 'C9FDB5091CF2521E22B213490B3E9AC1746E0E114425F4D74F0D023CC243BFAA' -or
    [int]$controlled.workspace.release_result_groups -ne 196 -or
    [int]$controlled.workspace.release_passed -ne 1222 -or
    [int]$controlled.workspace.release_failed -ne 0 -or
    [int]$controlled.workspace.release_ignored -ne 3 -or
    [string]$controlled.workspace.release_transcript_sha256 -cne '52CDFC03C294F05799B2C4D4A30EF34066FA7478E6EE34CA29B520E945EF7B7C' -or
    [bool]$controlled.boundaries.provider_contacted -or
    [bool]$controlled.boundaries.model_called -or
    [bool]$controlled.boundaries.semantic_review_performed -or
    [bool]$controlled.boundaries.policy_governance_proved -or
    [bool]$controlled.boundaries.semantic_truth_proved -or
    [bool]$controlled.boundaries.signing_key_in_production -or
    [bool]$controlled.boundaries.signature_issued_by_product -or
    [bool]$controlled.boundaries.source_read_or_written_by_product -or
    [bool]$controlled.boundaries.sop_persisted -or
    [bool]$controlled.boundaries.sop_activated -or
    [bool]$controlled.boundaries.physical_activation_eligible -or
    [int]$controlled.live_provider.trials -ne 0) { throw 'controlled evidence differs' }

if ([int]$manifest.workspace_verification.debug.result_groups -ne 196 -or
    [int]$manifest.workspace_verification.debug.passed -ne 1222 -or
    [int]$manifest.workspace_verification.debug.failed -ne 0 -or
    [int]$manifest.workspace_verification.debug.ignored -ne 3 -or
    [int]$manifest.workspace_verification.overflow_checked_release.result_groups -ne 196 -or
    [int]$manifest.workspace_verification.overflow_checked_release.passed -ne 1222 -or
    [int]$manifest.workspace_verification.overflow_checked_release.failed -ne 0 -or
    [int]$manifest.workspace_verification.overflow_checked_release.ignored -ne 3) { throw 'workspace evidence differs' }

$module = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/succeeding_sop_review_admission.rs') -Raw
$cli = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/bin/cantor-succeeding-sop-review-admission.rs') -Raw
foreach ($forbidden in @('SigningKey','.sign(','std::fs','std::process::Command','TcpStream','UdpSocket','unsafe {','SystemTime','std::env::var')) {
    if ($module.Contains($forbidden) -or $cli.Contains($forbidden)) { throw "forbidden production surface: $forbidden" }
}
if ($cli.Contains('create_dir') -or $cli.Contains('fs::write')) { throw 'CLI output-path surface differs' }
if ($manifest.non_authority_statement -notmatch 'no semantic review' -or
    $manifest.non_authority_statement -notmatch 'no policy governance' -or
    $manifest.non_authority_statement -notmatch 'no.*SOP activation') { throw 'manifest non-authority differs' }

Write-Output "succeeding_sop_review_admission_evidence_verified artifacts=$verified provider_trials=0"
