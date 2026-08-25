[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_activation_transaction_p0/artifacts/succeeding_sop_activation_transaction_evidence_manifest.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_activation_transaction_p0/artifacts/controlled_provider_free_verification.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Resolve-Input([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $root $Path))
}

$fullPath = Resolve-Input $ManifestPath
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-succeeding-sop-activation-transaction-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -cne 'db806c96-9fad-4e6b-82ef-7f163fbfc28f' -or
    $manifest.canonical_uuid -cne '28da111f-c6b2-4df7-b708-a2d47f8e0bbb' -or
    $manifest.source_snapshot_uuid -cne '46e65481-fab8-4d97-8197-3f0d52895890' -or
    $manifest.satisfaction_signature_uuid -cne 'c454e50b-9342-4fd3-93d6-44fbb8c468ee' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
& git -C $root cat-file -e "$($manifest.source_commit)^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'manifest source commit is absent' }

$required = @(
    'crates/cantor_core/src/bin/cantor-succeeding-sop-activation-transaction.rs',
    'crates/cantor_core/src/succeeding_sop_activation_transaction.rs',
    'crates/cantor_core/tests/succeeding_sop_activation_transaction.rs',
    'experiments/succeeding_sop_activation_transaction_p0/artifacts/controlled_provider_free_verification.json',
    'feature_support/Cantor_Succeeding_SOP_Activation_Transaction_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPActivationTransactionP0CompletionReview.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Activation_Transaction_P0_Satisfaction_Signature.sop',
    'proofs/Cantor_Succeeding_SOP_Activation_Transaction_P0_Implementation_Proof.sop',
    'scripts/test_cantor_succeeding_sop_activation_transaction.ps1',
    'source_documents/2026-08-25_cantor_succeeding_sop_activation_transaction_p0/Cantor_Succeeding_SOP_Activation_Transaction_P0_Source.sop',
    'specifications/Cantor_Succeeding_SOP_Activation_Transaction_P0.sop'
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

$controlled = Get-Content -LiteralPath (Resolve-Input $ControlledPath) -Raw | ConvertFrom-Json
if ($controlled.profile -cne 'cantor-succeeding-sop-activation-transaction-controlled-verification/0.1' -or
    $controlled.evidence_uuid -cne '303a1be1-7483-4515-b809-fb0040dc5ff2' -or
    $controlled.status -cne 'provider_free_activation_transaction_correspondence_verified' -or
    $controlled.implementation.request_profile -cne 'cantor-succeeding-sop-activation-transaction-request/0.1' -or
    $controlled.implementation.receipt_profile -cne 'cantor-succeeding-sop-activation-transaction-receipt/0.1' -or
    $controlled.implementation.status -cne 'transaction_correspondence_verified_awaiting_physical_execution' -or
    $controlled.implementation.authority -cne 'supplied_activation_plan_correspondence_only' -or
    [int]$controlled.focused.wsl_debug_passed -ne 45 -or
    [int]$controlled.focused.wsl_overflow_checked_release_passed -ne 45 -or
    [int]$controlled.focused.new_SWA_06B2A_tests -ne 10 -or
    [int]$controlled.focused.reused_predecessor_tests -ne 35 -or
    [int]$controlled.focused.failed -ne 0 -or
    [int]$controlled.workspace.debug_result_groups -ne 198 -or
    [int]$controlled.workspace.debug_passed -ne 1267 -or
    [int]$controlled.workspace.debug_failed -ne 0 -or
    [int]$controlled.workspace.debug_ignored -ne 3 -or
    [int]$controlled.workspace.debug_transcript_bytes -ne 158979 -or
    [string]$controlled.workspace.debug_transcript_sha256 -cne '56644534B80ED3D675ECD01DF8151D979E7020E5DA0C7894F5C58B914A70E2DE' -or
    [int]$controlled.workspace.release_result_groups -ne 198 -or
    [int]$controlled.workspace.release_passed -ne 1267 -or
    [int]$controlled.workspace.release_failed -ne 0 -or
    [int]$controlled.workspace.release_ignored -ne 3 -or
    [int]$controlled.workspace.release_transcript_bytes -ne 159750 -or
    [string]$controlled.workspace.release_transcript_sha256 -cne '8B9EE6191DCC481177D5A55445A169571BFE8460A22E576658188CE866DB5E34' -or
    [bool]$controlled.boundaries.provider_contacted -or
    [bool]$controlled.boundaries.model_called -or
    [bool]$controlled.boundaries.policy_governance_proved -or
    [bool]$controlled.boundaries.semantic_truth_proved -or
    [bool]$controlled.boundaries.source_reacquired -or
    [bool]$controlled.boundaries.registry_observed -or
    [bool]$controlled.boundaries.registry_persisted -or
    [bool]$controlled.boundaries.current_sop_selected -or
    [bool]$controlled.boundaries.boot_activation_verified -or
    [bool]$controlled.boundaries.rollback_executed -or
    [bool]$controlled.boundaries.physical_contact -or
    [bool]$controlled.boundaries.physical_execution_eligible -or
    [bool]$controlled.boundaries.child_process_surface_in_product_module -or
    [bool]$controlled.boundaries.output_path_surface -or
    [int]$controlled.live_provider.trials -ne 0) { throw 'controlled evidence differs' }

if ([int]$manifest.workspace_verification.debug.result_groups -ne 198 -or
    [int]$manifest.workspace_verification.debug.passed -ne 1267 -or
    [int]$manifest.workspace_verification.debug.failed -ne 0 -or
    [int]$manifest.workspace_verification.debug.ignored -ne 3 -or
    [int]$manifest.workspace_verification.overflow_checked_release.result_groups -ne 198 -or
    [int]$manifest.workspace_verification.overflow_checked_release.passed -ne 1267 -or
    [int]$manifest.workspace_verification.overflow_checked_release.failed -ne 0 -or
    [int]$manifest.workspace_verification.overflow_checked_release.ignored -ne 3) { throw 'workspace evidence differs' }

$module = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/succeeding_sop_activation_transaction.rs') -Raw
$cli = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_core/src/bin/cantor-succeeding-sop-activation-transaction.rs') -Raw
foreach ($forbidden in @('std::fs','std::process::Command','TcpStream','UdpSocket','unsafe {','SystemTime','std::env::var','PathBuf')) {
    if ($module.Contains($forbidden) -or $cli.Contains($forbidden)) { throw "forbidden production surface: $forbidden" }
}
if ($cli.Contains('create_dir') -or $cli.Contains('fs::write') -or $cli.Contains('--output')) { throw 'CLI output-path surface differs' }
if ($manifest.non_authority_statement -notmatch 'no policy governance' -or
    $manifest.non_authority_statement -notmatch 'no physical source reacquisition' -or
    $manifest.non_authority_statement -notmatch 'no registry observation or persistence' -or
    $manifest.non_authority_statement -notmatch 'no boot activation' -or
    $manifest.non_authority_statement -notmatch 'no physical execution eligibility') { throw 'manifest non-authority differs' }

Write-Output "succeeding_sop_activation_transaction_evidence_verified artifacts=$verified provider_trials=0"
