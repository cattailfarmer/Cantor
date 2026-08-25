[CmdletBinding()]
param([string]$ManifestPath = 'experiments/provider_free_self_work_composition_p0/artifacts/provider_free_self_work_composition_evidence_manifest.json')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullPath = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path $root $ManifestPath)) }
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-provider-free-self-work-composition-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -cne '8276d957-8dac-4995-afc5-45a21ab84e1f' -or
    $manifest.canonical_uuid -cne 'd36ead3a-82eb-4a88-897e-1d903cc01c01' -or
    $manifest.source_snapshot_uuid -cne '9c4c374d-db80-4a0b-b186-cff44e2916af' -or
    $manifest.satisfaction_signature_uuid -cne 'f95853e7-ce55-4e91-b1d7-5adc412bab0f' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
& git -C $root cat-file -e "$($manifest.source_commit)^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'manifest source commit is absent' }

$required = @(
    'crates/cantor_ecosystem/src/bin/cantor-provider-free-self-work-composition.rs',
    'crates/cantor_ecosystem/src/provider_free_self_work_composition.rs',
    'crates/cantor_ecosystem/tests/provider_free_self_work_composition.rs',
    'experiments/provider_free_self_work_composition_p0/artifacts/controlled_provider_free_verification.json',
    'narrative/registries/Cantor_Provider_Free_Self_Work_Composition_P0_Satisfaction_Signature.sop',
    'proofs/Cantor_Provider_Free_Self_Work_Composition_P0_Implementation_Proof.sop',
    'source_documents/2026-08-24_cantor_provider_free_self_work_composition_p0/Cantor_Provider_Free_Self_Work_Composition_P0_Source.sop',
    'specifications/Cantor_Provider_Free_Self_Work_Composition_P0.sop'
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

$controlled = Get-Content -LiteralPath (Join-Path $root 'experiments/provider_free_self_work_composition_p0/artifacts/controlled_provider_free_verification.json') -Raw | ConvertFrom-Json
if ($controlled.profile -cne 'cantor-provider-free-self-work-composition-controlled-verification/0.1' -or
    $controlled.evidence_uuid -cne 'fdc97238-cb20-471c-8048-f96c6f00b35d' -or
    $controlled.status -cne 'provider_free_chain_correspondence_verified' -or
    $controlled.implementation.authority -cne 'supplied_data_correspondence_only' -or
    [bool]$controlled.implementation.physical_contact -or
    [int]$controlled.focused.wsl_debug_passed -ne 32 -or
    [int]$controlled.focused.wsl_overflow_checked_release_passed -ne 32 -or
    [int]$controlled.focused.direct_SWA_07_tests -ne 7 -or
    [int]$controlled.focused.imported_predecessor_tests -ne 25 -or
    [bool]$controlled.boundaries.provider_contacted -or
    [bool]$controlled.boundaries.model_called -or
    [bool]$controlled.boundaries.physical_update_performed -or
    [bool]$controlled.boundaries.workspace_mutated_by_product -or
    [bool]$controlled.boundaries.semantic_review_performed -or
    [bool]$controlled.boundaries.sop_activated -or
    [bool]$controlled.boundaries.publication_performed_by_product -or
    [int]$controlled.live_provider.trials -ne 0 -or
    [int]$controlled.windows_application_control.operating_system_error -ne 4551 -or
    [bool]$controlled.windows_application_control.bypass_attempted) { throw 'controlled evidence differs' }

$module = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_ecosystem/src/provider_free_self_work_composition.rs') -Raw
$cli = Get-Content -LiteralPath (Join-Path $root 'crates/cantor_ecosystem/src/bin/cantor-provider-free-self-work-composition.rs') -Raw
foreach ($forbidden in @('std::fs','std::process::Command','TcpStream','UdpSocket','unsafe {','SystemTime','std::env::var','PathBuf')) {
    if ($module.Contains($forbidden) -or $cli.Contains($forbidden)) { throw "forbidden production surface: $forbidden" }
}
if ($cli.Contains('create_dir') -or $cli.Contains('fs::write') -or $cli.Contains('--output')) { throw 'CLI output-path surface differs' }
if ($manifest.non_authority_statement -notmatch 'no provider or model contact' -or
    $manifest.non_authority_statement -notmatch 'no.*SOP activation') { throw 'manifest non-authority differs' }

Write-Output "provider_free_self_work_composition_evidence_verified artifacts=$verified provider_trials=0"
