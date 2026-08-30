param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/runtime_plus_sop_installation_seed_p0/formation_evidence_manifest.json'

function Assert-ExactSet([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    if ($actualStrings.Count -ne $Expected.Count -or @($actualStrings | Sort-Object -Unique).Count -ne $Expected.Count) {
        throw "$Label cardinality or uniqueness mismatch"
    }
    $delta = Compare-Object ($Expected | Sort-Object) ($actualStrings | Sort-Object)
    if ($delta) { throw "$Label membership mismatch: $($delta | Out-String)" }
}

function Assert-RawJsonKeyCount([string]$Raw, [string]$Name, [int]$ExpectedCount) {
    $actual = [regex]::Matches($Raw, ('"' + [regex]::Escape($Name) + '"\s*:')).Count
    if ($actual -ne $ExpectedCount) { throw "JSON key count mismatch for $Name`: expected $ExpectedCount actual $actual" }
}

$raw = [IO.File]::ReadAllText($manifestPath)
$manifest = $raw | ConvertFrom-Json
$top = @('profile','manifest_uuid','generated_at_utc','source_custody_commit','formation_work_order_commit','canonical_uuid','signature_uuid','disposition','file_ref_count','artifacts','verification','non_authority_statement')
Assert-ExactSet @($manifest.PSObject.Properties.Name) $top 'top-level properties'
foreach ($name in $top) { Assert-RawJsonKeyCount $raw $name 1 }

if ($manifest.profile -cne 'cantor-runtime-plus-sop-installation-seed-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne 'e2d611c1-8e5e-42ac-8339-4ee413f5db08' -or
    $manifest.canonical_uuid -cne '5fbec09b-e92d-48e2-826c-ea8bd420559d' -or
    $manifest.signature_uuid -cne '923cce08-2c03-4ddf-97f6-d19d03838b4b' -or
    $manifest.source_custody_commit -cne 'f41b4d1e6e0f7b838d38993570d17f7ec189f4fd' -or
    $manifest.formation_work_order_commit -cne '6c15e1db582bf186b5452431e81686739627b709') {
    throw 'formation identity mismatch'
}

$expectedPaths = @(
    'source_documents/2026-08-29_cantor_runtime_plus_sop_installation_seed_p0/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Source.sop',
    'source_documents/2026-08-29_cantor_runtime_plus_sop_installation_seed_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Input_Audit_2026-08-29.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Constraint_Ledger_2026-08-29.sop',
    'plans/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Formation_Work_Order.sop',
    'feature_support/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Formation_Readiness_Matrix.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Delineation_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Data_Design_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Dual_Hemisphere_Review_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Threat_Review_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Seven_Fold_Exhaustion_2026-08-30.sop',
    'specifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0.sop',
    'specifications/exploded/Cantor_Runtime_Plus_SOP_Installation_Seed_P0.exploded.sop',
    'feature_support/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Requirement_Matrix.sop',
    'justifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Justification.sop',
    'solutions/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Solution.sop',
    'plans/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Plan.sop',
    'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorRuntimePlusSOPInstallationSeedP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Satisfaction_Signature.sop'
)
if ($manifest.file_ref_count -ne 21 -or @($manifest.artifacts).Count -ne 21) { throw 'formation artifact count mismatch' }
foreach ($name in @('path','bytes','sha256')) { Assert-RawJsonKeyCount $raw $name 21 }
Assert-ExactSet @($manifest.artifacts.path) $expectedPaths 'formation artifacts'

$artifactIdentities = @()
foreach ($artifact in @($manifest.artifacts)) {
    Assert-ExactSet @($artifact.PSObject.Properties.Name) @('path','bytes','sha256') "artifact properties $($artifact.path)"
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw "nonportable artifact path: $relative" }
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "formation artifact missing: $relative" }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ([long]$artifact.bytes -ne $item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -ne $hash) { throw "formation artifact identity mismatch: $relative" }
    $artifactIdentities += "$($item.Length)|$hash"
}

$signaturePath = Join-Path $RepositoryRoot 'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Satisfaction_Signature.sop'
$signature = [IO.File]::ReadAllText($signaturePath)
$bindings = [regex]::Matches($signature, ' is ([0-9]+) bytes SHA256 ([A-F0-9]{64})')
if ($bindings.Count -ne 20) { throw "signature binding count mismatch: $($bindings.Count)" }
$signatureIdentities = @($bindings | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)" })
Assert-ExactSet $signatureIdentities @($artifactIdentities[0..19]) 'signature artifact bindings'

$specPath = Join-Path $RepositoryRoot 'specifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0.sop'
$spec = [IO.File]::ReadAllText($specPath)
$requirements = @([regex]::Matches($spec, '\[RIS-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($spec, '\[RIS-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..30 | ForEach-Object { $_.ToString('000') }) 'canonical requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance requirements'

$denials = @('filesystem_read','filesystem_write','filesystem_delete','environment_read','clock_read','process_spawn','shell_exec','compiler_exec','package_manager_exec','network_contact','artifact_download','provider_contact','model_load','inference','mcp_contact','git_mutation','workspace_mutation','secret_access','permission_change','service_activation','cleanup','rollback','remote_access','hardware_effect','external_effect')
$denialLine = [regex]::Match($spec, '\[RIS-023\][^\r\n]*exact capability denials are ([^\r\n]+)').Groups[1].Value
$denialTokens = @($denialLine -split ' ' | Where-Object { $_ -match '^[a-z_]+$' -and $_ -cne 'and' })
Assert-ExactSet $denialTokens $denials 'capability denials'

$threatPath = Join-Path $RepositoryRoot 'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Threat_Review_2026-08-30.sop'
$threat = [IO.File]::ReadAllText($threatPath)
$threats = @([regex]::Matches($threat, '\[RIS-T([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $threats @(1..17 | ForEach-Object { $_.ToString('00') }) 'threat inventory'

$verification = $manifest.verification
$properties = @('formation_artifact_count','signature_bound_artifact_count','invalid_reference_count','requirement_count','acceptance_requirement_count','root_kind_count','material_kind_count','prerequisite_kind_count','source_kind_count','lifecycle_stage_count','capability_denial_count','threat_count','deterministic_normalization_required','independent_recompilation_required','synthetic_provider_free_fixture_required','implementation_authority_before_publication','material_presence_observed','bootstrap_executable_observed','installation_sop_executed','filesystem_effect_count','process_effect_count','network_contact_count','provider_trial_count','model_turn_count','secret_access_count','workspace_mutation_count','remote_contact_count','hardware_effect_count','activation_count','foreign_effect_count')
Assert-ExactSet @($verification.PSObject.Properties.Name) $properties 'verification properties'
foreach ($name in $properties) { Assert-RawJsonKeyCount $raw $name 1 }
$counts = @{formation_artifact_count=21;signature_bound_artifact_count=20;invalid_reference_count=0;requirement_count=30;acceptance_requirement_count=5;root_kind_count=2;material_kind_count=7;prerequisite_kind_count=9;source_kind_count=5;lifecycle_stage_count=11;capability_denial_count=25;threat_count=17}
foreach ($entry in $counts.GetEnumerator()) {
    if ([long]$verification.($entry.Key) -ne [long]$entry.Value) { throw "verification count mismatch: $($entry.Key)" }
}
foreach ($name in @('deterministic_normalization_required','independent_recompilation_required','synthetic_provider_free_fixture_required')) {
    if ($verification.$name -ne $true) { throw "required true formation flag mismatch: $name" }
}
foreach ($name in @('implementation_authority_before_publication','material_presence_observed','bootstrap_executable_observed','installation_sop_executed')) {
    if ($verification.$name -ne $false) { throw "required false formation flag mismatch: $name" }
}
foreach ($name in @('filesystem_effect_count','process_effect_count','network_contact_count','provider_trial_count','model_turn_count','secret_access_count','workspace_mutation_count','remote_contact_count','hardware_effect_count','activation_count','foreign_effect_count')) {
    if ([long]$verification.$name -ne 0) { throw "nonzero formation effect: $name" }
}

if ($manifest.disposition -cne 'formation_verified_ready_for_attributed_publication') { throw 'formation disposition mismatch' }
if ([string]::IsNullOrWhiteSpace([string]$manifest.non_authority_statement)) { throw 'missing non-authority statement' }

Write-Output 'runtime_plus_sop_installation_seed_formation_passed artifacts=21 signature_bindings=20 requirements=30 acceptance=5 roots=2 material_kinds=7 prerequisite_kinds=9 source_kinds=5 lifecycle=11 denials=25 threats=17 effects=0'
