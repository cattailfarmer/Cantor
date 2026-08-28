param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/nested_inner_launch_plan_p0/formation_evidence_manifest.json'

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
$top = @('profile','manifest_uuid','generated_at_utc','source_custody_commit','published_nhc03','canonical_uuid','signature_uuid','disposition','file_ref_count','artifacts','verification','non_authority_statement')
Assert-ExactSet @($manifest.PSObject.Properties.Name) $top 'top-level properties'
foreach ($name in $top) { Assert-RawJsonKeyCount $raw $name 1 }

if ($manifest.profile -cne 'cantor-nested-inner-launch-plan-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '328cd11a-593a-4962-ac5a-e001acc5a177' -or
    $manifest.canonical_uuid -cne '5a67e2bc-17a6-4207-939e-7a521945dcc6' -or
    $manifest.signature_uuid -cne 'cadc90ff-f823-454e-bdac-399bcb56e19b' -or
    $manifest.source_custody_commit -cne '4bfec006a9aca9aaa9e7968c0b26be40d8c7bfba' -or
    $manifest.published_nhc03 -cne '64bccb9aecd340ca02b625989834c09063d9aa0c') {
    throw 'formation identity mismatch'
}

$expectedPaths = @(
    'proofs/Cantor_Nested_Inner_Model_Admission_P0_Implementation_Publication_Checkpoint_Proof.sop',
    'source_documents/2026-08-28_nested_inner_launch_plan_p0/Nested_Inner_Launch_Plan_P0_Source.sop',
    'source_documents/2026-08-28_nested_inner_launch_plan_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Input_Audit_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Delineation_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Data_Design_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Dual_Hemisphere_Review_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Threat_Review_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Launch_Plan_P0_Seven_Fold_Exhaustion_2026-08-28.sop',
    'specifications/Cantor_Nested_Inner_Launch_Plan_P0.sop',
    'specifications/exploded/Cantor_Nested_Inner_Launch_Plan_P0.exploded.sop',
    'feature_support/Cantor_Nested_Inner_Launch_Plan_P0_Requirement_Matrix.sop',
    'justifications/Cantor_Nested_Inner_Launch_Plan_P0_Justification.sop',
    'solutions/Cantor_Nested_Inner_Launch_Plan_P0_Solution.sop',
    'plans/Cantor_Nested_Inner_Launch_Plan_P0_Plan.sop',
    'narrative/registries/Cantor_Nested_Inner_Launch_Plan_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_Nested_Inner_Launch_Plan_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorNestedInnerLaunchPlanP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_Nested_Inner_Launch_Plan_P0_Satisfaction_Signature.sop'
)
if ($manifest.file_ref_count -ne 19 -or @($manifest.artifacts).Count -ne 19) { throw 'formation artifact count mismatch' }
foreach ($name in @('path','bytes','sha256')) { Assert-RawJsonKeyCount $raw $name 19 }
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

$signature = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'narrative/registries/Cantor_Nested_Inner_Launch_Plan_P0_Satisfaction_Signature.sop'))
$bindings = [regex]::Matches($signature, ' is ([0-9]+) bytes SHA256 ([A-F0-9]{64})')
if ($bindings.Count -ne 18) { throw "signature binding count mismatch: $($bindings.Count)" }
$signatureIdentities = @($bindings | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)" })
Assert-ExactSet $signatureIdentities @($artifactIdentities[0..17]) 'signature artifact bindings'

$spec = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_Nested_Inner_Launch_Plan_P0.sop'))
$requirements = @([regex]::Matches($spec, '\[NHLP-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($spec, '\[NHLP-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..24 | ForEach-Object { $_.ToString('000') }) 'canonical requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance requirements'

$verification = $manifest.verification
$properties = @('formation_artifact_count','signature_bound_artifact_count','invalid_reference_count','requirement_count','acceptance_requirement_count','upstream_operational_identity_count','operational_identity_count','bound_identity_count','capability_denial_count','upstream_unresolved_truth_count','unresolved_truth_count','detached_authorization_required','launch_plan_authority_form_defined','authorization_issued','executable_file_observed','executable_bytes_reacquired','model_load_attempt_count','model_load_completion_count','process_launch_attempt_count','process_created_count','runtime_model_observed','provider_trial_count','model_turn_count','stream_custody_count','cancellation_execution_count','cleanup_effect_count','workspace_mutation_count','network_contact_count','remote_contact_count','persistence_count','activation_count','foreign_effect_count')
Assert-ExactSet @($verification.PSObject.Properties.Name) $properties 'verification properties'
foreach ($name in $properties) { Assert-RawJsonKeyCount $raw $name 1 }
$counts = @{formation_artifact_count=19;signature_bound_artifact_count=18;invalid_reference_count=0;requirement_count=24;acceptance_requirement_count=5;upstream_operational_identity_count=8;operational_identity_count=10;bound_identity_count=12;capability_denial_count=18;upstream_unresolved_truth_count=10;unresolved_truth_count=12}
foreach ($entry in $counts.GetEnumerator()) { if ([long]$verification.($entry.Key) -ne [long]$entry.Value) { throw "verification count mismatch: $($entry.Key)" } }
foreach ($name in @('detached_authorization_required','launch_plan_authority_form_defined')) { if ($verification.$name -ne $true) { throw "required true formation flag mismatch: $name" } }
foreach ($name in @('authorization_issued','executable_file_observed','executable_bytes_reacquired','runtime_model_observed')) { if ($verification.$name -ne $false) { throw "required false formation flag mismatch: $name" } }
foreach ($name in @('model_load_attempt_count','model_load_completion_count','process_launch_attempt_count','process_created_count','provider_trial_count','model_turn_count','stream_custody_count','cancellation_execution_count','cleanup_effect_count','workspace_mutation_count','network_contact_count','remote_contact_count','persistence_count','activation_count','foreign_effect_count')) { if ([long]$verification.$name -ne 0) { throw "nonzero formation effect: $name" } }

Write-Output 'nested_inner_launch_plan_formation_passed artifacts=19 signature_bindings=18 requirements=24 acceptance=5 upstream_identities=8 operational_identities=10 bound_identities=12 denials=18 upstream_unresolved=10 unresolved=12 effects=0'
