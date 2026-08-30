param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/sjs_compiled_minimum_recoverable_frame_p0/formation_evidence_manifest.json'

function Assert-ExactSet([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    if ($actualStrings.Count -ne $Expected.Count -or @($actualStrings | Sort-Object -Unique).Count -ne $Expected.Count) {
        throw "$Label cardinality or uniqueness mismatch"
    }
    $delta = Compare-Object ($Expected | Sort-Object) ($actualStrings | Sort-Object)
    if ($delta) { throw "$Label membership mismatch: $($delta | Out-String)" }
}

function Assert-ExactProperties([object]$Object, [string[]]$Expected, [string]$Label) {
    Assert-ExactSet @($Object.PSObject.Properties.Name) $Expected $Label
}

$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
$topProperties = @(
    'profile','manifest_uuid','canonical_uuid','signature_uuid','source_snapshot_uuid',
    'parent_source_uuid','substrate_audit_uuid','source_commit','file_ref_count',
    'artifacts','verification','disposition'
)
Assert-ExactProperties $manifest $topProperties 'manifest top properties'
if ($manifest.profile -cne 'cantor-sjs-minimum-recoverable-frame-p0-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne 'e0a9ae25-4b75-4485-9148-1f7284d99b5f' -or
    $manifest.canonical_uuid -cne '3fd17e47-0277-4856-85be-ac275690aa56' -or
    $manifest.signature_uuid -cne '5b367535-6a6d-47bf-abb3-356884a737ab' -or
    $manifest.source_snapshot_uuid -cne '93fca9d7-12d5-4e50-849d-867b0b92be03' -or
    $manifest.parent_source_uuid -cne 'a31d4fcd-3d56-4f88-875e-4bcb0ff244e9' -or
    $manifest.substrate_audit_uuid -cne 'b556eade-b240-477d-8a10-cac53c3c3ce2' -or
    $manifest.source_commit -cne '6390f6a62e6b001dc5eb3e4ca474d335eb2f5584' -or
    $manifest.disposition -cne 'formation_complete_provider_free_awaiting_attributed_publication') {
    throw 'formation identity or disposition mismatch'
}

$expectedPaths = @(
    'source_documents/2026-08-30_sjs_compiled_minimum_recoverable_frame_p0/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Source.sop',
    'source_documents/2026-08-30_sjs_compiled_minimum_recoverable_frame_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Input_Audit_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Constraint_Ledger_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Delineation_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Data_Design_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Dual_Hemisphere_Review_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Threat_Review_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Seven_Fold_Exhaustion_2026-08-30.sop',
    'specifications/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0.sop',
    'specifications/exploded/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0.exploded.sop',
    'justifications/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Justification.sop',
    'solutions/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Solution.sop',
    'plans/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Plan.sop',
    'feature_support/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorSJSCompiledMinimumRecoverableFrameP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Satisfaction_Signature.sop'
)
if ([long]$manifest.file_ref_count -ne 19 -or @($manifest.artifacts).Count -ne 19) { throw 'artifact count mismatch' }
Assert-ExactSet @($manifest.artifacts.path) $expectedPaths 'artifact paths'

$manifestHashes = @{}
foreach ($artifact in @($manifest.artifacts)) {
    Assert-ExactProperties $artifact @('path','bytes','sha256') "artifact properties $($artifact.path)"
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw "nonportable path $relative" }
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ([long]$artifact.bytes -ne [long]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -cne $hash) {
        throw "artifact identity mismatch $relative"
    }
    $manifestHashes[$relative] = $hash
}

$signaturePath = 'narrative/registries/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0_Satisfaction_Signature.sop'
$signature = [IO.File]::ReadAllText((Join-Path $RepositoryRoot $signaturePath))
$bindingMatches = [regex]::Matches($signature, '\[artifact_binding\] ([^\r\n]+) SHA256 ([A-F0-9]{64})')
if ($bindingMatches.Count -ne 18) { throw 'signature binding count mismatch' }
$boundPaths = @()
foreach ($binding in $bindingMatches) {
    $relative = $binding.Groups[1].Value
    $hash = $binding.Groups[2].Value
    if (-not $manifestHashes.ContainsKey($relative) -or $manifestHashes[$relative] -cne $hash) { throw "signature binding mismatch $relative" }
    $boundPaths += $relative
}
Assert-ExactSet $boundPaths @($expectedPaths[0..17]) 'signature-bound paths'

$canonical = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_SJS_Compiled_Minimum_Recoverable_Frame_P0.sop'))
$requirements = @([regex]::Matches($canonical, '\[MRF-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($canonical, '\[MRF-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..30 | ForEach-Object { $_.ToString('000') }) 'requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance gates'

$profiles = @([regex]::Matches($canonical, 'cantor-sjs-minimum-recoverable-frame-[a-z-]+/0\.1') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @(
    'cantor-sjs-minimum-recoverable-frame-request/0.1',
    'cantor-sjs-minimum-recoverable-frame-envelope/0.1',
    'cantor-sjs-minimum-recoverable-frame-verification/0.1',
    'cantor-sjs-minimum-recoverable-frame-evidence/0.1'
) 'canonical profiles'

$inputLine = [regex]::Match($canonical, '\[MRF-004\][^\r\n]+').Value
$inputs = @([regex]::Matches($inputLine, '(synthetic_provider_free_fixture|supplied_unobserved_declaration)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $inputs @('synthetic_provider_free_fixture','supplied_unobserved_declaration') 'input classes'

$hintLine = [regex]::Match($canonical, '\[MRF-011\][^\r\n]+').Value
$hintClasses = @([regex]::Matches($hintLine, '(mandatory_governing_anchor|mandatory_denial|mandatory_open_obligation|stable_relation|recoverable_coordinate|optional_trajectory_cue|expired_item)') | ForEach-Object { $_.Value })
Assert-ExactSet $hintClasses @('mandatory_governing_anchor','mandatory_denial','mandatory_open_obligation','stable_relation','recoverable_coordinate','optional_trajectory_cue','expired_item') 'hint classes'

$sourceLine = [regex]::Match($canonical, '\[MRF-015\][^\r\n]+').Value
$sourceKinds = @([regex]::Matches($sourceLine, '(exact_checkpoint|exact_event_ledger|exact_source_artifact)') | ForEach-Object { $_.Value })
Assert-ExactSet $sourceKinds @('exact_checkpoint','exact_event_ledger','exact_source_artifact') 'recovery source kinds'

$outcomeLine = [regex]::Match($canonical, '\[MRF-016\][^\r\n]+').Value
$outcomes = @([regex]::Matches($outcomeLine, '(anchored|drifted|underdetermined)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $outcomes @('anchored','drifted','underdetermined') 'comparison outcomes'

$dispositionLine = [regex]::Match($canonical, '\[MRF-019\][^\r\n]+').Value
$dispositions = @([regex]::Matches($dispositionLine, '(release_admitted|release_refused_drifted|release_refused_underdetermined)') | ForEach-Object { $_.Value })
Assert-ExactSet $dispositions @('release_admitted','release_refused_drifted','release_refused_underdetermined') 'witness dispositions'

if ($canonical -cnotmatch 'candidate group size 1 through 4 and pass budget 1 through 256' -or
    $canonical -cnotmatch 'two jobs eight hints two exact recovery sources four accepted releases one drift refusal one underdetermined refusal a four-hint final basis' -or
    $canonical -cnotmatch 'no destructive forgetting occurs' -or
    $canonical -cnotmatch 'performs no filesystem environment clock process network provider model inference MCP Git workspace secret permission activation remote hardware or external action') {
    throw 'canonical bounds fixture non-destruction or pure-production assertion mismatch'
}

$v = $manifest.verification
$verificationProperties = @(
    'formation_artifact_count','signature_bound_artifact_count','requirement_count','acceptance_gate_count',
    'profile_count','input_class_count','hint_class_count','recovery_source_kind_count','comparison_outcome_count',
    'witness_disposition_count','maximum_group_size','maximum_pass_budget','fixture_job_count','fixture_hint_count',
    'fixture_recovery_source_count','fixture_initial_basis_count','fixture_final_basis_count','fixture_admitted_release_count',
    'fixture_drift_refusal_count','fixture_underdetermined_refusal_count','execution_authorized','effect_counter_count','effect_count'
)
Assert-ExactProperties $v $verificationProperties 'verification properties'
$expectedCounts = @{
    formation_artifact_count=19; signature_bound_artifact_count=18; requirement_count=30; acceptance_gate_count=5;
    profile_count=4; input_class_count=2; hint_class_count=7; recovery_source_kind_count=3;
    comparison_outcome_count=3; witness_disposition_count=3; maximum_group_size=4; maximum_pass_budget=256;
    fixture_job_count=2; fixture_hint_count=8; fixture_recovery_source_count=2; fixture_initial_basis_count=8;
    fixture_final_basis_count=4; fixture_admitted_release_count=4; fixture_drift_refusal_count=1;
    fixture_underdetermined_refusal_count=1; effect_counter_count=14; effect_count=0
}
foreach ($entry in $expectedCounts.GetEnumerator()) {
    if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" }
}
if ($v.execution_authorized -ne $false) { throw 'execution authority must remain false' }

Write-Output 'sjs_compiled_minimum_recoverable_frame_formation_passed artifacts=19 bindings=18 requirements=30 acceptance=5 profiles=4 input_classes=2 hint_classes=7 recovery_kinds=3 outcomes=3 dispositions=3 group_max=4 pass_max=256 fixture=2_jobs_8_hints_2_sources_8_to_4_admitted4_drift1_under1 execution_authorized=false effects=0'
