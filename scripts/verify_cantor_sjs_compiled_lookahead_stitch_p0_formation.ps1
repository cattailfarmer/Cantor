param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/sjs_compiled_lookahead_stitch_p0/formation_evidence_manifest.json'

function Assert-ExactSet([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    if ($actualStrings.Count -ne $Expected.Count -or @($actualStrings | Sort-Object -Unique).Count -ne $Expected.Count) { throw "$Label cardinality or uniqueness mismatch" }
    $delta = Compare-Object ($Expected | Sort-Object) ($actualStrings | Sort-Object)
    if ($delta) { throw "$Label membership mismatch: $($delta | Out-String)" }
}

function Assert-ExactProperties([object]$Object, [string[]]$Expected, [string]$Label) {
    Assert-ExactSet @($Object.PSObject.Properties.Name) $Expected $Label
}

$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
$topProperties = @('profile','manifest_uuid','canonical_uuid','signature_uuid','source_snapshot_uuid','parent_source_uuid','source_commit','file_ref_count','artifacts','verification','disposition')
Assert-ExactProperties $manifest $topProperties 'manifest top properties'
if ($manifest.profile -cne 'cantor-sjs-compiled-lookahead-stitch-p0-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne 'e1eab572-7e57-4b81-a928-d94906a1d972' -or
    $manifest.canonical_uuid -cne '5b57d004-0a43-4d89-9c5a-6dc671a2a05a' -or
    $manifest.signature_uuid -cne '2b743f94-ec0a-48cb-a68c-f5cb0b62bc68' -or
    $manifest.source_snapshot_uuid -cne '9a3eb07f-b5f3-4d4b-83ec-32c410deb7ec' -or
    $manifest.parent_source_uuid -cne '2093c2d5-e406-4a93-a393-bbed0f5922f9' -or
    $manifest.source_commit -cne '6b7ca8dd70dcca14b775faa5997fb0908f289d92' -or
    $manifest.disposition -cne 'formation_complete_provider_free_awaiting_attributed_publication') { throw 'formation identity or disposition mismatch' }

$expectedPaths = @(
    'source_documents/2026-08-29_sop_compiled_lookahead_stitch_p0/Cantor_SOP_Compiled_Lookahead_Stitch_P0_Source.sop',
    'source_documents/2026-08-29_sop_compiled_lookahead_stitch_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Input_Audit_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Constraint_Ledger_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Delineation_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Data_Design_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Dual_Hemisphere_Review_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Threat_Review_2026-08-30.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Seven_Fold_Exhaustion_2026-08-30.sop',
    'specifications/Cantor_SJS_Compiled_Lookahead_Stitch_P0.sop',
    'specifications/exploded/Cantor_SJS_Compiled_Lookahead_Stitch_P0.exploded.sop',
    'justifications/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Justification.sop',
    'solutions/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Solution.sop',
    'plans/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Plan.sop',
    'feature_support/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorSJSCompiledLookaheadStitchP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Satisfaction_Signature.sop'
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
    if ([long]$artifact.bytes -ne [long]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -cne $hash) { throw "artifact identity mismatch $relative" }
    $manifestHashes[$relative] = $hash
}

$signaturePath = 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_P0_Satisfaction_Signature.sop'
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

$canonical = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_SJS_Compiled_Lookahead_Stitch_P0.sop'))
$requirements = @([regex]::Matches($canonical, '\[LAS-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($canonical, '\[LAS-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..30 | ForEach-Object { $_.ToString('000') }) 'requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance gates'

$profiles = @([regex]::Matches($canonical, 'cantor-sjs-compiled-lookahead-stitch-[a-z-]+/0\.1') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @('cantor-sjs-compiled-lookahead-stitch-request/0.1','cantor-sjs-compiled-lookahead-stitch-envelope/0.1','cantor-sjs-compiled-lookahead-stitch-verification/0.1','cantor-sjs-compiled-lookahead-stitch-evidence/0.1') 'canonical profiles'

$inputLine = [regex]::Match($canonical, '\[LAS-004\][^\r\n]+').Value
$inputs = @([regex]::Matches($inputLine, '(synthetic_provider_free_fixture|supplied_unobserved_declaration)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $inputs @('synthetic_provider_free_fixture','supplied_unobserved_declaration') 'input classes'

$turnLine = [regex]::Match($canonical, '\[LAS-008\][^\r\n]+').Value
$turns = @([regex]::Matches($turnLine, '(select_distinction|conserve_invariant|expose_relationship|change_abstraction_level|introduce_counterexample|route_evidence_gate)') | ForEach-Object { $_.Value })
Assert-ExactSet $turns @('select_distinction','conserve_invariant','expose_relationship','change_abstraction_level','introduce_counterexample','route_evidence_gate') 'semantic turn kinds'

$sourceLine = [regex]::Match($canonical, '\[LAS-009\][^\r\n]+').Value
$sourceClasses = @([regex]::Matches($sourceLine, '(governing_anchor|plan_hint|observed_coordinate|nonauthority_evidence)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $sourceClasses @('governing_anchor','plan_hint','observed_coordinate','nonauthority_evidence') 'source binding classes'

$stateLine = [regex]::Match($canonical, '\[LAS-012\][^\r\n]+').Value
$states = @([regex]::Matches($stateLine, '(proposed|active|fulfilled|invalidated|released)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $states @('proposed','active','fulfilled','invalidated','released') 'lifecycle states'

$boundaryLine = [regex]::Match($canonical, '\[LAS-018\][^\r\n]+').Value
$boundaries = @([regex]::Matches($boundaryLine, '(initial|resume_after_stop|resume_after_tool_result|reentry)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $boundaries @('initial','resume_after_stop','resume_after_tool_result','reentry') 'boundary kinds'

if ($canonical -cnotmatch 'stitches are 1 through 2' -or $canonical -cnotmatch 'projected bytes at most 8192' -or
    $canonical -cnotmatch 'two stitches eight total hints four source bindings six observations four invocation coordinates five projected stitch inclusions two activations one fulfillment one invalidation zero refused transitions and zero effects' -or
    $canonical -cnotmatch 'performs no filesystem environment clock process network provider model inference prompt mutation MCP Git workspace secret permission activation remote hardware or external action') { throw 'canonical bounds fixture or pure-production assertion mismatch' }

$v = $manifest.verification
$verificationProperties = @('formation_artifact_count','signature_bound_artifact_count','requirement_count','acceptance_gate_count','profile_count','input_class_count','semantic_turn_kind_count','source_binding_class_count','lifecycle_state_count','boundary_kind_count','maximum_stitch_count','maximum_projected_bytes','fixture_stitch_count','fixture_hint_count','fixture_source_binding_count','fixture_observation_count','fixture_coordinate_count','fixture_projected_inclusion_count','fixture_activation_count','fixture_fulfillment_count','fixture_invalidation_count','execution_authorized','effect_counter_count','effect_count')
Assert-ExactProperties $v $verificationProperties 'verification properties'
$expectedCounts = @{formation_artifact_count=19;signature_bound_artifact_count=18;requirement_count=30;acceptance_gate_count=5;profile_count=4;input_class_count=2;semantic_turn_kind_count=6;source_binding_class_count=4;lifecycle_state_count=5;boundary_kind_count=4;maximum_stitch_count=2;maximum_projected_bytes=8192;fixture_stitch_count=2;fixture_hint_count=8;fixture_source_binding_count=4;fixture_observation_count=6;fixture_coordinate_count=4;fixture_projected_inclusion_count=5;fixture_activation_count=2;fixture_fulfillment_count=1;fixture_invalidation_count=1;effect_counter_count=14;effect_count=0}
foreach ($entry in $expectedCounts.GetEnumerator()) { if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" } }
if ($v.execution_authorized -ne $false) { throw 'execution authority must remain false' }

Write-Output 'sjs_compiled_lookahead_stitch_formation_passed artifacts=19 bindings=18 requirements=30 acceptance=5 profiles=4 input_classes=2 turns=6 source_classes=4 states=5 boundaries=4 stitch_max=2 bytes_max=8192 fixture=2_stitches_8_hints_4_sources_6_observations_4_coordinates_5_inclusions_active2_fulfilled1_invalidated1 execution_authorized=false effects=0'
