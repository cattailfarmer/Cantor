param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/sjs_compiled_lookahead_term_set_optimization_p0/formation_evidence_manifest.json'

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
$top = @('profile','manifest_uuid','canonical_uuid','signature_uuid','source_snapshot_uuid','parent_stitch_source_uuid','compiled_stitch_canonical_uuid','source_commit','file_ref_count','artifacts','verification','disposition')
Assert-ExactProperties $manifest $top 'manifest top properties'
if ($manifest.profile -cne 'cantor-sjs-compiled-lookahead-term-set-optimization-p0-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '0509afa5-e3e8-4c08-bffe-53932d5462c2' -or
    $manifest.canonical_uuid -cne '5bb132b9-8250-4f6d-a7e6-6977edad8162' -or
    $manifest.signature_uuid -cne '65b049b8-7af6-463a-9c03-9e0714f068b0' -or
    $manifest.source_snapshot_uuid -cne '24c3902d-634f-40b5-93bc-ffec40db2f84' -or
    $manifest.parent_stitch_source_uuid -cne '9a3eb07f-b5f3-4d4b-83ec-32c410deb7ec' -or
    $manifest.compiled_stitch_canonical_uuid -cne '5b57d004-0a43-4d89-9c5a-6dc671a2a05a' -or
    $manifest.source_commit -cne 'daacbf75449e0fa73bf5b169e7a07a1d7c0e990a' -or
    $manifest.disposition -cne 'formation_complete_provider_free_awaiting_attributed_publication') { throw 'formation identity or disposition mismatch' }

$expectedPaths = @(
    'source_documents/2026-08-30_sop_compiled_lookahead_term_set_optimization_p0/Cantor_SOP_Compiled_Lookahead_Term_Set_Optimization_P0_Source.sop',
    'source_documents/2026-08-30_sop_compiled_lookahead_term_set_optimization_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Input_Audit_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Constraint_Ledger_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Delineation_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Data_Design_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Dual_Hemisphere_Review_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Threat_Review_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Seven_Fold_Exhaustion_2026-08-31.sop',
    'specifications/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0.sop',
    'specifications/exploded/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0.exploded.sop',
    'justifications/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Justification.sop',
    'solutions/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Solution.sop',
    'plans/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Plan.sop',
    'feature_support/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorSJSCompiledLookaheadTermSetOptimizationP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Satisfaction_Signature.sop'
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

$signaturePath = 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0_Satisfaction_Signature.sop'
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

$canonical = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_SJS_Compiled_Lookahead_Term_Set_Optimization_P0.sop'))
$requirements = @([regex]::Matches($canonical, '\[LTO-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($canonical, '\[LTO-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..32 | ForEach-Object { $_.ToString('000') }) 'requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance gates'

$profiles = @([regex]::Matches($canonical, 'cantor-sjs-lookahead-term-set-[a-z-]+/0\.1') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @('cantor-sjs-lookahead-term-set-request/0.1','cantor-sjs-lookahead-term-set-envelope/0.1','cantor-sjs-lookahead-term-set-verification/0.1','cantor-sjs-lookahead-term-set-evidence/0.1') 'profiles'

$inputLine = [regex]::Match($canonical, '\[LTO-006\][^\r\n]+').Value
$inputs = @([regex]::Matches($inputLine, '(synthetic_provider_free_fixture|supplied_unobserved_candidate_pool)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $inputs @('synthetic_provider_free_fixture','supplied_unobserved_candidate_pool') 'input classes'

$obligationLine = [regex]::Match($canonical, '\[LTO-009\][^\r\n]+').Value
$obligations = @([regex]::Matches($obligationLine, '(governing_requirement|current_decision|action_coordinate|evidence_gate|known_fault)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $obligations @('governing_requirement','current_decision','action_coordinate','evidence_gate','known_fault') 'obligation kinds'

$sourceLine = [regex]::Match($canonical, '\[LTO-012\][^\r\n]+').Value
$sources = @([regex]::Matches($sourceLine, '(governing_anchor|plan_hint|observed_coordinate|nonauthority_evidence)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $sources @('governing_anchor','plan_hint','observed_coordinate','nonauthority_evidence') 'source classes'

$metricLine = [regex]::Match($canonical, '\[LTO-013\][^\r\n]+').Value
$metrics = @([regex]::Matches($metricLine, '(decision relevance|ambiguity reduction|action relevance|evidence relevance|fault avoidance|anchoring risk|unsupported inference risk|stale distance)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $metrics @('decision relevance','ambiguity reduction','action relevance','evidence relevance','fault avoidance','anchoring risk','unsupported inference risk','stale distance') 'candidate metrics'

$statusLine = [regex]::Match($canonical, '\[LTO-024\][^\r\n]+').Value
$statuses = @([regex]::Matches($statusLine, '(selected_exact|insufficient_budget|uncoverable_mandatory)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $statuses @('selected_exact','insufficient_budget','uncoverable_mandatory') 'result statuses'

$dispositionLine = [regex]::Match($canonical, '\[LTO-025\][^\r\n]+').Value
$dispositions = @([regex]::Matches($dispositionLine, '(selected|dominated|feasible_not_selected|ineligible)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $dispositions @('selected','dominated','feasible_not_selected','ineligible') 'candidate dispositions'

if ($canonical -cnotmatch 'candidates are 1 through 16' -or $canonical -cnotmatch 'selected candidates 1 through 8' -or
    $canonical -cnotmatch 'projected bytes at most 8192' -or
    $canonical -cnotmatch 'eight candidates six obligations twelve coverage edges selection ceiling three ninety-two enumerated subsets three selected five rejected one dominated zero uncovered one unique optimum and fourteen zero effect counters' -or
    $canonical -cnotmatch 'performs no filesystem environment clock process network provider model inference embedding prompt mutation stitch mutation MCP Git workspace secret permission activation remote hardware or external action') { throw 'canonical bound fixture or pure-production assertion mismatch' }

$v = $manifest.verification
$verificationProperties = @('formation_artifact_count','signature_bound_artifact_count','requirement_count','acceptance_gate_count','profile_count','input_class_count','obligation_kind_count','source_class_count','candidate_metric_count','result_status_count','candidate_disposition_count','maximum_candidate_count','maximum_selected_count','maximum_projected_bytes','fixture_candidate_count','fixture_obligation_count','fixture_coverage_edge_count','fixture_selection_ceiling','fixture_enumerated_subset_count','fixture_selected_count','fixture_rejected_count','fixture_dominated_count','fixture_uncovered_count','execution_authorized','effect_counter_count','effect_count')
Assert-ExactProperties $v $verificationProperties 'verification properties'
$expectedCounts = @{formation_artifact_count=19;signature_bound_artifact_count=18;requirement_count=32;acceptance_gate_count=5;profile_count=4;input_class_count=2;obligation_kind_count=5;source_class_count=4;candidate_metric_count=8;result_status_count=3;candidate_disposition_count=4;maximum_candidate_count=16;maximum_selected_count=8;maximum_projected_bytes=8192;fixture_candidate_count=8;fixture_obligation_count=6;fixture_coverage_edge_count=12;fixture_selection_ceiling=3;fixture_enumerated_subset_count=92;fixture_selected_count=3;fixture_rejected_count=5;fixture_dominated_count=1;fixture_uncovered_count=0;effect_counter_count=14;effect_count=0}
foreach ($entry in $expectedCounts.GetEnumerator()) { if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" } }
if ($v.execution_authorized -ne $false) { throw 'execution authority must remain false' }

Write-Output 'sjs_compiled_lookahead_term_set_optimization_formation_passed artifacts=19 bindings=18 requirements=32 acceptance=5 profiles=4 input_classes=2 obligations=5 sources=4 metrics=8 statuses=3 dispositions=4 candidates_max=16 selected_max=8 bytes_max=8192 fixture=8_candidates_6_obligations_12_edges_ceiling3_92_subsets_selected3_rejected5_dominated1_uncovered0_unique1 execution_authorized=false effects=0'
