param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/sjs_compiled_lookahead_repository_candidate_extraction_p0/formation_evidence_manifest.json'

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
$top = @('profile','manifest_uuid','canonical_uuid','signature_uuid','source_snapshot_uuid','parent_term_set_canonical_uuid','source_commit','file_ref_count','artifacts','verification','disposition')
Assert-ExactProperties $manifest $top 'manifest top properties'
if ($manifest.profile -cne 'cantor-sjs-compiled-lookahead-repository-candidate-extraction-p0-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '13684bf3-fe6a-4ddd-87bd-c56a5c8fda03' -or
    $manifest.canonical_uuid -cne '3359fdaf-f4bf-44f0-9892-3f8d8d5e027f' -or
    $manifest.signature_uuid -cne '4d4b6518-942f-4219-9d63-55ec9dd66cc3' -or
    $manifest.source_snapshot_uuid -cne '81ba4e67-0ebe-41db-bb8f-2437bc629c4c' -or
    $manifest.parent_term_set_canonical_uuid -cne '5bb132b9-8250-4f6d-a7e6-6977edad8162' -or
    $manifest.source_commit -cne '848a80e90e64af253c7c195e2a5e14cb20330295' -or
    $manifest.disposition -cne 'formation_complete_provider_free_awaiting_attributed_publication') { throw 'formation identity or disposition mismatch' }

$expectedPaths = @(
    'source_documents/2026-08-31_sjs_compiled_lookahead_repository_candidate_extraction_p0/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Source.sop',
    'source_documents/2026-08-31_sjs_compiled_lookahead_repository_candidate_extraction_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Input_Audit_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Constraint_Ledger_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Delineation_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Data_Design_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Dual_Hemisphere_Review_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Threat_Review_2026-08-31.sop',
    'narrative/research/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Seven_Fold_Exhaustion_2026-08-31.sop',
    'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0.sop',
    'specifications/exploded/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0.exploded.sop',
    'justifications/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Justification.sop',
    'solutions/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Solution.sop',
    'plans/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Plan.sop',
    'feature_support/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorSJSCompiledLookaheadRepositoryCandidateExtractionP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Satisfaction_Signature.sop'
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

$signaturePath = 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0_Satisfaction_Signature.sop'
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

$canonical = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Candidate_Extraction_P0.sop'))
$requirements = @([regex]::Matches($canonical, '\[RCX-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($canonical, '\[RCX-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..32 | ForEach-Object { $_.ToString('000') }) 'requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance gates'

$profiles = @([regex]::Matches($canonical, 'cantor-sjs-lookahead-repository-candidate-[a-z-]+/0\.1') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @('cantor-sjs-lookahead-repository-candidate-request/0.1','cantor-sjs-lookahead-repository-candidate-envelope/0.1','cantor-sjs-lookahead-repository-candidate-verification/0.1','cantor-sjs-lookahead-repository-candidate-evidence/0.1') 'profiles'

$elementLine = [regex]::Match($canonical, '\[RCX-008\][^\r\n]+').Value
$elementKinds = @([regex]::Matches($elementLine, '(governing_requirement|governing_constraint|nonauthority_denial|open_obligation|current_objective|dependency_coordinate|frontier|file_coordinate|symbol_coordinate|expected_output|evidence_gate|operational_fault|ambiguity|rejected_route|attributed_prior_receipt)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
if ($elementKinds.Count -ne 15) { throw 'element kind count mismatch' }

if ($canonical -cnotmatch 'records are 1 through 16 obligations are 1 through 64 coverage edges are 0 through 256' -or
    $canonical -cnotmatch 'supplied records are eight obligations are six coverage edges are twelve' -or
    $canonical -cnotmatch 'ninety-two subsets under selection ceiling three' -or
    $canonical -cnotmatch 'performs no filesystem environment clock process network provider model inference embedding prompt mutation stitch mutation MCP Git workspace secret permission activation remote hardware or external action') { throw 'canonical bounds fixture or effect assertion mismatch' }

$v = $manifest.verification
$expected = [ordered]@{formation_artifact_count=19;signature_bound_artifact_count=18;requirement_count=32;acceptance_gate_count=5;profile_count=4;input_class_count=2;element_kind_count=15;source_class_count=4;obligation_kind_count=5;maximum_record_count=16;maximum_obligation_count=64;maximum_coverage_edge_count=256;maximum_machine_form_bytes=1048576;fixture_record_count=8;fixture_obligation_count=6;fixture_coverage_edge_count=12;fixture_downstream_subset_count=92;fixture_selected_count=3;fixture_rejected_count=5;fixture_dominated_count=1;fixture_uncovered_count=0;effect_counter_count=14;effect_count=0}
Assert-ExactProperties $v (@($expected.Keys) + @('execution_authorized')) 'verification properties'
foreach ($entry in $expected.GetEnumerator()) { if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" } }
if ($v.execution_authorized -ne $false) { throw 'execution authority must remain false' }

Write-Output 'sjs_compiled_lookahead_repository_candidate_extraction_formation_passed artifacts=19 bindings=18 requirements=32 acceptance=5 profiles=4 inputs=2 element_kinds=15 source_classes=4 obligation_kinds=5 records_max=16 obligations_max=64 edges_max=256 bytes_max=1048576 fixture=8_records_6_obligations_12_edges_92_subsets_selected3_rejected5_dominated1_uncovered0 execution_authorized=false effects=0'
