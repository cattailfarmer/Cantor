param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/runtime_closure_materialization_plan_p0/formation_evidence_manifest.json'

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
    'upstream_canonical_uuid','upstream_signature_uuid','source_commit','file_ref_count',
    'artifacts','verification','disposition'
)
Assert-ExactProperties $manifest $topProperties 'manifest top properties'
if ($manifest.profile -cne 'cantor-runtime-closure-materialization-plan-p0-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '4ccf4650-254f-49d0-a9bc-ba2102cf1dae' -or
    $manifest.canonical_uuid -cne '1ec5159a-cddd-4061-a316-4dace13d2e06' -or
    $manifest.signature_uuid -cne '90be7b47-10d2-47a5-989e-8c40120bd60b' -or
    $manifest.source_snapshot_uuid -cne 'dc7d8d88-83bd-4f0c-bc2a-6973afa99700' -or
    $manifest.upstream_canonical_uuid -cne '9f2b4613-353f-4cf2-ab66-a3bb3b97feb3' -or
    $manifest.upstream_signature_uuid -cne '8f34fed3-755e-4ae5-a129-9a09ad6dd94b' -or
    $manifest.source_commit -cne '0538a45b9de9e30540026c106d7e5f0284aadb2f' -or
    $manifest.disposition -cne 'formation_complete_effectless_awaiting_attributed_publication') {
    throw 'formation identity or disposition mismatch'
}

$expectedPaths = @(
    'source_documents/2026-08-30_runtime_closure_materialization_plan_p0/Cantor_Runtime_Closure_Materialization_Plan_P0_Source.sop',
    'source_documents/2026-08-30_runtime_closure_materialization_plan_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Input_Audit_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Constraint_Ledger_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Delineation_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Data_Design_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Dual_Hemisphere_Review_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Threat_Review_2026-08-30.sop',
    'narrative/research/Cantor_Runtime_Closure_Materialization_Plan_P0_Seven_Fold_Exhaustion_2026-08-30.sop',
    'specifications/Cantor_Runtime_Closure_Materialization_Plan_P0.sop',
    'specifications/exploded/Cantor_Runtime_Closure_Materialization_Plan_P0.exploded.sop',
    'justifications/Cantor_Runtime_Closure_Materialization_Plan_P0_Justification.sop',
    'solutions/Cantor_Runtime_Closure_Materialization_Plan_P0_Solution.sop',
    'plans/Cantor_Runtime_Closure_Materialization_Plan_P0_Plan.sop',
    'feature_support/Cantor_Runtime_Closure_Materialization_Plan_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_Runtime_Closure_Materialization_Plan_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_Runtime_Closure_Materialization_Plan_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorRuntimeClosureMaterializationPlanP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_Runtime_Closure_Materialization_Plan_P0_Satisfaction_Signature.sop'
)
if ([long]$manifest.file_ref_count -ne 19 -or @($manifest.artifacts).Count -ne 19) { throw 'artifact count mismatch' }
Assert-ExactSet @($manifest.artifacts.path) $expectedPaths 'artifact paths'

$manifestHashes = @{}
foreach ($artifact in @($manifest.artifacts)) {
    Assert-ExactProperties $artifact @('path','bytes','sha256') "artifact properties $($artifact.path)"
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') { throw "nonportable path $relative" }
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ([long]$artifact.bytes -ne [long]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -cne $hash) {
        throw "artifact identity mismatch $relative"
    }
    $manifestHashes[$relative] = $hash
}

$signaturePath = 'narrative/registries/Cantor_Runtime_Closure_Materialization_Plan_P0_Satisfaction_Signature.sop'
$signature = [IO.File]::ReadAllText((Join-Path $RepositoryRoot $signaturePath))
$bindingMatches = [regex]::Matches($signature, '\[artifact_binding\] ([^\r\n]+) SHA256 ([A-F0-9]{64})')
if ($bindingMatches.Count -ne 18) { throw 'signature binding count mismatch' }
$boundPaths = @()
foreach ($binding in $bindingMatches) {
    $relative = $binding.Groups[1].Value
    $hash = $binding.Groups[2].Value
    if (-not $manifestHashes.ContainsKey($relative) -or $manifestHashes[$relative] -cne $hash) {
        throw "signature binding mismatch $relative"
    }
    $boundPaths += $relative
}
Assert-ExactSet $boundPaths @($expectedPaths[0..17]) 'signature-bound paths'

$canonicalPath = Join-Path $RepositoryRoot 'specifications/Cantor_Runtime_Closure_Materialization_Plan_P0.sop'
$canonical = [IO.File]::ReadAllText($canonicalPath)
$requirements = @([regex]::Matches($canonical, '\[RMP-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($canonical, '\[RMP-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $requirements @(1..30 | ForEach-Object { $_.ToString('000') }) 'requirements'
Assert-ExactSet $acceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'acceptance gates'

$profiles = @([regex]::Matches($canonical, 'cantor-runtime-closure-materialization-plan-[a-z-]+/0\.1') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @(
    'cantor-runtime-closure-materialization-plan-request/0.1',
    'cantor-runtime-closure-materialization-plan-envelope/0.1',
    'cantor-runtime-closure-materialization-plan-verification/0.1',
    'cantor-runtime-closure-materialization-plan-evidence/0.1'
) 'canonical profiles'

$inputLine = [regex]::Match($canonical, '\[RMP-004\][^\r\n]+').Value
$inputs = @([regex]::Matches($inputLine, '(synthetic_provider_free_fixture|supplied_unobserved_declaration)') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $inputs @('synthetic_provider_free_fixture','supplied_unobserved_declaration') 'input classes'

$phaseLine = [regex]::Match($canonical, '\[RMP-009\][^\r\n]+').Value
$expectedPhases = @('seed_validation','prerequisite_resolution','material_production','target_preparation','material_staging','material_verification','rollback_preparation','closure_verification','receipt_candidate')
$phases = @([regex]::Matches($phaseLine, '[a-z]+(?:_[a-z]+)+') | ForEach-Object { $_.Value })
Assert-ExactSet $phases $expectedPhases 'phases'

$kindLine = [regex]::Match($canonical, '\[RMP-010\][^\r\n]+').Value
$expectedKinds = @('validate_seed_root','resolve_prerequisite','apply_deterministic_transform','run_source_build','acquire_content_addressed_artifact','accept_explicitly_supplied_material','generate_configuration','prepare_target','stage_material','verify_material','prepare_rollback','verify_closure','emit_receipt_candidate')
$kinds = @([regex]::Matches($kindLine, '[a-z]+(?:_[a-z]+)+') | ForEach-Object { $_.Value })
Assert-ExactSet $kinds $expectedKinds 'operation kinds'

$denialLine = [regex]::Match($canonical, '\[RMP-023\][^\r\n]+').Value
$expectedDenials = @('filesystem_read','filesystem_write','filesystem_delete','environment_read','clock_read','process_spawn','shell_exec','compiler_exec','package_manager_exec','network_contact','artifact_download','provider_contact','model_load','inference','mcp_contact','git_mutation','workspace_mutation','secret_access','permission_change','service_activation','cleanup','rollback','remote_access','hardware_effect','external_effect')
$denials = @([regex]::Matches($denialLine, '[a-z]+(?:_[a-z]+)+|\binference\b|\bcleanup\b|\brollback\b') | ForEach-Object { $_.Value })
Assert-ExactSet $denials $expectedDenials 'capability denials'

$formulaLine = [regex]::Match($canonical, '\[RMP-017\][^\r\n]+').Value
if ($formulaLine -cnotmatch 'exactly four times material node count plus prerequisite count plus three' -or
    $formulaLine -cnotmatch '11 through 1155') { throw 'operation formula or bounds mismatch' }
if ($canonical -cnotmatch 'execution_authorized is false' -or
    $canonical -cnotmatch 'zero observations executed operations materialized nodes verified nodes filesystem results verifier results' -or
    $canonical -cnotmatch 'first retained fixture is the exact existing small synthetic P0 closure') {
    throw 'canonical authority, receipt-zero, or fixture-class assertion mismatch'
}

$v = $manifest.verification
$verificationProperties = @(
    'formation_artifact_count','signature_bound_artifact_count','requirement_count','acceptance_gate_count',
    'profile_count','input_class_count','phase_count','operation_kind_count','operation_count_formula_coefficient',
    'operation_count_formula_constant','operation_count_minimum','operation_count_maximum','capability_denial_count',
    'execution_authorized','observation_count','executed_operation_count','filesystem_effect_count','process_effect_count',
    'network_effect_count','provider_effect_count','model_effect_count','secret_effect_count','remote_effect_count',
    'hardware_effect_count','foreign_effect_count'
)
Assert-ExactProperties $v $verificationProperties 'verification properties'
$expectedCounts = @{
    formation_artifact_count=19; signature_bound_artifact_count=18; requirement_count=30; acceptance_gate_count=5;
    profile_count=4; input_class_count=2; phase_count=9; operation_kind_count=13;
    operation_count_formula_coefficient=4; operation_count_formula_constant=3; operation_count_minimum=11;
    operation_count_maximum=1155; capability_denial_count=25; observation_count=0; executed_operation_count=0
}
foreach ($entry in $expectedCounts.GetEnumerator()) {
    if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" }
}
if ($v.execution_authorized -ne $false) { throw 'execution authority must remain false' }
foreach ($name in @('filesystem_effect_count','process_effect_count','network_effect_count','provider_effect_count','model_effect_count','secret_effect_count','remote_effect_count','hardware_effect_count','foreign_effect_count')) {
    if ([long]$v.$name -ne 0) { throw "nonzero effect $name" }
}

$forbiddenImplementationPaths = @(
    'crates/cantor_core/src/runtime_closure_materialization_plan.rs',
    'crates/cantor_core/tests/runtime_closure_materialization_plan.rs',
    'crates/cantor_core/src/bin/cantor-runtime-closure-materialization-plan-fixture.rs',
    'crates/cantor_core/src/bin/cantor-runtime-closure-materialization-plan-verify.rs'
)
foreach ($relative in $forbiddenImplementationPaths) {
    if (Test-Path -LiteralPath (Join-Path $RepositoryRoot $relative)) { throw "implementation preceded formation publication: $relative" }
}

Write-Output 'runtime_closure_materialization_plan_formation_passed artifacts=19 bindings=18 requirements=30 acceptance=5 profiles=4 input_classes=2 phases=9 operation_kinds=13 operation_bounds=11..1155 denials=25 execution_authorized=false effects=0'
