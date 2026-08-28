param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$manifestRelative = 'experiments/nested_inner_model_admission_p0/formation_evidence_manifest.json'
$manifestPath = Join-Path $RepositoryRoot $manifestRelative

function Assert-ExactSet([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    if ($actualStrings.Count -ne $Expected.Count -or @($actualStrings | Sort-Object -Unique).Count -ne $Expected.Count) {
        throw "$Label cardinality or uniqueness mismatch"
    }
    $delta = Compare-Object ($Expected | Sort-Object) ($actualStrings | Sort-Object)
    if ($delta) {
        throw "$Label membership mismatch: $($delta | Out-String)"
    }
}

function Assert-RawJsonKeyCount([string]$Raw, [string]$Name, [int]$ExpectedCount) {
    $pattern = '"' + [regex]::Escape($Name) + '"\s*:'
    $actualCount = [regex]::Matches($Raw, $pattern).Count
    if ($actualCount -ne $ExpectedCount) {
        throw "JSON key count mismatch for $Name`: expected $ExpectedCount actual $actualCount"
    }
}

$raw = [IO.File]::ReadAllText($manifestPath)
$manifest = $raw | ConvertFrom-Json

$expectedTopLevel = @(
    'profile', 'manifest_uuid', 'generated_at_utc', 'source_custody_commit',
    'published_nhc02', 'canonical_uuid', 'signature_uuid', 'disposition',
    'file_ref_count', 'artifacts', 'verification', 'non_authority_statement'
)
Assert-ExactSet @($manifest.PSObject.Properties.Name) $expectedTopLevel 'top-level properties'
foreach ($name in $expectedTopLevel) {
    Assert-RawJsonKeyCount $raw $name 1
}

if ($manifest.profile -cne 'cantor-nested-inner-model-admission-formation-evidence/0.1' -or
    $manifest.manifest_uuid -cne '85236e6d-d514-4e07-84c5-f43d68c94f42' -or
    $manifest.canonical_uuid -cne 'b3d30f7a-6c16-4245-9d9a-3e8b79a61247' -or
    $manifest.signature_uuid -cne '7d16343d-39d9-492e-84c5-770d281a8a2c' -or
    $manifest.source_custody_commit -cne '7908bd4b9e742f6d02991c3695c024a2a40c5389' -or
    $manifest.published_nhc02 -cne '72855c2f83c220c9bc589df497a3389553bf0990') {
    throw 'formation identity mismatch'
}

$expectedPaths = @(
    'proofs/Cantor_Nested_Inner_Process_Lineage_P0_Implementation_Publication_Checkpoint_Proof.sop',
    'source_documents/2026-08-28_nested_inner_model_admission_p0/Nested_Inner_Model_Admission_P0_Source.sop',
    'source_documents/2026-08-28_nested_inner_model_admission_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Input_Audit_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Delineation_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Data_Design_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Dual_Hemisphere_Review_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Threat_Review_2026-08-28.sop',
    'narrative/research/Cantor_Nested_Inner_Model_Admission_P0_Seven_Fold_Exhaustion_2026-08-28.sop',
    'specifications/Cantor_Nested_Inner_Model_Admission_P0.sop',
    'specifications/exploded/Cantor_Nested_Inner_Model_Admission_P0.exploded.sop',
    'feature_support/Cantor_Nested_Inner_Model_Admission_P0_Requirement_Matrix.sop',
    'justifications/Cantor_Nested_Inner_Model_Admission_P0_Justification.sop',
    'solutions/Cantor_Nested_Inner_Model_Admission_P0_Solution.sop',
    'plans/Cantor_Nested_Inner_Model_Admission_P0_Plan.sop',
    'narrative/registries/Cantor_Nested_Inner_Model_Admission_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_Nested_Inner_Model_Admission_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorNestedInnerModelAdmissionP0SignatureReadinessReview.sop',
    'narrative/registries/Cantor_Nested_Inner_Model_Admission_P0_Satisfaction_Signature.sop'
)
if ($manifest.file_ref_count -ne 19 -or @($manifest.artifacts).Count -ne 19) {
    throw 'formation artifact count mismatch'
}
foreach ($name in @('path', 'bytes', 'sha256')) {
    Assert-RawJsonKeyCount $raw $name 19
}
Assert-ExactSet @($manifest.artifacts.path) $expectedPaths 'formation artifacts'

$artifactIdentities = @()
foreach ($artifact in @($manifest.artifacts)) {
    Assert-ExactSet @($artifact.PSObject.Properties.Name) @('path', 'bytes', 'sha256') "artifact properties $($artifact.path)"
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "nonportable artifact path: $relative"
    }
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "formation artifact missing: $relative"
    }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ([long]$artifact.bytes -ne $item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -ne $hash) {
        throw "formation artifact identity mismatch: $relative"
    }
    $artifactIdentities += "$($item.Length)|$hash"
}

$signaturePath = Join-Path $RepositoryRoot 'narrative/registries/Cantor_Nested_Inner_Model_Admission_P0_Satisfaction_Signature.sop'
$signature = [IO.File]::ReadAllText($signaturePath)
$bindingMatches = [regex]::Matches($signature, ' is ([0-9]+) bytes SHA256 ([A-F0-9]{64})')
if ($bindingMatches.Count -ne 18) {
    throw "signature binding count mismatch: $($bindingMatches.Count)"
}
$signatureIdentities = @($bindingMatches | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)" })
Assert-ExactSet $signatureIdentities @($artifactIdentities[0..17]) 'signature artifact bindings'

$specPath = Join-Path $RepositoryRoot 'specifications/Cantor_Nested_Inner_Model_Admission_P0.sop'
$spec = [IO.File]::ReadAllText($specPath)
$requirements = @([regex]::Matches($spec, '\[NHMA-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$acceptance = @([regex]::Matches($spec, '\[NHMA-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
$expectedRequirements = @(1..23 | ForEach-Object { $_.ToString('000') })
$expectedAcceptance = @(1..5 | ForEach-Object { $_.ToString('00') })
Assert-ExactSet $requirements $expectedRequirements 'canonical requirements'
Assert-ExactSet $acceptance $expectedAcceptance 'acceptance requirements'

$verification = $manifest.verification
$verificationProperties = @(
    'formation_artifact_count', 'signature_bound_artifact_count', 'invalid_reference_count',
    'requirement_count', 'acceptance_requirement_count', 'upstream_operational_identity_count',
    'operational_identity_count', 'bound_identity_count', 'capability_denial_count',
    'unresolved_truth_count', 'detached_authorization_required', 'load_authority_form_defined',
    'authorization_issued', 'artifact_file_observed', 'artifact_bytes_reacquired',
    'artifact_admitted', 'model_load_attempt_count', 'model_load_completion_count',
    'runtime_model_observed', 'process_count', 'provider_trial_count', 'model_turn_count',
    'mcp_call_count', 'workspace_mutation_count', 'network_contact_count',
    'remote_contact_count', 'persistence_count', 'activation_count',
    'cleanup_effect_count', 'foreign_effect_count'
)
Assert-ExactSet @($verification.PSObject.Properties.Name) $verificationProperties 'verification properties'
foreach ($name in $verificationProperties) {
    Assert-RawJsonKeyCount $raw $name 1
}
$exactCounts = @{
    formation_artifact_count = 19
    signature_bound_artifact_count = 18
    invalid_reference_count = 0
    requirement_count = 23
    acceptance_requirement_count = 5
    upstream_operational_identity_count = 7
    operational_identity_count = 8
    bound_identity_count = 10
    capability_denial_count = 15
    unresolved_truth_count = 10
}
foreach ($entry in $exactCounts.GetEnumerator()) {
    if ([long]$verification.($entry.Key) -ne [long]$entry.Value) {
        throw "verification count mismatch: $($entry.Key)"
    }
}
$requiredTrue = @('detached_authorization_required', 'load_authority_form_defined')
foreach ($name in $requiredTrue) {
    if ($verification.$name -ne $true) { throw "required true formation flag mismatch: $name" }
}
$requiredFalse = @('authorization_issued', 'artifact_file_observed', 'artifact_bytes_reacquired', 'artifact_admitted', 'runtime_model_observed')
foreach ($name in $requiredFalse) {
    if ($verification.$name -ne $false) { throw "required false formation flag mismatch: $name" }
}
$zeroCounts = @('model_load_attempt_count', 'model_load_completion_count', 'process_count', 'provider_trial_count', 'model_turn_count', 'mcp_call_count', 'workspace_mutation_count', 'network_contact_count', 'remote_contact_count', 'persistence_count', 'activation_count', 'cleanup_effect_count', 'foreign_effect_count')
foreach ($name in $zeroCounts) {
    if ([long]$verification.$name -ne 0) { throw "nonzero formation effect: $name" }
}

Write-Output 'nested_inner_model_admission_formation_passed artifacts=19 signature_bindings=18 requirements=23 acceptance=5 upstream_identities=7 operational_identities=8 bound_identities=10 denials=15 unresolved=10 effects=0'
