[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $root 'experiments/b1_operator_policy_governance_bundle_verification_p0/formation_evidence_manifest.json'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_B1_Operator_Policy_Governance_Bundle_Verification_P0_Satisfaction_Signature.sop'
$specificationPath = Join-Path $root 'specifications/Cantor_B1_Operator_Policy_Governance_Bundle_Verification_P0.sop'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Utf8([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$manifest = Read-Utf8 $manifestPath | ConvertFrom-Json
Assert-Exact ($manifest.profile -ceq 'cantor-b1-operator-policy-governance-bundle-verification-formation-evidence/0.1') 'manifest profile differs'
Assert-Exact ($manifest.manifest_uuid -ceq 'abcb2b28-1fe9-4188-8ebe-58f944d4ccda') 'manifest UUID differs'
Assert-Exact ($manifest.source_snapshot_uuid -ceq '39915a21-c45a-4402-a573-d43346c1edd8') 'source snapshot UUID differs'
Assert-Exact ($manifest.canonical_uuid -ceq '4a7ef159-ef62-4a2e-82fb-4010633c6858') 'canonical UUID differs'
Assert-Exact ($manifest.signature_uuid -ceq 'a67353a2-6730-4a81-b250-4f9ef9f1e6e7') 'signature UUID differs'
Assert-Exact ($manifest.source_custody_commit -ceq '142c5a0bcdc861e1effae00b3c34360a9b88ff55') 'source custody commit differs'
Assert-Exact ([int]$manifest.file_ref_count -eq 20 -and @($manifest.artifacts).Count -eq 20) 'artifact count differs'

$artifactPaths = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    Assert-Exact (-not $artifactPaths.ContainsKey($relative)) "duplicate artifact $relative"
    $artifactPaths[$relative] = $true
    $full = Join-Path $root $relative
    Assert-Exact (Test-Path -LiteralPath $full -PathType Leaf) "artifact absent $relative"
    Assert-Exact ([long]$artifact.bytes -eq (Get-Item -LiteralPath $full).Length) "artifact bytes differ $relative"
    Assert-Exact ([string]$artifact.sha256 -ceq (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash) "artifact hash differs $relative"
}

$signature = Read-Utf8 $signaturePath
$bindings = @([regex]::Matches($signature, '(?m)^\s*\+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\s*$'))
Assert-Exact ($bindings.Count -eq 19) 'signature binding count differs'
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    Assert-Exact ($artifactPaths.ContainsKey($relative)) "signature artifact absent from manifest $relative"
    Assert-Exact ($binding.Groups[2].Value -ceq (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash) "signature binding differs $relative"
}

$specification = Read-Utf8 $specificationPath
$requirements = @([regex]::Matches($specification, '(?m)^\s*\+ \[BPV-(\d{3})\]'))
$acceptance = @([regex]::Matches($specification, '(?m)^\s*\+ \[BPV-A(\d{2})\]'))
Assert-Exact ($requirements.Count -eq 24) 'requirement count differs'
Assert-Exact ($acceptance.Count -eq 5) 'acceptance count differs'
Assert-Exact ((@($requirements | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 24) 'requirement identity differs'
Assert-Exact ((@($acceptance | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 5) 'acceptance identity differs'

foreach ($profile in @(
    'cantor-b1-operator-policy-governance-payload/0.1',
    'cantor-b1-operator-policy-governance-envelope/0.1',
    'cantor-b1-operator-policy-governance-verification-request/0.1',
    'cantor-b1-operator-policy-governance-verification-receipt/0.1',
    'cantor-b1-operator-policy-governance-verification-evidence/0.1'
)) { Assert-Exact ($specification.Contains($profile)) "profile absent $profile" }
foreach ($inputClass in @('deterministic_fixture_candidate', 'externally_supplied_candidate')) {
    Assert-Exact ($specification.Contains($inputClass)) "input class absent $inputClass"
}
foreach ($coordinate in @(
    'policy_governance', 'key_custody', 'revocation_truth', 'current_time',
    'live_decision', 'fresh_observation', 'private_execution_permit',
    'broker_projection', 'physical_preparation'
)) { Assert-Exact ($specification.Contains($coordinate)) "authority coordinate absent $coordinate" }

$v = $manifest.verification
Assert-Exact ([int]$v.formation_artifact_count -eq 20 -and [int]$v.signature_bound_artifact_count -eq 19 -and [int]$v.invalid_reference_count -eq 0) 'formation account differs'
Assert-Exact ([int]$v.requirement_count -eq 24 -and [int]$v.acceptance_gate_count -eq 5) 'requirement account differs'
Assert-Exact ([int]$v.profile_count -eq 5 -and [int]$v.input_class_count -eq 2 -and [int]$v.evidence_file_count -eq 7) 'type account differs'
Assert-Exact ([int]$v.selected_coordinate_count -eq 1 -and [int]$v.downstream_authority_count -eq 8 -and [int]$v.positive_correspondence_field_count -eq 5) 'coordinate account differs'
Assert-Exact ([int]$v.maximum_form_bytes -eq 1048576 -and [int]$v.maximum_evidence_bytes -eq 8388608 -and [int]$v.maximum_depth -eq 32 -and [int]$v.maximum_fields -eq 2048 -and [int]$v.maximum_text_bytes -eq 8192 -and [int]$v.maximum_evidence_references -eq 32) 'bound account differs'
Assert-Exact ([int]$v.maximum_attempts -eq 1 -and [int]$v.retry_count -eq 0 -and [int]$v.cleanup_count -eq 0) 'attempt account differs'
foreach ($field in @(
    'production_authority_claimed', 'policy_governance_proved', 'key_custody_proved',
    'revocation_truth_proved', 'current_nonexpired', 'live_authorization_admitted',
    'fresh_observation_proved', 'private_execution_permit_present',
    'production_broker_projection_present', 'physical_preparation_authorized',
    'ready_for_physical_execution', 'execution_authorized'
)) { Assert-Exact (-not [bool]$v.$field) "authority field widened $field" }
Assert-Exact ([bool]$v.implementation_authorized -and [int]$v.formation_effect_count -eq 0) 'formation authority account differs'

Write-Output 'b1_operator_policy_governance_bundle_verification_formation_passed artifacts=20 bindings=19 requirements=24 acceptance=5 profiles=5 inputs=2 files=7 selected_A1=1 downstream_authorities=8 positive_correspondence=5 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false formation_effects=0'
