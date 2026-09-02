[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $root 'experiments/b1_public_verifying_key_custody_attestation_verification_p0/formation_evidence_manifest.json'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_B1_Public_Verifying_Key_Custody_Attestation_Verification_P0_Satisfaction_Signature.sop'
$specificationPath = Join-Path $root 'specifications/Cantor_B1_Public_Verifying_Key_Custody_Attestation_Verification_P0.sop'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Utf8([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$manifest = Read-Utf8 $manifestPath | ConvertFrom-Json
Assert-Exact ($manifest.profile -ceq 'cantor-b1-public-verifying-key-custody-attestation-verification-formation-evidence/0.1') 'manifest profile differs'
Assert-Exact ($manifest.manifest_uuid -ceq '28857fd7-7632-4806-ba59-be7b2da72ef9') 'manifest UUID differs'
Assert-Exact ($manifest.source_snapshot_uuid -ceq '957fa5a6-34eb-41da-8c95-2a1dc89cc3bb') 'source snapshot UUID differs'
Assert-Exact ($manifest.canonical_uuid -ceq '668ae1a2-e8c9-4f88-9556-a39585817105') 'canonical UUID differs'
Assert-Exact ($manifest.signature_uuid -ceq 'fd889970-8468-447c-bf1c-58d22b9c64a1') 'signature UUID differs'
Assert-Exact ($manifest.source_custody_commit -ceq 'c94c2eeb104243fd9e83ee67c4ad6a763f4bdfbc') 'source custody commit differs'
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
$requirements = @([regex]::Matches($specification, '(?m)^\s*\+ \[KCV-(\d{3})\]'))
$acceptance = @([regex]::Matches($specification, '(?m)^\s*\+ \[KCV-A(\d{2})\]'))
Assert-Exact ($requirements.Count -eq 25) 'requirement count differs'
Assert-Exact ($acceptance.Count -eq 5) 'acceptance count differs'
Assert-Exact ((@($requirements | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 25) 'requirement identity differs'
Assert-Exact ((@($acceptance | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 5) 'acceptance identity differs'

foreach ($profile in @(
    'cantor-b1-public-verifying-key-custody-attestation/0.1',
    'cantor-b1-key-custody-proof-challenge/0.1',
    'cantor-b1-public-verifying-key-custody-verification-request/0.1',
    'cantor-b1-public-verifying-key-custody-verification-receipt/0.1',
    'cantor-b1-public-verifying-key-custody-verification-evidence/0.1'
)) { Assert-Exact ($specification.Contains($profile)) "profile absent $profile" }
foreach ($inputClass in @('deterministic_fixture_candidate', 'externally_supplied_candidate')) {
    Assert-Exact ($specification.Contains($inputClass)) "input class absent $inputClass"
}
foreach ($evidenceFile in @(
    'predecessor_request.json', 'predecessor_packet.json', 'predecessor_verification.json',
    'a1_policy_envelope.json', 'a1_verification_request.json', 'a1_receipt.json',
    'custody_attestation.json', 'verification_request.json', 'receipt.json', 'evidence_manifest.json'
)) { Assert-Exact ($specification.Contains($evidenceFile)) "evidence file absent $evidenceFile" }
foreach ($coordinate in @(
    'policy_governance', 'key_custody', 'revocation_truth', 'current_time',
    'live_decision', 'fresh_observation', 'private_execution_permit',
    'broker_projection', 'physical_preparation'
)) { Assert-Exact ($specification.Contains($coordinate)) "authority coordinate absent $coordinate" }

$v = $manifest.verification
Assert-Exact ([int]$v.formation_artifact_count -eq 20 -and [int]$v.signature_bound_artifact_count -eq 19 -and [int]$v.invalid_reference_count -eq 0) 'formation account differs'
Assert-Exact ([int]$v.requirement_count -eq 25 -and [int]$v.acceptance_gate_count -eq 5) 'requirement account differs'
Assert-Exact ([int]$v.profile_count -eq 5 -and [int]$v.input_class_count -eq 2 -and [int]$v.evidence_file_count -eq 10) 'type account differs'
Assert-Exact ([int]$v.selected_coordinate_count -eq 1 -and [int]$v.upstream_coordinate_replay_count -eq 1 -and [int]$v.downstream_authority_count -eq 7) 'coordinate account differs'
Assert-Exact ([int]$v.positive_correspondence_field_count -eq 7 -and [int]$v.false_authority_field_count -eq 18) 'truth-field account differs'
Assert-Exact ([int]$v.maximum_form_bytes -eq 1048576 -and [int]$v.maximum_evidence_bytes -eq 12582912 -and [int]$v.maximum_depth -eq 32 -and [int]$v.maximum_fields -eq 3072 -and [int]$v.maximum_text_bytes -eq 8192 -and [int]$v.maximum_evidence_references -eq 32 -and [int]$v.nonce_bytes -eq 32) 'bound account differs'
Assert-Exact ([int]$v.maximum_attempts -eq 1 -and [int]$v.retry_count -eq 0 -and [int]$v.cleanup_count -eq 0) 'attempt account differs'
foreach ($field in @(
    'challenge_freshness_proved', 'replay_prevention_proved', 'custodian_identity_proved',
    'protected_storage_proved', 'private_key_nonexportability_proved', 'exclusive_control_proved',
    'current_possession_proved', 'policy_governance_proved', 'key_custody_proved',
    'revocation_truth_proved', 'current_nonexpired', 'live_authorization_admitted',
    'fresh_observation_proved', 'private_execution_permit_present',
    'production_broker_projection_present', 'physical_preparation_authorized',
    'ready_for_physical_execution', 'execution_authorized'
)) { Assert-Exact (-not [bool]$v.$field) "authority field widened $field" }
Assert-Exact ([bool]$v.implementation_authorized -and [int]$v.formation_effect_count -eq 0) 'formation authority account differs'

Write-Output 'b1_public_verifying_key_custody_attestation_verification_formation_passed artifacts=20 bindings=19 requirements=25 acceptance=5 profiles=5 inputs=2 files=10 selected_A2=1 upstream_A1=1 downstream_authorities=7 positive_correspondence=7 false_authority=18 nonce_bytes=32 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false formation_effects=0'
