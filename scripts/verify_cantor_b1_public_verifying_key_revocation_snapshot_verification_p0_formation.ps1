[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $root 'experiments/b1_public_verifying_key_revocation_snapshot_verification_p0/formation_evidence_manifest.json'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Satisfaction_Signature.sop'
$specificationPath = Join-Path $root 'specifications/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0.sop'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Utf8([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$expectedPaths = @(
    'source_documents/2026-09-02_b1_public_verifying_key_revocation_snapshot_verification_p0/Derived_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Source.sop',
    'source_documents/2026-09-02_b1_public_verifying_key_revocation_snapshot_verification_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Input_Audit_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Requirements_Analysis_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Constraint_Ledger_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Delineation_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Dual_Hemisphere_Review_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Data_Design_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Threat_Review_2026-09-02.sop',
    'narrative/research/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Seven_Fold_Exhaustion_2026-09-02.sop',
    'specifications/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0.sop',
    'specifications/exploded/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0.exploded.sop',
    'justifications/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Justification.sop',
    'solutions/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Solution.sop',
    'plans/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Plan.sop',
    'feature_support/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorB1PublicVerifyingKeyRevocationSnapshotVerificationP0ReadinessReview.sop',
    'narrative/registries/Cantor_B1_Public_Verifying_Key_Revocation_Snapshot_Verification_P0_Satisfaction_Signature.sop'
)

$manifest = Read-Utf8 $manifestPath | ConvertFrom-Json
Assert-Exact ($manifest.profile -ceq 'cantor-b1-public-verifying-key-revocation-snapshot-verification-formation-evidence/0.1') 'manifest profile differs'
Assert-Exact ($manifest.manifest_uuid -ceq '8fe13e99-4d7c-44c5-8d87-2ddbd00a184d') 'manifest UUID differs'
Assert-Exact ($manifest.source_snapshot_uuid -ceq 'c6588e38-3471-4a56-96c7-d86e456e900a') 'source snapshot UUID differs'
Assert-Exact ($manifest.canonical_uuid -ceq 'aeb226ac-3c59-4b9b-a81e-d59f285f5a2d') 'canonical UUID differs'
Assert-Exact ($manifest.signature_uuid -ceq '5f4844b8-d5c0-47eb-ad0d-21f06dbdab6d') 'signature UUID differs'
Assert-Exact ($manifest.source_custody_commit -ceq '35d5774be39494afd8e5925cb42b2fc66dfb6b10') 'source custody commit differs'
Assert-Exact ([int]$manifest.file_ref_count -eq 20 -and @($manifest.artifacts).Count -eq 20) 'artifact count differs'
Assert-Exact ((@($manifest.artifacts.path) -join "`n") -ceq ($expectedPaths -join "`n")) 'artifact path sequence differs'

$artifactPaths = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    Assert-Exact (-not $artifactPaths.ContainsKey($relative)) "duplicate artifact $relative"
    $artifactPaths[$relative] = $true
    $full = Join-Path $root $relative
    Assert-Exact (Test-Path -LiteralPath $full -PathType Leaf) "artifact absent $relative"
    $item = Get-Item -LiteralPath $full -Force
    Assert-Exact (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) "artifact is link $relative"
    Assert-Exact ([long]$artifact.bytes -eq $item.Length) "artifact bytes differ $relative"
    Assert-Exact ([string]$artifact.sha256 -ceq (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash) "artifact hash differs $relative"
}

$signature = Read-Utf8 $signaturePath
$bindings = @([regex]::Matches($signature, '(?m)^\s*\+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\s*$'))
Assert-Exact ($bindings.Count -eq 19) 'signature binding count differs'
Assert-Exact ((@($bindings | ForEach-Object { $_.Groups[1].Value }) -join "`n") -ceq (($expectedPaths | Select-Object -First 19) -join "`n")) 'signature path sequence differs'
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    Assert-Exact ($artifactPaths.ContainsKey($relative)) "signature artifact absent from manifest $relative"
    Assert-Exact ($binding.Groups[2].Value -ceq (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash) "signature binding differs $relative"
}

$specification = Read-Utf8 $specificationPath
$requirements = @([regex]::Matches($specification, '(?m)^\s*\+ \[KRV-(\d{3})\]'))
$acceptance = @([regex]::Matches($specification, '(?m)^\s*\+ \[KRV-A(\d{2})\]'))
$expectedRequirements = @(1..25 | ForEach-Object { '{0:D3}' -f $_ })
$expectedAcceptance = @(1..5 | ForEach-Object { '{0:D2}' -f $_ })
Assert-Exact ($requirements.Count -eq 25 -and ((@($requirements | ForEach-Object { $_.Groups[1].Value }) -join ',') -ceq ($expectedRequirements -join ','))) 'requirement identity differs'
Assert-Exact ($acceptance.Count -eq 5 -and ((@($acceptance | ForEach-Object { $_.Groups[1].Value }) -join ',') -ceq ($expectedAcceptance -join ','))) 'acceptance identity differs'

foreach ($profile in @(
    'cantor-b1-public-verifying-key-revocation-snapshot/0.1',
    'cantor-b1-public-verifying-key-revocation-verification-request/0.1',
    'cantor-b1-public-verifying-key-revocation-verification-receipt/0.1',
    'cantor-b1-public-verifying-key-revocation-verification-evidence/0.1'
)) { Assert-Exact ($specification.Contains($profile)) "profile absent $profile" }
foreach ($inputClass in @('deterministic_fixture_candidate', 'externally_supplied_candidate')) {
    Assert-Exact ($specification.Contains($inputClass)) "input class absent $inputClass"
}
foreach ($evidenceFile in @(
    'predecessor_request.json', 'predecessor_packet.json', 'predecessor_verification.json',
    'a1_policy_envelope.json', 'a1_verification_request.json', 'a1_receipt.json',
    'custody_attestation.json', 'a2_verification_request.json', 'a2_receipt.json',
    'revocation_snapshot.json', 'verification_request.json', 'receipt.json', 'evidence_manifest.json'
)) { Assert-Exact ($specification.Contains($evidenceFile)) "evidence file absent $evidenceFile" }
foreach ($coordinate in @(
    'policy_governance', 'key_custody', 'revocation_truth', 'current_time',
    'live_decision', 'fresh_observation', 'private_execution_permit',
    'broker_projection', 'physical_preparation'
)) { Assert-Exact ($specification.Contains($coordinate)) "authority coordinate absent $coordinate" }
foreach ($status in @('status_assertion_not_revoked', 'status_assertion_revoked', 'status_assertion_unknown')) {
    Assert-Exact ($specification.Contains($status)) "status projection absent $status"
}

$v = $manifest.verification
Assert-Exact ([int]$v.formation_artifact_count -eq 20 -and [int]$v.signature_bound_artifact_count -eq 19 -and [int]$v.invalid_reference_count -eq 0) 'formation account differs'
Assert-Exact ([int]$v.requirement_count -eq 25 -and [int]$v.acceptance_gate_count -eq 5) 'requirement account differs'
Assert-Exact ([int]$v.profile_count -eq 4 -and [int]$v.input_class_count -eq 2 -and [int]$v.evidence_file_count -eq 13 -and [int]$v.status_projection_count -eq 3) 'type account differs'
Assert-Exact ([int]$v.selected_coordinate_count -eq 1 -and [int]$v.upstream_coordinate_replay_count -eq 1 -and [int]$v.downstream_authority_count -eq 6) 'coordinate account differs'
Assert-Exact ([int]$v.positive_correspondence_field_count -eq 9 -and [int]$v.false_authority_field_count -eq 24) 'truth-field account differs'
Assert-Exact ([int]$v.maximum_form_bytes -eq 1048576 -and [int]$v.maximum_evidence_bytes -eq 16777216 -and [int]$v.maximum_depth -eq 32 -and [int]$v.maximum_fields -eq 4096 -and [int]$v.maximum_text_bytes -eq 8192 -and [int]$v.maximum_evidence_references -eq 48) 'bound account differs'
Assert-Exact ([int]$v.maximum_attempts -eq 1 -and [int]$v.retry_count -eq 0 -and [int]$v.cleanup_count -eq 0) 'attempt account differs'
foreach ($field in @(
    'challenge_freshness_proved', 'replay_prevention_proved', 'custodian_identity_proved',
    'protected_storage_proved', 'private_key_nonexportability_proved', 'exclusive_control_proved',
    'current_possession_proved', 'responder_identity_proved', 'responder_authority_proved',
    'source_completeness_proved', 'monotonic_history_proved', 'snapshot_freshness_proved',
    'current_time_compared', 'policy_governance_proved', 'key_custody_proved',
    'revocation_truth_proved', 'current_nonexpired', 'live_authorization_admitted',
    'fresh_observation_proved', 'private_execution_permit_present',
    'production_broker_projection_present', 'physical_preparation_authorized',
    'ready_for_physical_execution', 'execution_authorized'
)) { Assert-Exact (-not [bool]$v.$field) "authority field widened $field" }
Assert-Exact ([bool]$v.implementation_authorized -and [int]$v.formation_effect_count -eq 0) 'formation authority account differs'

git -C $root cat-file -e '35d5774be39494afd8e5925cb42b2fc66dfb6b10^{commit}'
Assert-Exact ($LASTEXITCODE -eq 0) 'source custody commit absent'

Write-Output 'b1_public_verifying_key_revocation_snapshot_verification_formation_passed artifacts=20 bindings=19 requirements=25 acceptance=5 profiles=4 inputs=2 files=13 statuses=3 selected_A3=1 upstream_A2=1 downstream_authorities=6 positive_correspondence=9 false_authority=24 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false formation_effects=0'
