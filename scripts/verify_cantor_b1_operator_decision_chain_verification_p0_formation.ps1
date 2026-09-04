[CmdletBinding()]
param([string]$RepositoryRoot)

# Read-only A5 formation verifier. Semantic pins are independent of supplied manifest and signature text.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$scriptRepository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestRelative = 'experiments/b1_operator_decision_chain_verification_p0/formation_evidence_manifest.json'
$expectedPaths = @(
    'source_documents/2026-09-03_b1_operator_decision_chain_verification_p0/Derived_B1_Operator_Decision_Chain_Verification_P0_Source.sop',
    'source_documents/2026-09-03_b1_operator_decision_chain_verification_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Input_Audit_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Requirements_Analysis_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Constraint_Ledger_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Delineation_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Dual_Hemisphere_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Data_Design_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Threat_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Seven_Fold_Exhaustion_2026-09-03.sop',
    'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Primary_Research_2026-09-03.sop',
    'specifications/Cantor_B1_Operator_Decision_Chain_Verification_P0.sop',
    'specifications/exploded/Cantor_B1_Operator_Decision_Chain_Verification_P0.exploded.sop',
    'justifications/Cantor_B1_Operator_Decision_Chain_Verification_P0_Justification.sop',
    'solutions/Cantor_B1_Operator_Decision_Chain_Verification_P0_Solution.sop',
    'plans/Cantor_B1_Operator_Decision_Chain_Verification_P0_Plan.sop',
    'feature_support/Cantor_B1_Operator_Decision_Chain_Verification_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_B1_Operator_Decision_Chain_Verification_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_B1_Operator_Decision_Chain_Verification_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorB1OperatorDecisionChainVerificationP0ReadinessReview.sop',
    'narrative/registries/Cantor_B1_Operator_Decision_Chain_Verification_P0_Satisfaction_Signature.sop'
)
$expectedRequirements = @(
    '  + [ODCV-001] bind source snapshot dc4d390b-953b-415f-9fd9-2bd6f4838e19 custody a2bcb61130c60244a1bc6ba98a00a652c657ed40 source bookend 91a80ea053e70fe073c8cd2257e5dc7fe5a2b97e A4 implementation bc212c53a62cf99a3ff0c27544be5e5f4d6cf46e bookend 7eeadad031c432648942d8725edb2d56554c251a proof 851b534f-6542-43c6-b4d3-472dd0bd70b6 and legacy implementation 9aaaab269836b8265c74ac9c46c690493c9fe746 bookend bfc068ff93ef781cab3d58e7f3fce0be21ac0ccc proof 5e48d1ed-a769-46b1-b7c0-a52fe7db5b2b',
    '  + [ODCV-002] new profiles are exactly cantor-b1-operator-decision-chain-request/0.1 cantor-b1-operator-decision-chain-receipt/0.1 cantor-b1-operator-decision-chain-evidence/0.1; import five unchanged legacy policy request payload envelope verification contracts and no new signature grammar',
    '  + [ODCV-003] maximum form bytes 1048576 total evidence bytes 16777216 JSON depth 32 aggregate fields 4096 new general text bytes 8192 evidence references one through forty-eight unique nonempty opaque values; preserve stricter legacy limits',
    '  + [ODCV-004] input class is exactly deterministic_fixture_candidate or externally_supplied_candidate and matches A5 descriptor policy payload and envelope fixture markers without forcing all upstream candidates to have that class',
    '  + [ODCV-005] evidence membership is exactly twenty-one direct regular nonlink files in this order: predecessor_request.json predecessor_packet.json predecessor_verification.json a1_policy_envelope.json a1_verification_request.json a1_receipt.json custody_attestation.json a2_verification_request.json a2_receipt.json revocation_snapshot.json a3_verification_request.json a3_receipt.json time_witness_receipt.json a4_verification_request.json a4_receipt.json operator_decision_policy.json operator_decision_request.json operator_decision_envelope.json verification_request.json receipt.json evidence_manifest.json',
    '  + [ODCV-006] rehash evidence bytes before typed admission; replay A4 using its unchanged verifier thereby replaying A1 A2 A3 and packet; compare every supplied predecessor receipt exactly',
    '  + [ODCV-007] select exactly ordinal five live_decision operator_decision_envelope_candidate live-operator-decision-verifier/0.1 public_metadata dependency ordinal four',
    '  + [ODCV-008] raw legacy envelope byte count SHA256 candidate UUID descriptor digest origin confidentiality profile fixture and dependency agree across A5 request and descriptor before envelope parsing',
    '  + [ODCV-009] compile current packet twice byte-identically; only A5 descriptor may differ from the replayed A4 packet request; every other descriptor and normalized request remains unchanged',
    '  + [ODCV-010] legacy policy UUID principal role and subject equal A1 policy identity; branch canonical remote project conversation purpose and embedded fixed proposal retain unchanged legacy checks',
    '  + [ODCV-011] decode and compare exact A1 and legacy public-key bytes; recompute each fingerprint in its own existing domain and never demand equality of fingerprints across distinct domains',
    '  + [ODCV-012] legacy policy_governance_artifact_sha256 equals exact A1 raw envelope SHA256 and revocation_list_artifact_sha256 equals exact A3 raw snapshot SHA256, excluding evidence transport LF; never resolve policy_governance_ref',
    '  + [ODCV-013] bind expected_policy_revision_uuid to replayed A1 revision and receipt; legacy policy has no revision field so this is chain association and not an invented standalone signed legacy field',
    '  + [ODCV-014] run unchanged verify_b1_cdrive_operator_decision against explicit policy request and raw envelope; reconstruct its verification rather than accepting an extra supplied verification',
    '  + [ODCV-015] preserve strict Ed25519 signature input as legacy constant domain then NUL then complete canonical payload including checked payload digest; no new signing API or signature algorithm',
    '  + [ODCV-016] decision UUID kind and external_decision_identity equal explicit request expectations; Authorize maps to A1 permitted authorize_once and Reject maps to permitted reject',
    '  + [ODCV-017] legacy decision issuance is strictly less than expiry; compare supplied A4 observed time with half-open decision interval using direct u64 comparisons and no arithmetic overflow',
    '  + [ODCV-018] before_decision_interval iff observed < issued; within_decision_interval iff issued <= observed < expires; after_decision_interval iff observed >= expires; issuance equality is within and expiry equality is after',
    '  + [ODCV-019] both Authorize and Reject support all three descriptive outcomes; preserve supplied A3 status assertion without treating it as operative revocation or suppressing adverse input',
    '  + [ODCV-020] existing decision signature does not bind A4 witness or receipt; explicit request association and interval comparison leave decision_signature_binds_a4_lineage false in every result',
    '  + [ODCV-021] request binds exact governance publications all predecessor identities current packet legacy policy request raw envelope expected decision and revision references one attempt zero retries zero cleanup and self digest',
    '  + [ODCV-022] receipt status is operator_decision_chain_and_supplied_interval_correspondence_verified_live_authorization_and_execution_unresolved and authority is supplied_operator_decision_chain_correspondence_only',
    '  + [ODCV-023] receipt includes exactly fifteen positive correspondence fields thirty-three conserved false authority and signature-coverage fields complete twenty-two-field zero effect account comparison inputs outcomes raw and semantic digests and inherited status',
    '  + [ODCV-024] new request receipt and evidence digest domains are cantor.b1.operator-decision-chain.request.v1 cantor.b1.operator-decision-chain.receipt.v1 cantor.b1.operator-decision-chain.evidence-manifest.v1 each followed by NUL and canonical form with only own digest replaced by SHA256 empty bytes',
    '  + [ODCV-025] strict compact UTF-8 typed declaration order refuses unknown duplicate reordered alternate escaping BOM CRLF whitespace concatenated trailing malformed oversized or overdeep forms; retained files carry exactly one LF',
    '  + [ODCV-026] manifest hashes twenty ordered payload artifacts using exact path bytes SHA256 and checked total; canonical manifest and complete receipt are reconstructed and compared rather than trusted',
    '  + [ODCV-027] independent verifier replays the full chain and legacy decision twice byte-identically without producer import; nineteen-input CLI and twenty-one-file directory CLI write only stdout; at least two fresh processes reproduce retained receipt bytes',
    '  + [ODCV-028] typed atomic refusals cover path profile size shape identity lineage coordinate dependency predecessor raw bytes digest key policy expectation decision interval signature receipt truth effect evidence arithmetic machine form and restart discrepancies',
    '  + [ODCV-029] production has no unsafe signing private-key reference-resolution clock environment service process network provider model MCP Git workspace writer broker persistence activation cleanup remote or physical capability; only explicit bounded supplied file reads',
    '  + [ODCV-030] primary research separates signature coverage application domain separation trust decisions and expiration endpoints; no Ed25519ctx Ed25519ph JWT JOSE RFC3161 OCSP or live-time interoperability is claimed',
    '  + [ODCV-031] immutable source full SJS formation safe Rust fixtures provider-independent proof exact gates publication and foreign ownership remain distinct; no frozen source formation upstream implementation or legacy signing changes'
)
$expectedAcceptance = @(
    '  + [ODCV-A01] source audit research requirements constraints delineation constructive and adversarial review ordered data design threats sevenfold canonical explosion justification solution plan matrix lock proof readiness signature manifest and independent dual-host formation gates agree',
    '  + [ODCV-A02] safe Rust uses existing dependencies unchanged A1 through A4 and legacy verification with explicit policy key raw-artifact revision decision expectation and unsigned-A4-context bindings',
    '  + [ODCV-A03] focused debug and overflow release cover both classes both decision kinds all three outcomes interval endpoints u64 extremes every field and adversarial evidence and fresh-process replay',
    '  + [ODCV-A04] exact locked-offline serialized workspace debug overflow release separate documentation tests warnings-denied workspace and five experiment Clippy format dual-host script formation evidence attribution non-force publication direct remote equality and post-push replay pass',
    '  + [ODCV-A05] all signer policy key-custody revocation time freshness replay-prevention live-decision observation permit broker physical provider and effect authorities remain separately governed and unproved'
)
$expectedAccount = [ordered]@{
    formation_artifact_count = 21
    signature_bound_artifact_count = 20
    invalid_reference_count = 0
    requirement_count = 31
    acceptance_gate_count = 5
    new_profile_count = 3
    imported_legacy_type_count = 5
    input_class_count = 2
    decision_kind_count = 2
    evidence_file_count = 21
    explicit_input_count = 19
    comparison_outcome_count = 3
    selected_coordinate = 5
    dependency_coordinate = 4
    downstream_authority_count = 4
    positive_correspondence_field_count = 15
    false_authority_field_count = 33
    effect_account_field_count = 22
    maximum_form_bytes = 1048576
    maximum_evidence_bytes = 16777216
    maximum_depth = 32
    maximum_fields = 4096
    maximum_text_bytes = 8192
    maximum_evidence_references = 48
    maximum_attempts = 1
    retry_count = 0
    cleanup_count = 0
    production_authority_claimed = $false
    challenge_freshness_proved = $false
    replay_prevention_proved = $false
    custodian_identity_proved = $false
    protected_storage_proved = $false
    private_key_nonexportability_proved = $false
    exclusive_control_proved = $false
    current_possession_proved = $false
    responder_identity_proved = $false
    responder_authority_proved = $false
    source_completeness_proved = $false
    monotonic_history_proved = $false
    snapshot_freshness_proved = $false
    current_time_compared = $false
    policy_governance_proved = $false
    key_custody_proved = $false
    revocation_truth_proved = $false
    current_nonexpired = $false
    live_authorization_admitted = $false
    fresh_observation_proved = $false
    private_execution_permit_present = $false
    production_broker_projection_present = $false
    physical_preparation_authorized = $false
    ready_for_physical_execution = $false
    execution_authorized = $false
    witness_identity_proved = $false
    witness_authority_proved = $false
    witness_freshness_proved = $false
    trusted_current_time_proved = $false
    decision_signer_identity_proved = $false
    decision_authority_proved = $false
    decision_freshness_proved = $false
    decision_signature_binds_a4_lineage = $false
    implementation_authorized = $true
    formation_effect_count = 0
}

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Read-Plain([string]$Relative) {
    $full = [IO.Path]::GetFullPath((Join-Path $root $Relative))
    Assert-Exact ($full.StartsWith($root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) 'artifact escapes root'
    $item = Get-Item -LiteralPath $full -Force
    Assert-Exact (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) "not a direct regular file: $Relative"
    Assert-Exact ($item.Length -gt 0 -and $item.Length -le 1048576) "artifact size differs: $Relative"
    $parent = $item.Directory
    while ($null -ne $parent -and $parent.FullName.Length -ge $root.TrimEnd([IO.Path]::DirectorySeparatorChar).Length) {
        Assert-Exact (-not ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) "link parent: $Relative"
        $parent = $parent.Parent
    }
    return [IO.File]::ReadAllText($full, [Text.UTF8Encoding]::new($false, $true))
}
function Assert-Properties($Value, [string[]]$Names, [string]$Label) {
    Assert-Exact (($Value.PSObject.Properties.Name -join '|') -ceq ($Names -join '|')) "$Label field set or order differs"
}
function Assert-Value($Actual, $Expected, [string]$Label) {
    if ($Expected -is [bool]) { Assert-Exact (($Actual -is [bool]) -and $Actual -eq $Expected) "$Label boolean differs" }
    elseif ($Expected -is [string]) { Assert-Exact (($Actual -is [string]) -and $Actual -ceq $Expected) "$Label text differs" }
    else { Assert-Exact (($Actual -is [int] -or $Actual -is [long]) -and $Actual -eq $Expected) "$Label integer differs" }
}


$rawManifest = Read-Plain $manifestRelative
Assert-Exact ($rawManifest.EndsWith("`n") -and -not $rawManifest.Contains("`r")) 'manifest framing differs'
$manifest = $rawManifest | ConvertFrom-Json
Assert-Exact ($rawManifest -ceq (($manifest | ConvertTo-Json -Depth 50 -Compress) + "`n")) 'manifest is not canonical; duplicate alternate or trailing JSON rejected'
Assert-Properties $manifest @('profile','manifest_uuid','source_snapshot_uuid','canonical_uuid','signature_uuid','source_custody_commit','file_ref_count','artifacts','verification') 'manifest'
Assert-Value $manifest.profile 'cantor-b1-operator-decision-chain-verification-formation-evidence/0.1' 'manifest profile'
Assert-Value $manifest.manifest_uuid 'd2919bb8-4c56-44c9-8d7e-bfa893e1235c' 'manifest manifest_uuid'
Assert-Value $manifest.source_snapshot_uuid 'dc4d390b-953b-415f-9fd9-2bd6f4838e19' 'manifest source_snapshot_uuid'
Assert-Value $manifest.canonical_uuid 'ee06ff6d-ba10-4a02-a157-9533d734912e' 'manifest canonical_uuid'
Assert-Value $manifest.signature_uuid 'b40dd6f3-9adc-4bd4-b87d-154e92668106' 'manifest signature_uuid'
Assert-Value $manifest.source_custody_commit 'a2bcb61130c60244a1bc6ba98a00a652c657ed40' 'manifest source_custody_commit'
Assert-Value $manifest.file_ref_count 21 'file ref count'
Assert-Exact (@($manifest.artifacts).Count -eq 21 -and ($manifest.artifacts.path -join '|') -ceq ($expectedPaths -join '|')) 'artifact path membership or order differs'
foreach ($artifact in $manifest.artifacts) {
    Assert-Properties $artifact @('path','bytes','sha256') 'artifact'
    $null = Read-Plain $artifact.path
    $full = Join-Path $root $artifact.path
    Assert-Value $artifact.bytes (Get-Item -LiteralPath $full).Length 'artifact bytes'
    Assert-Value $artifact.sha256 (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash 'artifact SHA256'
}
Assert-Value (Get-FileHash -LiteralPath (Join-Path $root $expectedPaths[0]) -Algorithm SHA256).Hash '4C697593888AD83D22BC7B0E7A53C0F5D3EF37B605EAE396C2791A84DB27313C' 'pinned source digest'
$signature = Read-Plain $expectedPaths[-1]
$bindings = @([regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\r?$'))
Assert-Exact ($bindings.Count -eq 20 -and (($bindings | ForEach-Object { $_.Groups[1].Value }) -join '|') -ceq (($expectedPaths | Select-Object -First 20) -join '|')) 'signature binding set differs'
foreach ($binding in $bindings) { Assert-Value $binding.Groups[2].Value (Get-FileHash -LiteralPath (Join-Path $root $binding.Groups[1].Value) -Algorithm SHA256).Hash 'signature artifact identity' }
foreach ($marker in @('b40dd6f3-9adc-4bd4-b87d-154e92668106','ee06ff6d-ba10-4a02-a157-9533d734912e','ad10f10f-d506-48ef-a805-f8b0a133766c','valid_for_bounded_formation','execution_authorized_false','decision_signature_binds_a4_lineage_false')) { Assert-Exact ($signature.Contains($marker)) "signature marker absent: $marker" }
$specification = Read-Plain 'specifications/Cantor_B1_Operator_Decision_Chain_Verification_P0.sop'
$requirements = @([regex]::Matches($specification, '(?m)^  \+ \[ODCV-\d{3}\] [^\r\n]+') | ForEach-Object { $_.Value })
$acceptance = @([regex]::Matches($specification, '(?m)^  \+ \[ODCV-A\d{2}\] [^\r\n]+') | ForEach-Object { $_.Value })
Assert-Exact (($requirements -join "`n") -ceq ($expectedRequirements -join "`n")) 'exact requirement semantics differ'
Assert-Exact (($acceptance -join "`n") -ceq ($expectedAcceptance -join "`n")) 'exact acceptance semantics differ'
Assert-Exact ($specification.Contains('  + positive correspondence fields are exactly packet_replayed a1_correspondence_receipt_verified a2_correspondence_receipt_verified a3_correspondence_receipt_verified a4_correspondence_receipt_verified a5_candidate_bytes_matched descriptor_correspondence_verified subject_lineage_correspondence_verified decision_policy_key_correspondence_verified decision_policy_artifact_bindings_verified decision_request_correspondence_verified decision_structure_verified decision_signature_correspondence_verified decision_expectations_verified supplied_decision_interval_comparison_verified')) 'positive correspondence field set differs'
Assert-Exact ($specification.Contains('  + conserved false fields are exactly production_authority_claimed challenge_freshness_proved replay_prevention_proved custodian_identity_proved protected_storage_proved private_key_nonexportability_proved exclusive_control_proved current_possession_proved responder_identity_proved responder_authority_proved source_completeness_proved monotonic_history_proved snapshot_freshness_proved current_time_compared policy_governance_proved key_custody_proved revocation_truth_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved decision_signer_identity_proved decision_authority_proved decision_freshness_proved decision_signature_binds_a4_lineage')) 'conserved false field set differs'
Assert-Exact ($specification.Contains('  + zero effect fields are exactly reference_resolution_count private_key_read_count signing_count revocation_service_contact_count witness_service_contact_count clock_read_count environment_read_count host_observation_count process_count provider_trial_count model_turn_count mcp_call_count network_contact_count broker_invocation_count writer_run_count filesystem_mutation_count git_mutation_count persistence_count activation_count cleanup_count remote_hardware_contact_count physical_contact')) 'zero effect field set differs'
$design = Read-Plain 'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Data_Design_2026-09-03.sop'
Assert-Exact ($design.Contains('  + exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a4_implementation_commit a4_bookend_commit a4_proof_uuid legacy_implementation_commit legacy_bookend_commit legacy_proof_uuid predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 a4_time_witness_receipt_raw_sha256 a4_verification_request_sha256 a4_receipt_sha256 authority_packet_request authority_packet_request_sha256 authority_packet_sha256 a5_candidate_uuid a5_descriptor_sha256 operator_decision_policy_sha256 operator_decision_request_sha256 operator_decision_envelope_bytes operator_decision_envelope_raw_sha256 expected_policy_revision_uuid expected_decision_uuid expected_decision_kind expected_external_decision_identity input_class evidence_references maximum_attempts automatic_retry_count automatic_cleanup_count request_sha256')) 'request ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are profile status authority source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a4_implementation_commit a4_bookend_commit a4_proof_uuid legacy_implementation_commit legacy_bookend_commit legacy_proof_uuid predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 a4_time_witness_receipt_raw_sha256 a4_verification_request_sha256 a4_receipt_sha256 authority_packet_request_sha256 authority_packet_sha256 request_sha256 a5_candidate_uuid a5_descriptor_sha256 operator_decision_policy_sha256 operator_decision_request_sha256 operator_decision_envelope_bytes operator_decision_envelope_raw_sha256 policy_uuid policy_revision_uuid principal role subject target_policy_key_fingerprint_sha256 legacy_policy_key_fingerprint_sha256 decision_uuid decision_kind external_decision_identity observed_unix_ms issued_at_unix_millis expires_at_unix_millis comparison_outcome supplied_a3_status_assertion payload_sha256 envelope_sha256 signature_sha256 legacy_verification_sha256 input_class fixture_only maximum_attempts automatic_retry_count automatic_cleanup_count packet_replayed a1_correspondence_receipt_verified a2_correspondence_receipt_verified a3_correspondence_receipt_verified a4_correspondence_receipt_verified a5_candidate_bytes_matched descriptor_correspondence_verified subject_lineage_correspondence_verified decision_policy_key_correspondence_verified decision_policy_artifact_bindings_verified decision_request_correspondence_verified decision_structure_verified decision_signature_correspondence_verified decision_expectations_verified supplied_decision_interval_comparison_verified production_authority_claimed challenge_freshness_proved replay_prevention_proved custodian_identity_proved protected_storage_proved private_key_nonexportability_proved exclusive_control_proved current_possession_proved responder_identity_proved responder_authority_proved source_completeness_proved monotonic_history_proved snapshot_freshness_proved current_time_compared policy_governance_proved key_custody_proved revocation_truth_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved decision_signer_identity_proved decision_authority_proved decision_freshness_proved decision_signature_binds_a4_lineage effect_account receipt_sha256')) 'receipt ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are reference_resolution_count private_key_read_count signing_count revocation_service_contact_count witness_service_contact_count clock_read_count environment_read_count host_observation_count process_count provider_trial_count model_turn_count mcp_call_count network_contact_count broker_invocation_count writer_run_count filesystem_mutation_count git_mutation_count persistence_count activation_count cleanup_count remote_hardware_contact_count physical_contact')) 'effects ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are profile manifest_uuid fixture_only artifacts artifact_count total_artifact_bytes retained_authority_packet_sha256 retained_a1_receipt_sha256 retained_a2_receipt_sha256 retained_a3_receipt_sha256 retained_a4_receipt_sha256 retained_legacy_verification_sha256 retained_receipt_sha256 deterministic_replay_count required_fresh_process_replay_count byte_identical effect_count manifest_sha256')) 'manifest ordered data shape differs'
Assert-Exact ($design.Contains('  + imported exact ordered fields are profile policy_uuid principal role subject verifying_key_hex key_fingerprint_sha256 policy_governance_ref policy_governance_artifact_sha256 revocation_list_artifact_sha256 fixture_only policy_sha256')) 'B1CDriveOperatorDecisionPolicy imported shape differs'
Assert-Exact ($design.Contains('  + imported exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit proposal_implementation_commit proposal_bookend_commit expected_current_commit branch canonical_remote working_project proposal_machine_form proposal_bytes proposal_raw_sha256 proposal_uuid proposal_self_sha256 policy_sha256 request_sha256')) 'B1CDriveOperatorDecisionRequest imported shape differs'
Assert-Exact ($design.Contains('  + imported exact ordered fields are profile decision_uuid request_sha256 policy_sha256 decision_kind principal role subject purpose conversation_uuid external_decision_identity issued_at_unix_millis expires_at_unix_millis maximum_attempts retry_count automatic_cleanup_count fixture_only payload_sha256')) 'B1CDriveOperatorDecisionPayload imported shape differs'
Assert-Exact ($design.Contains('  + imported exact ordered fields are profile payload signature_hex fixture_only envelope_sha256')) 'B1CDriveOperatorDecisionEnvelope imported shape differs'
Assert-Exact ($design.Contains('  + imported exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit proposal_implementation_commit proposal_bookend_commit proposal_uuid proposal_self_sha256 proposal_raw_sha256 policy_uuid policy_sha256 request_sha256 decision_uuid payload_sha256 envelope_sha256 decision_kind status authority proposal_correspondence_verified cryptographic_signature_verified fixture_only policy_governance_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present physical_preparation_authorized production_broker_projection_present effect_account verification_sha256')) 'B1CDriveOperatorDecisionVerification imported shape differs'
Assert-Properties $manifest.verification @($expectedAccount.Keys) 'verification'
foreach ($key in $expectedAccount.Keys) { Assert-Value $manifest.verification.$key $expectedAccount[$key] "verification.$key" }
foreach ($commit in @('a2bcb61130c60244a1bc6ba98a00a652c657ed40','91a80ea053e70fe073c8cd2257e5dc7fe5a2b97e','bc212c53a62cf99a3ff0c27544be5e5f4d6cf46e','9aaaab269836b8265c74ac9c46c690493c9fe746')) {
    git -C $scriptRepository cat-file -e ($commit + '^{commit}')
    Assert-Exact ($LASTEXITCODE -eq 0) 'required publication commit absent'
}
Write-Output 'b1_operator_decision_chain_formation_passed artifacts=21 bindings=20 requirements=31 acceptance=5 new_profiles=3 imported_types=5 inputs=2 kinds=2 files=21 explicit_inputs=19 outcomes=3 selected_A5=1 dependency_A4=1 downstream=4 positive=15 false_authority=33 effects=22 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false signed_a4_context=false formation_effects=0'
