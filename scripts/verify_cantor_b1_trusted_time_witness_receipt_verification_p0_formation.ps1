[CmdletBinding()]
param([string]$RepositoryRoot)

# Read-only source-bound formation verification; alternate roots are for isolated adversarial copies.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 has not initialized PSScriptRoot during default-parameter evaluation.
if ([string]::IsNullOrEmpty($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$scriptRepository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestRelative = 'experiments/b1_trusted_time_witness_receipt_verification_p0/formation_evidence_manifest.json'
$expectedPaths = @(
    'source_documents/2026-09-03_b1_trusted_time_witness_receipt_verification_p0/Derived_B1_Trusted_Time_Witness_Receipt_Verification_P0_Source.sop',
    'source_documents/2026-09-03_b1_trusted_time_witness_receipt_verification_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Input_Audit_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Requirements_Analysis_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Constraint_Ledger_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Delineation_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Dual_Hemisphere_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Data_Design_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Threat_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Seven_Fold_Exhaustion_2026-09-03.sop',
    'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Primary_Research_2026-09-03.sop',
    'specifications/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0.sop',
    'specifications/exploded/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0.exploded.sop',
    'justifications/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Justification.sop',
    'solutions/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Solution.sop',
    'plans/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Plan.sop',
    'feature_support/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorB1TrustedTimeWitnessReceiptVerificationP0ReadinessReview.sop',
    'narrative/registries/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Satisfaction_Signature.sop'
)
$expectedRequirements = @(
    '  + [TWV-001] bind source snapshot 3f33fd16-abed-4838-9272-bc3f44aaff54 source-custody commit 8fc0fe68dd706a13ff57cf7beb32e35e7be6ba56 A3 canonical aeb226ac-3c59-4b9b-a81e-d59f285f5a2d implementation 508ddddaedee96d97f393244692b17801394f01c bookend cb1c608a50bfaad24281c34278ee8fdda2f30f8b and proof ccecea62-9e48-42ef-ba5b-adadd240ae18',
    '  + [TWV-002] profiles are exactly cantor-b1-trusted-time-witness-receipt/0.1 cantor-b1-trusted-time-witness-verification-request/0.1 cantor-b1-trusted-time-witness-verification-receipt/0.1 cantor-b1-trusted-time-witness-verification-evidence/0.1',
    '  + [TWV-003] maximum form and raw witness bytes 1048576 total evidence bytes 16777216 JSON depth 32 fields 4096 text bytes 8192 evidence references one through forty-eight and bounded checked arithmetic',
    '  + [TWV-004] input class is exactly deterministic_fixture_candidate or externally_supplied_candidate and matches A4 origin and fixture marker; external input is not authority',
    '  + [TWV-005] evidence membership is exactly sixteen direct regular nonlink files in this order: predecessor_request.json predecessor_packet.json predecessor_verification.json a1_policy_envelope.json a1_verification_request.json a1_receipt.json custody_attestation.json a2_verification_request.json a2_receipt.json revocation_snapshot.json a3_verification_request.json a3_receipt.json time_witness_receipt.json verification_request.json receipt.json evidence_manifest.json',
    '  + [TWV-006] rehash raw evidence before typed admission; replay predecessor packet A1 A2 and A3 using their existing verifiers and compare every predecessor receipt exactly',
    '  + [TWV-007] select exactly ordinal four current_time trusted_time_witness_receipt_candidate trusted-time-witness-verifier/0.1 public_metadata dependency ordinal three; no other coordinate is selectable',
    '  + [TWV-008] raw witness byte count SHA256 candidate UUID descriptor digest origin confidentiality profile and fixture flag agree across current packet request and candidate before semantic admission',
    '  + [TWV-009] compile current authority packet twice byte-identically; only A4 descriptor may differ from exact A3 current packet; all other descriptors and normalized packet request remain unchanged',
    '  + [TWV-010] candidate binds exact subject cantor_b1_cdrive_production_preparation_p0 branch codex/self-hosted-corpus remote https://github.com/cattailfarmer/Cantor policy UUID revision A1 A2 A3 receipt identities A3 packet snapshot raw and semantic digests and target policy-key fingerprint',
    '  + [TWV-011] witness UUID authority label public key fingerprint and positive u64 sequence equal explicit request expectations; key and label are supplied correspondence pins not trusted identity',
    '  + [TWV-012] witness key fingerprint is SHA256 of exactly thirty-two decoded Ed25519 public-key bytes and equals the separately supplied expected key; substituted key with otherwise valid signature refuses against the unchanged request',
    '  + [TWV-013] witness payload signing context is exactly cantor-b1-time-witness-signature/0.1; strict detached Ed25519 verification covers compact canonical fields with signature_hex and witness_sha256 excluded, with fixed domain separation',
    '  + [TWV-014] issued_at_unix_ms <= observed_unix_ms <= expires_at_unix_ms under u64 comparison; equality is allowed; positive sequence required; no ambient clock or freshness assertion',
    '  + [TWV-015] derive before_snapshot_interval iff observed < this_update; within_snapshot_interval iff this_update <= observed <= next_update; after_snapshot_interval iff observed > next_update; A3 interval comes only from replayed A3 receipt',
    '  + [TWV-016] candidate lineage binds A3 packet rather than the current A4 packet to avoid a self-referential raw digest cycle; request binds the resulting A4 packet and witness bytes',
    '  + [TWV-017] request binds governance publications predecessor digests raw witnesses explicit expectations evidence references one attempt zero retries zero cleanup and self-excluding domain-separated digest',
    '  + [TWV-018] receipt status is time_witness_signature_and_supplied_interval_correspondence_verified_current_time_and_all_execution_authority_unresolved and authority is supplied_time_witness_correspondence_only',
    '  + [TWV-019] receipt exposes exactly twelve positive correspondence fields and one descriptive comparison outcome with comparison inputs, raw witness identity, signature digest and request digest',
    '  + [TWV-020] twenty-nine named authority fields including production_authority_claimed remain false in candidate admission or resulting receipt as applicable; before within and after never promote authority',
    '  + [TWV-021] UTF-8 compact canonical typed forms refuse unknown duplicate noncanonical BOM CRLF whitespace concatenated trailing malformed and oversized inputs; direct files carry exactly one LF terminator',
    '  + [TWV-022] manifest binds ordered fifteen payload artifacts by direct-child path raw bytes SHA256 checked count and total; reconstructed evidence account is compared rather than trusted',
    '  + [TWV-023] independent evidence verifier replays packet A1 A2 A3 A4 twice byte-identically; at least two fresh processes reproduce exact retained receipt bytes; no producer import into verifier',
    '  + [TWV-024] typed atomic refusals cover path profile size shape identity lineage coordinate dependency raw bytes digest key expectation sequence interval signature receipt truth effect evidence arithmetic and restart discrepancies',
    '  + [TWV-025] production modules have no unsafe signing private-key clock environment service discovery process network model provider MCP Git workspace write broker persistence activation cleanup remote or physical capability; only explicit supplied file reads are admitted',
    '  + [TWV-026] primary research distinguishes timestamp syntax signature correspondence time-source authorization freshness delay uncertainty rollback and relying-party currentness; no RFC 3161 OCSP or NTS interoperability claim',
    '  + [TWV-027] source formation implementation fixture authority proof publication and foreign ownership remain separate; no frozen formation artifact changes after publication; closure records carry implementation results'
)
$expectedAcceptance = @(
    '  + [TWV-A01] source audit primary research requirements constraints delineation dual review data design threats seven-fold canonical explosion justification solution plan matrix lock proof readiness signature manifest and independent formation tests agree exactly',
    '  + [TWV-A02] safe Rust uses existing dependencies for strict forms A3 replay raw A4 admission expectations signatures supplied interval comparison receipts evidence and two bounded CLIs',
    '  + [TWV-A03] focused debug and overflow-checked release cover both input classes all three outcomes both exact endpoints u64 extremes and every named adversary; exact sixteen-file evidence independently replays across fresh processes',
    '  + [TWV-A04] locked offline serialized exact workspace debug and overflow-checked release warnings-denied Clippy format dual-host formation parsing evidence attribution non-force publication remote equality and post-push replay pass',
    '  + [TWV-A05] witness identity authority service contact clock correctness accuracy synchronization freshness rollback replay prevention current-time truth operative revocation downstream authorization provider and all effects remain separately governed and locked'
)
$expectedAccount = [ordered]@{
    formation_artifact_count = 21
    signature_bound_artifact_count = 20
    invalid_reference_count = 0
    requirement_count = 27
    acceptance_gate_count = 5
    profile_count = 4
    input_class_count = 2
    evidence_file_count = 16
    comparison_outcome_count = 3
    selected_coordinate = 4
    dependency_coordinate = 3
    downstream_authority_count = 5
    positive_correspondence_field_count = 12
    false_authority_field_count = 29
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
$canonicalManifest = ($manifest | ConvertTo-Json -Depth 50 -Compress) + "`n"
Assert-Exact ($rawManifest -ceq $canonicalManifest) 'manifest is not canonical; duplicate alternate or trailing JSON rejected'
Assert-Properties $manifest @('profile','manifest_uuid','source_snapshot_uuid','canonical_uuid','signature_uuid','source_custody_commit','file_ref_count','artifacts','verification') 'manifest'
Assert-Value $manifest.profile 'cantor-b1-trusted-time-witness-receipt-verification-formation-evidence/0.1' 'manifest profile'
Assert-Value $manifest.manifest_uuid '58e9ede2-fce4-4fa7-b29f-675bd2b20be7' 'manifest UUID'
Assert-Value $manifest.source_snapshot_uuid '3f33fd16-abed-4838-9272-bc3f44aaff54' 'source snapshot'
Assert-Value $manifest.canonical_uuid 'd4bbec0d-b308-4e83-ad80-29cdb61424eb' 'canonical UUID'
Assert-Value $manifest.signature_uuid '2e058f81-3eab-49e2-89aa-c677552191a0' 'signature UUID'
Assert-Value $manifest.source_custody_commit '8fc0fe68dd706a13ff57cf7beb32e35e7be6ba56' 'source custody'
Assert-Value $manifest.file_ref_count 21 'file ref count'
Assert-Exact (@($manifest.artifacts).Count -eq 21 -and ($manifest.artifacts.path -join '|') -ceq ($expectedPaths -join '|')) 'artifact path membership or order differs'
foreach ($artifact in $manifest.artifacts) {
    Assert-Properties $artifact @('path','bytes','sha256') 'artifact'
    $null = Read-Plain $artifact.path
    $full = Join-Path $root $artifact.path
    Assert-Value $artifact.bytes (Get-Item -LiteralPath $full).Length 'artifact bytes'
    Assert-Value $artifact.sha256 (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash 'artifact SHA256'
}
Assert-Value (Get-FileHash -LiteralPath (Join-Path $root $expectedPaths[0]) -Algorithm SHA256).Hash '0F1536E9D44DF045CD0983B552F373CEE152F328BC5D460627BF5890FC3ABD0F' 'pinned source digest'
$signature = Read-Plain $expectedPaths[-1]
$bindings = @([regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\r?$'))
Assert-Exact ($bindings.Count -eq 20 -and (($bindings | ForEach-Object { $_.Groups[1].Value }) -join '|') -ceq (($expectedPaths | Select-Object -First 20) -join '|')) 'signature binding set differs'
foreach ($binding in $bindings) {
    Assert-Value $binding.Groups[2].Value (Get-FileHash -LiteralPath (Join-Path $root $binding.Groups[1].Value) -Algorithm SHA256).Hash 'signature artifact identity'
}
foreach ($marker in @('2e058f81-3eab-49e2-89aa-c677552191a0', 'd4bbec0d-b308-4e83-ad80-29cdb61424eb', 'ad10f10f-d506-48ef-a805-f8b0a133766c', 'valid_for_bounded_formation', 'execution_authorized_false')) {
    Assert-Exact ($signature.Contains($marker)) "signature marker absent: $marker"
}
$specification = Read-Plain 'specifications/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0.sop'
$requirements = @([regex]::Matches($specification, '(?m)^  \+ \[TWV-\d{3}\] [^\r\n]+') | ForEach-Object { $_.Value })
$acceptance = @([regex]::Matches($specification, '(?m)^  \+ \[TWV-A\d{2}\] [^\r\n]+') | ForEach-Object { $_.Value })
Assert-Exact (($requirements -join "`n") -ceq ($expectedRequirements -join "`n")) 'exact requirement semantics differ'
Assert-Exact (($acceptance -join "`n") -ceq ($expectedAcceptance -join "`n")) 'exact acceptance semantics differ'
Assert-Exact ($specification.Contains('  + positive correspondence fields are exactly packet_replayed a1_correspondence_receipt_verified a2_correspondence_receipt_verified a3_correspondence_receipt_verified a4_candidate_bytes_matched descriptor_correspondence_verified subject_lineage_correspondence_verified witness_key_correspondence_verified witness_structure_verified time_bounds_structure_verified witness_signature_correspondence_verified supplied_interval_comparison_verified')) 'positive field set differs'
Assert-Exact ($specification.Contains('  + conserved false fields are exactly production_authority_claimed challenge_freshness_proved replay_prevention_proved custodian_identity_proved protected_storage_proved private_key_nonexportability_proved exclusive_control_proved current_possession_proved responder_identity_proved responder_authority_proved source_completeness_proved monotonic_history_proved snapshot_freshness_proved current_time_compared policy_governance_proved key_custody_proved revocation_truth_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved')) 'false field set differs'
$design = Read-Plain 'narrative/research/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Data_Design_2026-09-03.sop'
Assert-Exact ($design.Contains('  + exact ordered fields are profile witness_uuid candidate_label authority_label subject branch canonical_remote policy_uuid policy_revision_uuid a1_receipt_sha256 a2_receipt_sha256 a3_receipt_sha256 a3_authority_packet_sha256 a3_snapshot_sha256 a3_snapshot_raw_sha256 a4_candidate_uuid target_policy_key_fingerprint_sha256 witness_verifying_key_hex witness_public_key_fingerprint_sha256 observed_unix_ms issued_at_unix_ms expires_at_unix_ms sequence signing_context signature_hex input_class fixture_only production_authority_claimed witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved witness_sha256')) 'ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a3_implementation_commit a3_bookend_commit a3_proof_uuid predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 authority_packet_request authority_packet_request_sha256 authority_packet_sha256 a4_candidate_uuid a4_descriptor_sha256 time_witness_receipt_bytes time_witness_receipt_raw_sha256 expected_witness_uuid expected_witness_authority_label expected_witness_verifying_key_hex expected_witness_public_key_fingerprint_sha256 expected_sequence input_class evidence_references maximum_attempts automatic_retry_count automatic_cleanup_count request_sha256')) 'ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are profile status authority source_snapshot_uuid canonical_uuid signature_uuid formation_commit formation_bookend_commit predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 authority_packet_request_sha256 authority_packet_sha256 request_sha256 a4_candidate_uuid a4_descriptor_sha256 time_witness_receipt_bytes time_witness_receipt_raw_sha256 witness_uuid authority_label policy_uuid policy_revision_uuid target_policy_key_fingerprint_sha256 witness_public_key_fingerprint_sha256 observed_unix_ms issued_at_unix_ms expires_at_unix_ms sequence a3_snapshot_sha256 this_update_unix_ms next_update_unix_ms comparison_outcome witness_sha256 signature_sha256 input_class fixture_only maximum_attempts automatic_retry_count automatic_cleanup_count packet_replayed a1_correspondence_receipt_verified a2_correspondence_receipt_verified a3_correspondence_receipt_verified a4_candidate_bytes_matched descriptor_correspondence_verified subject_lineage_correspondence_verified witness_key_correspondence_verified witness_structure_verified time_bounds_structure_verified witness_signature_correspondence_verified supplied_interval_comparison_verified production_authority_claimed challenge_freshness_proved replay_prevention_proved custodian_identity_proved protected_storage_proved private_key_nonexportability_proved exclusive_control_proved current_possession_proved responder_identity_proved responder_authority_proved source_completeness_proved monotonic_history_proved snapshot_freshness_proved current_time_compared policy_governance_proved key_custody_proved revocation_truth_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved effect_account receipt_sha256')) 'ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are reference_resolution_count private_key_read_count signing_count revocation_service_contact_count witness_service_contact_count clock_read_count environment_read_count host_observation_count process_count provider_trial_count model_turn_count mcp_call_count network_contact_count broker_invocation_count writer_run_count filesystem_mutation_count git_mutation_count persistence_count activation_count cleanup_count remote_hardware_contact_count physical_contact')) 'ordered data shape differs'
Assert-Exact ($design.Contains('  + exact ordered fields are profile manifest_uuid fixture_only artifacts artifact_count total_artifact_bytes retained_authority_packet_sha256 retained_a1_receipt_sha256 retained_a2_receipt_sha256 retained_a3_receipt_sha256 retained_receipt_sha256 deterministic_replay_count required_fresh_process_replay_count byte_identical effect_count manifest_sha256')) 'ordered data shape differs'
Assert-Properties $manifest.verification @($expectedAccount.Keys) 'verification'
foreach ($key in $expectedAccount.Keys) { Assert-Value $manifest.verification.$key $expectedAccount[$key] "verification.$key" }
git -C $scriptRepository cat-file -e '8fc0fe68dd706a13ff57cf7beb32e35e7be6ba56^{commit}'
Assert-Exact ($LASTEXITCODE -eq 0) 'source custody commit missing from repository'
Write-Output 'b1_trusted_time_witness_formation_passed artifacts=21 bindings=20 requirements=27 acceptance=5 profiles=4 inputs=2 files=16 outcomes=3 selected_A4=1 dependency_A3=1 downstream=5 positive=12 false_authority=29 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false formation_effects=0'
