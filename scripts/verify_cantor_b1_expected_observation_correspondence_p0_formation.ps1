[CmdletBinding()]
param([string]$RepositoryRoot)
# Read-only A6 formation verifier. Pinned source, requirements and shapes are independent of supplied hashes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$scriptRepository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestRelative = 'experiments/b1_expected_observation_correspondence_p0/formation_evidence_manifest.json'
$expectedPaths = @(
    'source_documents/2026-09-03_b1_expected_observation_correspondence_p0/Derived_B1_Expected_Observation_Correspondence_P0_Source.sop',
    'source_documents/2026-09-03_b1_expected_observation_correspondence_p0/Source_Document_Manifest.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Input_Audit_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Requirements_Analysis_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Constraint_Ledger_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Delineation_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Dual_Hemisphere_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Data_Design_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Threat_Review_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Seven_Fold_Exhaustion_2026-09-03.sop',
    'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Primary_Research_2026-09-03.sop',
    'specifications/Cantor_B1_Expected_Observation_Correspondence_P0.sop',
    'specifications/exploded/Cantor_B1_Expected_Observation_Correspondence_P0.exploded.sop',
    'justifications/Cantor_B1_Expected_Observation_Correspondence_P0_Justification.sop',
    'solutions/Cantor_B1_Expected_Observation_Correspondence_P0_Solution.sop',
    'plans/Cantor_B1_Expected_Observation_Correspondence_P0_Plan.sop',
    'feature_support/Cantor_B1_Expected_Observation_Correspondence_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_B1_Expected_Observation_Correspondence_P0_Artifact_Phase_Lock.sop',
    'proofs/Cantor_B1_Expected_Observation_Correspondence_P0_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorB1ExpectedObservationCorrespondenceP0ReadinessReview.sop',
    'narrative/registries/Cantor_B1_Expected_Observation_Correspondence_P0_Satisfaction_Signature.sop'
)
$expectedRequirements = @(
    '  + [EOCV-001] bind source snapshot d10dd69e-34d1-43db-ab46-109a11cc80e0 custody 4f1417d111911f0fd27437f13b480157332442b2 source bookend 23cc6c17667efefa88ca27a1af2d1e410a9ccd00 A5 implementation 9b3dd715439c26aa34181dace0e525681a1f29b9 bookend f72237acd50fdc296b7e47825a84200528f6c850 proof 498a8437-f165-4b57-ad07-b25f1c8c25ec plan implementation 2ae87673cfd343cc7a4685a5d0ebbdfc37256ea3 bookend 1b70fbd46a3bf6c1970d590ec6ec02ddc84d2cde proof eef4785a-3020-4cb5-82c3-e32b7a84882a',
    '  + [EOCV-002] four new profiles are exactly cantor-b1-expected-observation-bundle/0.1 cantor-b1-expected-observation-request/0.1 cantor-b1-expected-observation-receipt/0.1 cantor-b1-expected-observation-evidence/0.1; ordered shapes are bundle17 request34 receipt69 manifest16 and six imported contracts remain unchanged',
    '  + [EOCV-003] maximum form bytes 1048576 total evidence bytes 16777216 JSON depth32 aggregate fields4096 general text bytes8192 references1..48 unique nonempty opaque values; preserve all stricter imported limits and nested bounds',
    '  + [EOCV-004] input class is deterministic_fixture_candidate or externally_supplied_candidate and matches new A6 request bundle descriptor and fixture flag without forcing upstream classes equal',
    '  + [EOCV-005] evidence membership is exactly twenty-six direct regular nonlink files in this order: predecessor_request.json predecessor_packet.json predecessor_verification.json a1_policy_envelope.json a1_verification_request.json a1_receipt.json custody_attestation.json a2_verification_request.json a2_receipt.json revocation_snapshot.json a3_verification_request.json a3_receipt.json time_witness_receipt.json a4_verification_request.json a4_receipt.json operator_decision_policy.json operator_decision_request.json operator_decision_envelope.json a5_verification_request.json a5_receipt.json preparation_plan_request.json preparation_plan.json observation_bundle.json verification_request.json receipt.json evidence_manifest.json',
    '  + [EOCV-006] replay unchanged verify_odcv_operator_decision with all nineteen predecessor inputs and compare the entire supplied A5 receipt before A6 admission',
    '  + [EOCV-007] parse unchanged preparation plan request compile exact plan and compare supplied plan; its digest roles and operations equal the proposal inherited plan already signed and verified through A5; another valid namespace plan refuses',
    '  + [EOCV-008] preserve legacy decision expected_current_commit 98683316ff8735026dded1838c88e84edf7288f5 and plan expected_current_commit 49af9aa11db6696a95a13fead653c5edc1253f0d; new expected_carrier_commit is separate supplied lowercase forty-hex data with no signed expectation authority',
    '  + [EOCV-009] preserve old plan observed free bytes43004325888 and minimum15032385536; do not substitute new observations into the old plan or require new observed capacity to equal historical capacity',
    '  + [EOCV-010] select exactly ordinal six fresh_observation expected_current_observation_bundle_candidate expected-current-observation-verifier/0.1 public_metadata dependency ordinal five',
    '  + [EOCV-011] compile current packet twice byte-identically and permit only ordinal-six descriptor to differ from replayed A5 authority_packet_request; all other descriptor and subject bytes remain unchanged',
    '  + [EOCV-012] raw observation bundle byte count SHA256 candidate UUID descriptor digest origin confidentiality verifier fixture and dependency match before parsing bundle bytes',
    '  + [EOCV-013] bundle UUID matches expected_bundle_uuid and is distinct from source canonical signature and predecessor decision; bundle a5_receipt_sha256 and expected_carrier_commit equal replayed chain and request pins',
    '  + [EOCV-014] two junction observations retain exact plan source order and each source kind target; kind junction requires nonempty target string while missing other unknown require explicit null; wrong coordinates or conditional shapes refuse',
    '  + [EOCV-015] four upstream observations retain exact ordered unchanged role enum and valid digest shape; supplied profile or digest difference is a comparison mismatch while missing duplicate reordered or changed role refuses',
    '  + [EOCV-016] five role observations retain exact scratch candidate evidence lease ledger kinds and proposal-bound paths; reserved reference equals proposal proposed_ref; each presence state is absent present or unknown',
    '  + [EOCV-017] carrier commit compares to explicit new expected carrier and branch remote project compare exactly to unchanged legacy and plan strings; no latest-HEAD lookup alias normalization or .git suffix repair',
    '  + [EOCV-018] supplied observation_time_matches_a4 is exact u64 equality with replayed A5 observed_unix_ms; this proves neither current time nor atomic simultaneity freshness or collector identity',
    '  + [EOCV-019] capacity_meets_minimum uses direct u64 observed >= minimum comparison without arithmetic; zero below floor exact floor and u64 maximum remain representable',
    '  + [EOCV-020] build_junctions_match requires both junction kinds and exact expected target strings; upstream_identities_match requires exact profile and digest correspondence after role-coordinate admission',
    '  + [EOCV-021] all_roles_absent_asserted requires all five supplied states absent and reserved_ref_absent_asserted requires absent; present and unknown are valid mismatch observations and never reservations',
    '  + [EOCV-022] ten comparison flags are in fixed declared order; mismatch reasons enumerate exactly the false flags once in that order and all_expectations_match iff reasons empty and all flags true',
    '  + [EOCV-023] matched status supplied_observation_expectations_matched_freshness_and_execution_unresolved and mismatched status supplied_observation_expectations_mismatched_execution_unresolved both use supplied_observation_correspondence_only authority; valid adverse input emits a descriptive receipt not malformed refusal',
    '  + [EOCV-024] receipt nests exact unchanged113-field A5 receipt preserving its33 false authority fields22 zero effect fields rejection supplied A3 adverse status and all decision interval outcomes; coherent A6 rebinding remains unsigned context',
    '  + [EOCV-025] new receipt has seven positive correspondence fields fourteen global false authority fields complete22-field zero effect account one attempt zero retry zero cleanup and exact data-driven bindings',
    '  + [EOCV-026] bundle request receipt and evidence self-digests clear only own field to SHA256 empty bytes and hash their fixed respective cantor.b1.expected-observation.*.v1 domain followed by NUL and canonical typed form',
    '  + [EOCV-027] strict compact UTF-8 typed declaration order rejects unknown duplicate reordered alternate escaping BOM CRLF whitespace concatenated trailing malformed oversized or overdeep forms; retained files carry exactly one LF and raw candidate hashes exclude it',
    '  + [EOCV-028] manifest hashes twenty-five ordered payload artifacts before parsing with exact paths bytes SHA256 and checked total; reconstruct every retained digest and full nested receipt rather than trusting hashes or summary flags',
    '  + [EOCV-029] independent verifier replays A5 plan A6 twice without producer import; twenty-four-input CLI and twenty-six-file directory CLI output only canonical receipt plus LF; two fresh processes per debug/release profile reproduce exact bytes and rehashed false retained identity reaches Restart refusal',
    '  + [EOCV-030] typed atomic refusals distinguish malformed path profile size shape identity lineage coordinate dependency predecessor raw bytes digest plan bundle expectation receipt truth effect evidence arithmetic machine-form and restart discrepancies; well-formed mismatches are not faults',
    '  + [EOCV-031] pure production has no unsafe signer private-key resolver host-observation clock environment process network provider model MCP Git writer broker persistence activation cleanup remote or physical capability; bounded evidence reads only explicit inputs',
    '  + [EOCV-032] primary research informs strict struct/enum encoding and filesystem boundary without implying OS snapshot guarantees; no new protocol signature collector clock trust filesystem acquisition or interoperability claim',
    '  + [EOCV-033] immutable source full SJS formation safe Rust fixtures independent proof exact gates publication bookends and foreign ownership remain distinct; no frozen source formation predecessor implementation dependency or signature change'
)
$expectedAcceptance = @(
    '  + [EOCV-A01] complete source audit requirements constraints delineation constructive/adversarial review data design threats primary research sevenfold canonical/exploded justification solution plan matrix phase proof readiness signature manifest and independent dual-host formation agree',
    '  + [EOCV-A02] safe Rust replays complete unchanged A5 and signed proposal-bound plan then admits only raw A6 bundle and exact supplied comparison; historical pins and unsigned expectation boundary conserved',
    '  + [EOCV-A03] both input classes both decision kinds all A5 interval outcomes adverse A3 states all-match all-mismatch each mismatch and bounded combinations capacity endpoints every field strict bounds independent retained and fresh-process replay tested',
    '  + [EOCV-A04] exact locked-offline serialized workspace debug overflow release separate documentation workspace and five experiment warnings-denied Clippy format dual-host script formation evidence attribution non-force publication direct equality and post-push replay pass',
    '  + [EOCV-A05] all current host truth collector identity freshness atomicity signed A6 expectation real-world signer policy custody revocation time live authorization private permit broker projection and physical execution authorities remain unproved'
)
$expectedAccount = [ordered]@{
    formation_artifact_count = 21
    signature_bound_artifact_count = 20
    invalid_reference_count = 0
    requirement_count = 33
    acceptance_gate_count = 5
    new_profile_count = 4
    imported_type_count = 6
    input_class_count = 2
    decision_kind_count = 2
    evidence_file_count = 26
    explicit_input_count = 24
    comparison_field_count = 10
    mismatch_reason_count = 10
    status_count = 2
    selected_coordinate = 6
    dependency_coordinate = 5
    downstream_authority_count = 3
    bundle_field_count = 17
    request_field_count = 34
    receipt_field_count = 69
    manifest_field_count = 16
    positive_correspondence_field_count = 7
    global_false_authority_field_count = 14
    inherited_a5_false_authority_field_count = 33
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
    fresh_observation_proved = $false
    observation_source_identity_proved = $false
    observation_source_completeness_proved = $false
    observation_freshness_proved = $false
    atomic_observation_proved = $false
    decision_signature_binds_a6_observation = $false
    expected_carrier_authority_proved = $false
    live_authorization_admitted = $false
    private_execution_permit_present = $false
    production_broker_projection_present = $false
    physical_preparation_authorized = $false
    ready_for_physical_execution = $false
    execution_authorized = $false
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
Assert-Value $manifest.profile 'cantor-b1-expected-observation-correspondence-formation-evidence/0.1' 'manifest profile'
Assert-Value $manifest.manifest_uuid 'd3d96031-5f55-4db6-97b8-e98379fdfb9b' 'manifest UUID'
Assert-Value $manifest.source_snapshot_uuid 'd10dd69e-34d1-43db-ab46-109a11cc80e0' 'snapshot'
Assert-Value $manifest.canonical_uuid 'a992244a-31b1-4d0a-ad9e-39a1cc667c99' 'canonical'
Assert-Value $manifest.signature_uuid 'a4448ba3-5cc5-473f-a039-84b5347518ae' 'signature'
Assert-Value $manifest.source_custody_commit '4f1417d111911f0fd27437f13b480157332442b2' 'source commit'
Assert-Value $manifest.file_ref_count 21 'file reference count'
Assert-Exact (@($manifest.artifacts).Count -eq 21 -and ($manifest.artifacts.path -join '|') -ceq ($expectedPaths -join '|')) 'artifact membership or order differs'
foreach ($artifact in $manifest.artifacts) {
    Assert-Properties $artifact @('path','bytes','sha256') 'artifact'
    $null = Read-Plain $artifact.path
    $full = Join-Path $root $artifact.path
    Assert-Value $artifact.bytes (Get-Item -LiteralPath $full).Length 'artifact bytes'
    Assert-Value $artifact.sha256 (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash 'artifact SHA256'
}
Assert-Value (Get-FileHash -LiteralPath (Join-Path $root $expectedPaths[0]) -Algorithm SHA256).Hash '6DC3B8D95C0715E7E1CE00CFF5F2E148C4EC6C70D5A283407746CD4511A10805' 'pinned source digest'
$signature = Read-Plain $expectedPaths[-1]
$bindings = @([regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\r?$'))
Assert-Exact ($bindings.Count -eq 20 -and (($bindings | ForEach-Object { $_.Groups[1].Value }) -join '|') -ceq (($expectedPaths | Select-Object -First 20) -join '|')) 'signature binding set differs'
foreach ($binding in $bindings) { Assert-Value $binding.Groups[2].Value (Get-FileHash -LiteralPath (Join-Path $root $binding.Groups[1].Value) -Algorithm SHA256).Hash 'signature artifact identity' }
foreach ($marker in @('a4448ba3-5cc5-473f-a039-84b5347518ae','a992244a-31b1-4d0a-ad9e-39a1cc667c99','ad10f10f-d506-48ef-a805-f8b0a133766c','valid_for_bounded_formation','execution_authorized_false','decision_signature_binds_a6_observation_false','expected_carrier_authority_proved_false','fresh_observation_proved_false')) { Assert-Exact ($signature.Contains($marker)) "signature marker absent: $marker" }
$specification = Read-Plain 'specifications/Cantor_B1_Expected_Observation_Correspondence_P0.sop'
$requirements = @([regex]::Matches($specification, '(?m)^  \+ \[EOCV-\d{3}\] [^\r\n]+') | ForEach-Object { $_.Value })
$acceptance = @([regex]::Matches($specification, '(?m)^  \+ \[EOCV-A\d{2}\] [^\r\n]+') | ForEach-Object { $_.Value })
Assert-Exact (($requirements -join "`n") -ceq ($expectedRequirements -join "`n")) 'exact requirement semantics differ'
Assert-Exact (($acceptance -join "`n") -ceq ($expectedAcceptance -join "`n")) 'exact acceptance semantics differ'
Assert-Exact ($specification.Contains('  + positive correspondence fields are exactly a5_correspondence_receipt_verified preparation_plan_replayed proposal_plan_correspondence_verified packet_replayed descriptor_correspondence_verified observation_bundle_bytes_matched comparison_reconstructed')) 'positive correspondence set differs'
Assert-Exact ($specification.Contains('  + global false fields are exactly production_authority_claimed fresh_observation_proved observation_source_identity_proved observation_source_completeness_proved observation_freshness_proved atomic_observation_proved decision_signature_binds_a6_observation expected_carrier_authority_proved live_authorization_admitted private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized')) 'global false set differs'
Assert-Exact ($specification.Contains('  + zero effect fields are exactly reference_resolution_count private_key_read_count signing_count revocation_service_contact_count witness_service_contact_count clock_read_count environment_read_count host_observation_count process_count provider_trial_count model_turn_count mcp_call_count network_contact_count broker_invocation_count writer_run_count filesystem_mutation_count git_mutation_count persistence_count activation_count cleanup_count remote_hardware_contact_count physical_contact')) 'zero effect set differs'
$design = Read-Plain 'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Data_Design_2026-09-03.sop'
$bundleShape = [regex]::Match($design, '(?m)^& \[bundle\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($bundleShape.Success -and $bundleShape.Groups[1].Value -ceq '  + exact ordered fields are profile bundle_uuid a5_receipt_sha256 expected_carrier_commit observed_carrier_commit observed_branch observed_remote observed_project observed_unix_ms observed_cdrive_free_bytes build_junctions upstream_identities role_observations reserved_ref_observation input_class evidence_references bundle_sha256') 'bundle ordered shape differs'
$requestShape = [regex]::Match($design, '(?m)^& \[request\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($requestShape.Success -and $requestShape.Groups[1].Value -ceq '  + exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a5_implementation_commit a5_bookend_commit a5_proof_uuid plan_implementation_commit plan_bookend_commit plan_proof_uuid a5_verification_request_sha256 a5_receipt_sha256 preparation_plan_request_raw_sha256 preparation_plan_request_sha256 preparation_plan_raw_sha256 preparation_plan_sha256 authority_packet_request authority_packet_request_sha256 authority_packet_sha256 a6_candidate_uuid a6_descriptor_sha256 observation_bundle_bytes observation_bundle_raw_sha256 expected_bundle_uuid expected_carrier_commit input_class evidence_references maximum_attempts automatic_retry_count automatic_cleanup_count request_sha256') 'request ordered shape differs'
$junctionShape = [regex]::Match($design, '(?m)^& \[junction\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($junctionShape.Success -and $junctionShape.Groups[1].Value -ceq '  + exact ordered fields are source kind target') 'junction ordered shape differs'
$roleShape = [regex]::Match($design, '(?m)^& \[role\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($roleShape.Success -and $roleShape.Groups[1].Value -ceq '  + exact ordered fields are kind path state') 'role ordered shape differs'
$reserved_refShape = [regex]::Match($design, '(?m)^& \[reserved_ref\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($reserved_refShape.Success -and $reserved_refShape.Groups[1].Value -ceq '  + exact ordered fields are reference state') 'reserved_ref ordered shape differs'
$comparisonShape = [regex]::Match($design, '(?m)^& \[comparison\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($comparisonShape.Success -and $comparisonShape.Groups[1].Value -ceq '  + exact ordered fields are carrier_commit_matches branch_matches remote_matches project_matches observation_time_matches_a4 capacity_meets_minimum build_junctions_match upstream_identities_match all_roles_absent_asserted reserved_ref_absent_asserted mismatch_reasons all_expectations_match') 'comparison ordered shape differs'
$effectsShape = [regex]::Match($design, '(?m)^& \[effects\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($effectsShape.Success -and $effectsShape.Groups[1].Value -ceq '  + exact ordered fields are reference_resolution_count private_key_read_count signing_count revocation_service_contact_count witness_service_contact_count clock_read_count environment_read_count host_observation_count process_count provider_trial_count model_turn_count mcp_call_count network_contact_count broker_invocation_count writer_run_count filesystem_mutation_count git_mutation_count persistence_count activation_count cleanup_count remote_hardware_contact_count physical_contact') 'effects ordered shape differs'
$manifestShape = [regex]::Match($design, '(?m)^& \[manifest\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($manifestShape.Success -and $manifestShape.Groups[1].Value -ceq '  + exact ordered fields are profile manifest_uuid fixture_only artifacts artifact_count total_artifact_bytes retained_authority_packet_sha256 retained_a5_receipt_sha256 retained_preparation_plan_sha256 retained_observation_bundle_sha256 retained_receipt_sha256 deterministic_replay_count required_fresh_process_replay_count byte_identical effect_count manifest_sha256') 'manifest ordered shape differs'
$receiptShape = [regex]::Match($design, '(?m)^& \[receipt\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($receiptShape.Success -and $receiptShape.Groups[1].Value -ceq '  + exact ordered fields are profile status authority source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a5_implementation_commit a5_bookend_commit a5_proof_uuid plan_implementation_commit plan_bookend_commit plan_proof_uuid request_sha256 a5_verification_request_sha256 a5_receipt_sha256 a5_receipt preparation_plan_request_raw_sha256 preparation_plan_request_sha256 preparation_plan_raw_sha256 preparation_plan_sha256 proposal_sha256 authority_packet_request_sha256 authority_packet_sha256 a6_candidate_uuid a6_descriptor_sha256 observation_bundle_bytes observation_bundle_raw_sha256 observation_bundle_sha256 bundle_uuid expected_carrier_commit observed_carrier_commit legacy_decision_expected_current_commit preparation_plan_expected_current_commit observed_unix_ms a4_observed_unix_ms observed_cdrive_free_bytes minimum_cdrive_free_bytes comparison_account input_class fixture_only maximum_attempts automatic_retry_count automatic_cleanup_count a5_correspondence_receipt_verified preparation_plan_replayed proposal_plan_correspondence_verified packet_replayed descriptor_correspondence_verified observation_bundle_bytes_matched comparison_reconstructed production_authority_claimed fresh_observation_proved observation_source_identity_proved observation_source_completeness_proved observation_freshness_proved atomic_observation_proved decision_signature_binds_a6_observation expected_carrier_authority_proved live_authorization_admitted private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized effect_account receipt_sha256') 'receipt ordered shape differs'
$artifactShape = [regex]::Match($design, '(?m)^& \[artifact\]\r?\n(  \+ exact ordered fields are [^\r\n]+)')
Assert-Exact ($artifactShape.Success -and $artifactShape.Groups[1].Value -ceq '  + exact ordered fields are path bytes sha256') 'artifact ordered shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedOdcvVerificationRequest\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a4_implementation_commit a4_bookend_commit a4_proof_uuid legacy_implementation_commit legacy_bookend_commit legacy_proof_uuid predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 a4_time_witness_receipt_raw_sha256 a4_verification_request_sha256 a4_receipt_sha256 authority_packet_request authority_packet_request_sha256 authority_packet_sha256 a5_candidate_uuid a5_descriptor_sha256 operator_decision_policy_sha256 operator_decision_request_sha256 operator_decision_envelope_bytes operator_decision_envelope_raw_sha256 expected_policy_revision_uuid expected_decision_uuid expected_decision_kind expected_external_decision_identity input_class evidence_references maximum_attempts automatic_retry_count automatic_cleanup_count request_sha256') 'OdcvVerificationRequest imported shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedOdcvVerificationReceipt\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are profile status authority source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit formation_commit formation_bookend_commit a4_implementation_commit a4_bookend_commit a4_proof_uuid legacy_implementation_commit legacy_bookend_commit legacy_proof_uuid predecessor_request_sha256 predecessor_packet_sha256 predecessor_verification_sha256 a1_policy_envelope_raw_sha256 a1_verification_request_sha256 a1_receipt_sha256 a2_custody_attestation_raw_sha256 a2_verification_request_sha256 a2_receipt_sha256 a3_revocation_snapshot_raw_sha256 a3_verification_request_sha256 a3_receipt_sha256 a4_time_witness_receipt_raw_sha256 a4_verification_request_sha256 a4_receipt_sha256 authority_packet_request_sha256 authority_packet_sha256 request_sha256 a5_candidate_uuid a5_descriptor_sha256 operator_decision_policy_sha256 operator_decision_request_sha256 operator_decision_envelope_bytes operator_decision_envelope_raw_sha256 policy_uuid policy_revision_uuid principal role subject target_policy_key_fingerprint_sha256 legacy_policy_key_fingerprint_sha256 decision_uuid decision_kind external_decision_identity observed_unix_ms issued_at_unix_millis expires_at_unix_millis comparison_outcome supplied_a3_status_assertion payload_sha256 envelope_sha256 signature_sha256 legacy_verification_sha256 input_class fixture_only maximum_attempts automatic_retry_count automatic_cleanup_count packet_replayed a1_correspondence_receipt_verified a2_correspondence_receipt_verified a3_correspondence_receipt_verified a4_correspondence_receipt_verified a5_candidate_bytes_matched descriptor_correspondence_verified subject_lineage_correspondence_verified decision_policy_key_correspondence_verified decision_policy_artifact_bindings_verified decision_request_correspondence_verified decision_structure_verified decision_signature_correspondence_verified decision_expectations_verified supplied_decision_interval_comparison_verified production_authority_claimed challenge_freshness_proved replay_prevention_proved custodian_identity_proved protected_storage_proved private_key_nonexportability_proved exclusive_control_proved current_possession_proved responder_identity_proved responder_authority_proved source_completeness_proved monotonic_history_proved snapshot_freshness_proved current_time_compared policy_governance_proved key_custody_proved revocation_truth_proved current_nonexpired live_authorization_admitted fresh_observation_proved private_execution_permit_present production_broker_projection_present physical_preparation_authorized ready_for_physical_execution execution_authorized witness_identity_proved witness_authority_proved witness_freshness_proved trusted_current_time_proved decision_signer_identity_proved decision_authority_proved decision_freshness_proved decision_signature_binds_a4_lineage effect_account receipt_sha256') 'OdcvVerificationReceipt imported shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedB1CDriveProductionPreparationPlanRequest\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are profile source_snapshot_uuid canonical_uuid signature_uuid source_custody_commit production_broker_implementation_commit production_broker_bookend_commit expected_current_commit branch canonical_remote working_project observed_cdrive_free_bytes minimum_cdrive_free_bytes build_junctions upstream_identities plan_namespace_uuid provider_available request_sha256') 'B1CDriveProductionPreparationPlanRequest imported shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedB1CDriveProductionPreparationPlan\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are profile status authority request_sha256 roles operations fixed_ledger_bytes unclaimed_ledger_sha256 unresolved_authorities effect_account physical_preparation_authorized plan_sha256') 'B1CDriveProductionPreparationPlan imported shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedB1CDriveProductionPreparationUpstreamIdentity\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are role profile artifact_sha256') 'B1CDriveProductionPreparationUpstreamIdentity imported shape differs'
$importedShape = [regex]::Match($design, '(?m)^& \[ImportedB1CDriveProductionPreparationCommissionProposal\]\r?\n  \+ imported from [^\r\n]+\r?\n(  \+ imported exact ordered fields are [^\r\n]+)')
Assert-Exact ($importedShape.Success -and $importedShape.Groups[1].Value -ceq '  + imported exact ordered fields are profile status authority proposal_uuid request_sha256 inherited_plan_sha256 roles operations proposed_ref responsibilities authorization_gaps quarantine_policy effect_account external_authorization_present physical_preparation_authorized proposal_sha256') 'B1CDriveProductionPreparationCommissionProposal imported shape differs'
Assert-Exact ($design.Contains('  + mismatch reasons in exact order carrier_commit_mismatch branch_mismatch remote_mismatch project_mismatch observation_time_mismatch capacity_below_floor build_junction_mismatch upstream_identity_mismatch role_not_absent reserved_ref_not_absent')) 'mismatch reason order differs'
Assert-Exact ($design.Contains('Some iff junction and otherwise None serialized null')) 'junction nullable shape differs'
Assert-Exact ($design.Contains('Deserialize then exact reserialize equality refuses missing Option keys or alternate escaping')) 'missing nullable key admission differs'
Assert-Properties $manifest.verification @($expectedAccount.Keys) 'verification'
foreach ($key in $expectedAccount.Keys) { Assert-Value $manifest.verification.$key $expectedAccount[$key] "verification.$key" }
foreach ($commit in @('4f1417d111911f0fd27437f13b480157332442b2','23cc6c17667efefa88ca27a1af2d1e410a9ccd00','9b3dd715439c26aa34181dace0e525681a1f29b9','f72237acd50fdc296b7e47825a84200528f6c850','2ae87673cfd343cc7a4685a5d0ebbdfc37256ea3')) {
    git -C $scriptRepository cat-file -e ($commit + '^{commit}')
    Assert-Exact ($LASTEXITCODE -eq 0) 'required publication commit absent'
}
Write-Output 'b1_expected_observation_formation_passed artifacts=21 bindings=20 requirements=33 acceptance=5 new_profiles=4 imported_types=6 classes=2 decisions=2 files=26 explicit_inputs=24 comparisons=10 reasons=10 statuses=2 bundle_fields=17 request_fields=34 receipt_fields=69 manifest_fields=16 selected_A6=1 dependency_A5=1 downstream=3 positives=7 global_false=14 inherited_false=33 effects=22 attempts=1 retries=0 cleanup=0 implementation_authorized=true execution_authorized=false signed_a6_context=false freshness=false formation_effects=0'
