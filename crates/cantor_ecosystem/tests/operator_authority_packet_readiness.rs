use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    B1OAPR_AUTHORITY, B1OAPR_DISPOSITION, B1OAPR_EVIDENCE_MANIFEST_PROFILE,
    B1OAPR_FORMATION_COMMIT, B1OAPR_MAX_CANDIDATE_BYTES, B1OAPR_NON_AUTHORITY, B1OAPR_PACKET_FILE,
    B1OAPR_REQUEST_FILE, B1OAPR_SIGNATURE_UUID, B1OAPR_SOURCE_SNAPSHOT_UUID, B1OAPR_STATUS,
    B1OAPR_VERIFICATION_FILE, B1OaprCandidateOrigin, B1OaprConfidentiality, B1OaprEffectAccount,
    B1OaprEvidenceArtifact, B1OaprEvidenceManifest, B1OaprFaultCode, b1oapr_descriptor_digest,
    b1oapr_evidence_manifest_digest, b1oapr_packet_digest, b1oapr_request_digest,
    canonical_b1oapr_request, compile_b1oapr_packet, expected_b1oapr_unresolved_authorities,
    from_b1oapr_request_machine_form, to_b1oapr_evidence_manifest_machine_form,
    to_b1oapr_packet_machine_form, to_b1oapr_request_machine_form,
    to_b1oapr_verification_machine_form, verify_b1oapr_evidence_directory, verify_b1oapr_packet,
};

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

#[test]
fn deterministic_packet_conserves_all_authority_and_effects() {
    let request = canonical_b1oapr_request().unwrap();
    let first = compile_b1oapr_packet(&request).unwrap();
    let second = compile_b1oapr_packet(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.status, B1OAPR_STATUS);
    assert_eq!(first.authority, B1OAPR_AUTHORITY);
    assert_eq!(first.descriptors.len(), 9);
    assert_eq!(first.dispositions.len(), 9);
    assert_eq!(
        first.unresolved_authorities,
        expected_b1oapr_unresolved_authorities()
    );
    assert!(
        first
            .dispositions
            .iter()
            .all(|item| item.disposition == B1OAPR_DISPOSITION)
    );
    assert!(
        first
            .dispositions
            .iter()
            .all(|item| !item.externally_verified && !item.authority_admitted)
    );
    assert_eq!(first.effect_account, B1OaprEffectAccount::default());
    assert!(!first.candidate_material_authenticated);
    assert!(!first.live_authorization_admitted);
    assert!(!first.ready_for_physical_execution);
    let verification = verify_b1oapr_packet(&request, &first).unwrap();
    assert_eq!(verification.descriptor_count, 9);
    assert_eq!(verification.unresolved_authority_count, 9);
    assert_eq!(verification.deterministic_replay_count, 2);
    assert!(verification.byte_identical);
    assert!(verification.all_candidate_material_untrusted);
    assert!(verification.all_authority_unadmitted);
}

#[test]
fn exact_coordinate_dependency_and_confidentiality_table_is_closed() {
    let request = canonical_b1oapr_request().unwrap();
    let authorities = [
        "policy_governance",
        "key_custody",
        "revocation_truth",
        "current_time",
        "live_decision",
        "fresh_observation",
        "private_execution_permit",
        "broker_projection",
        "physical_preparation",
    ];
    for (index, descriptor) in request.descriptors.iter().enumerate() {
        assert_eq!(descriptor.ordinal as usize, index + 1);
        assert_eq!(descriptor.authority_name, authorities[index]);
        assert_eq!(
            descriptor.dependency_ordinal,
            if index == 0 { None } else { Some(index as u8) }
        );
        assert_eq!(
            descriptor.confidentiality,
            if index == 6 {
                B1OaprConfidentiality::SecretReferenceOnly
            } else {
                B1OaprConfidentiality::PublicMetadata
            }
        );
        assert!(descriptor.fixture_only);
        assert_eq!(
            descriptor.origin,
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        );
    }
}

#[test]
fn externally_supplied_labels_compile_without_authentication_or_resolution() {
    let mut request = canonical_b1oapr_request().unwrap();
    for descriptor in &mut request.descriptors {
        descriptor.fixture_only = false;
        descriptor.origin = B1OaprCandidateOrigin::ExternallySuppliedCandidate;
        descriptor.opaque_reference =
            format!("caller_owned_opaque_reference_a{}", descriptor.ordinal);
        descriptor.content_sha256 =
            sha256_bytes(format!("caller claim {}", descriptor.ordinal).as_bytes());
        descriptor.descriptor_sha256 = empty_digest();
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
    }
    redigest_request(&mut request);
    let packet = compile_b1oapr_packet(&request).unwrap();
    assert!(
        packet
            .descriptors
            .iter()
            .all(|descriptor| !descriptor.fixture_only)
    );
    assert!(!packet.candidate_material_authenticated);
    assert!(
        packet
            .dispositions
            .iter()
            .all(|item| !item.externally_verified && !item.authority_admitted)
    );
    assert_eq!(packet.effect_account, B1OaprEffectAccount::default());
}

#[test]
fn strict_forms_round_trip_and_duplicate_property_refuses() {
    let request = canonical_b1oapr_request().unwrap();
    let form = to_b1oapr_request_machine_form(&request).unwrap();
    assert_eq!(from_b1oapr_request_machine_form(&form).unwrap(), request);
    let duplicated = form.replacen(
        "{",
        r#"{"profile":"cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet-readiness-request/0.1","#,
        1,
    );
    assert!(from_b1oapr_request_machine_form(&duplicated).is_err());
    assert!(from_b1oapr_request_machine_form(&(form + " ")).is_err());
}

#[test]
fn lineage_attempt_retry_cleanup_and_self_digest_mutations_refuse() {
    for mutation in 0_u8..6 {
        let mut request = canonical_b1oapr_request().unwrap();
        match mutation {
            0 => request.branch = "main".to_owned(),
            1 => request.formation_commit.replace_range(..1, "7"),
            2 => request.maximum_attempts = 2,
            3 => request.automatic_retry_count = 1,
            4 => request.automatic_cleanup_count = 1,
            5 => request.ceremony_plan_digest.replace_range(..1, "f"),
            _ => unreachable!(),
        }
        redigest_request(&mut request);
        assert!(compile_b1oapr_packet(&request).is_err());
    }
    let mut request = canonical_b1oapr_request().unwrap();
    request.request_sha256.value.replace_range(..1, "f");
    assert!(compile_b1oapr_packet(&request).is_err());
}

#[test]
fn duplicate_coordinate_retains_ordinal_one_and_refuses() {
    let mut request = canonical_b1oapr_request().unwrap();
    let mut duplicate = request.descriptors[0].clone();
    duplicate.candidate_uuid = "a1000000-0000-4000-8000-000000000099".to_owned();
    duplicate.descriptor_sha256 = empty_digest();
    duplicate.descriptor_sha256 = b1oapr_descriptor_digest(&duplicate).unwrap();
    request.descriptors[1] = duplicate;
    assert_eq!(request.descriptors[0].ordinal, 1);
    assert_eq!(request.descriptors[1].ordinal, 1);
    redigest_request(&mut request);
    let fault = compile_b1oapr_packet(&request).unwrap_err();
    assert_eq!(fault.code, B1OaprFaultCode::Coordinate);
}

#[test]
fn coordinate_origin_confidentiality_dependency_and_reference_mutations_refuse() {
    for mutation in 0_u8..7 {
        let mut request = canonical_b1oapr_request().unwrap();
        let descriptor = &mut request.descriptors[6];
        match mutation {
            0 => descriptor.artifact_kind = "private_key_candidate".to_owned(),
            1 => descriptor.required_verifier_profile = "wrong/0.1".to_owned(),
            2 => descriptor.dependency_ordinal = Some(2),
            3 => descriptor.confidentiality = B1OaprConfidentiality::PublicMetadata,
            4 => descriptor.origin = B1OaprCandidateOrigin::ExternallySuppliedCandidate,
            5 => descriptor.opaque_reference = "x".repeat(8_193),
            6 => descriptor.content_sha256.value.make_ascii_uppercase(),
            _ => unreachable!(),
        }
        descriptor.descriptor_sha256 = empty_digest();
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
        redigest_request(&mut request);
        assert!(compile_b1oapr_packet(&request).is_err());
    }
}

#[test]
fn candidate_and_aggregate_byte_bounds_refuse() {
    let mut request = canonical_b1oapr_request().unwrap();
    request.descriptors[0].declared_bytes = B1OAPR_MAX_CANDIDATE_BYTES + 1;
    redigest_descriptor_and_request(&mut request, 0);
    assert!(compile_b1oapr_packet(&request).is_err());

    let mut request = canonical_b1oapr_request().unwrap();
    for index in 0..request.descriptors.len() {
        request.descriptors[index].declared_bytes = 8_000_000;
        request.descriptors[index].descriptor_sha256 = empty_digest();
        request.descriptors[index].descriptor_sha256 =
            b1oapr_descriptor_digest(&request.descriptors[index]).unwrap();
    }
    redigest_request(&mut request);
    assert!(compile_b1oapr_packet(&request).is_err());
}

#[test]
fn authority_disposition_effect_and_packet_digest_laundering_refuse() {
    let request = canonical_b1oapr_request().unwrap();
    let packet = compile_b1oapr_packet(&request).unwrap();

    let mut authority = packet.clone();
    authority.live_authorization_admitted = true;
    redigest_packet(&mut authority);
    assert_eq!(
        verify_b1oapr_packet(&request, &authority).unwrap_err().code,
        B1OaprFaultCode::Authority
    );

    let mut disposition = packet.clone();
    disposition.dispositions[0].authority_admitted = true;
    redigest_packet(&mut disposition);
    assert_eq!(
        verify_b1oapr_packet(&request, &disposition)
            .unwrap_err()
            .code,
        B1OaprFaultCode::Authority
    );

    let mut effect = packet.clone();
    effect.effect_account.candidate_reference_resolution_count = 1;
    redigest_packet(&mut effect);
    assert_eq!(
        verify_b1oapr_packet(&request, &effect).unwrap_err().code,
        B1OaprFaultCode::Effect
    );

    let mut digest = packet;
    digest.packet_sha256.value.replace_range(..1, "f");
    assert_eq!(
        verify_b1oapr_packet(&request, &digest).unwrap_err().code,
        B1OaprFaultCode::Digest
    );
}

#[test]
fn production_module_has_no_reference_resolution_or_effect_surface() {
    let source = fs::read_to_string(source_path()).unwrap();
    for forbidden in [
        "std::fs",
        "std::env",
        "std::process",
        "std::net",
        "SystemTime",
        "SigningKey",
        "Command::",
        "OpenOptions",
        "TcpStream",
        ".metadata(",
        "production_broker(",
    ] {
        assert!(
            !source.contains(forbidden),
            "production source contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn independent_evidence_double_replays_and_refuses_extra_entry() {
    let root = synthetic_root("valid");
    write_fixture(&root);
    let evidence = verify_b1oapr_evidence_directory(&root).unwrap();
    assert_eq!(evidence.artifact_count, 3);
    assert_eq!(evidence.descriptor_count, 9);
    assert_eq!(evidence.independent_replay_count, 2);
    assert!(evidence.byte_identical_replays);
    assert!(!evidence.candidate_material_authenticated);
    assert!(!evidence.authority_admitted);
    assert_eq!(evidence.effect_account, B1OaprEffectAccount::default());
    fs::write(root.join("extra.json"), "{}").unwrap();
    assert!(verify_b1oapr_evidence_directory(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn independent_evidence_refuses_raw_request_packet_and_manifest_tamper() {
    for (label, filename) in [
        ("request", B1OAPR_REQUEST_FILE),
        ("packet", B1OAPR_PACKET_FILE),
        ("restart", "evidence_manifest.json"),
    ] {
        let root = synthetic_root(label);
        write_fixture(&root);
        let path = root.join(filename);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b' ');
        fs::write(path, bytes).unwrap();
        assert!(verify_b1oapr_evidence_directory(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn bounded_compiler_and_evidence_clis_accept_only_the_exact_fixture() {
    let root = synthetic_root("cli");
    write_fixture(&root);
    let compiler = Command::new(env!("CARGO_BIN_EXE_cantor-b1-operator-authority-packet"))
        .arg(root.join(B1OAPR_REQUEST_FILE))
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    assert_eq!(
        compiler.stdout,
        [
            fs::read(root.join(B1OAPR_PACKET_FILE)).unwrap(),
            vec![b'\n']
        ]
        .concat()
    );
    let verifier = Command::new(env!(
        "CARGO_BIN_EXE_cantor-b1-operator-authority-packet-evidence-verify"
    ))
    .arg(&root)
    .output()
    .unwrap();
    assert!(
        verifier.status.success(),
        "{}",
        String::from_utf8_lossy(&verifier.stderr)
    );
    assert!(verifier.stdout.ends_with(b"\n"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_b1oapr_evidence() {
    let root = std::env::var_os("CANTOR_B1OAPR_EVIDENCE_DIR")
        .map(PathBuf::from)
        .expect("CANTOR_B1OAPR_EVIDENCE_DIR is required");
    assert!(!root.exists(), "owned evidence root must be absent");
    write_fixture(&root);
    verify_b1oapr_evidence_directory(&root).unwrap();
}

fn redigest_descriptor_and_request(request: &mut cantor_ecosystem::B1OaprRequest, index: usize) {
    request.descriptors[index].descriptor_sha256 = empty_digest();
    request.descriptors[index].descriptor_sha256 =
        b1oapr_descriptor_digest(&request.descriptors[index]).unwrap();
    redigest_request(request);
}

fn redigest_request(request: &mut cantor_ecosystem::B1OaprRequest) {
    request.request_sha256 = empty_digest();
    request.request_sha256 = b1oapr_request_digest(request).unwrap();
}

fn redigest_packet(packet: &mut cantor_ecosystem::B1OaprPacket) {
    packet.packet_sha256 = empty_digest();
    packet.packet_sha256 = b1oapr_packet_digest(packet).unwrap();
}

fn source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/self_work_update_broker_b1_operator_authority_packet_readiness.rs")
}

fn synthetic_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cantor_b1oapr_{}_{}", std::process::id(), label))
}

fn write_fixture(root: &Path) {
    assert!(!root.exists());
    fs::create_dir_all(root).unwrap();
    let request = canonical_b1oapr_request().unwrap();
    let packet = compile_b1oapr_packet(&request).unwrap();
    let verification = verify_b1oapr_packet(&request, &packet).unwrap();
    let request_text = to_b1oapr_request_machine_form(&request).unwrap();
    let packet_text = to_b1oapr_packet_machine_form(&request, &packet).unwrap();
    let verification_text =
        to_b1oapr_verification_machine_form(&request, &packet, &verification).unwrap();
    let artifacts = [
        (B1OAPR_PACKET_FILE, packet_text.as_bytes()),
        (B1OAPR_REQUEST_FILE, request_text.as_bytes()),
        (B1OAPR_VERIFICATION_FILE, verification_text.as_bytes()),
    ];
    for (path, bytes) in artifacts {
        fs::write(root.join(path), bytes).unwrap();
    }
    let mut manifest = B1OaprEvidenceManifest {
        profile: B1OAPR_EVIDENCE_MANIFEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1OAPR_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: cantor_ecosystem::B1OAPR_CANONICAL_UUID.to_owned(),
        signature_uuid: B1OAPR_SIGNATURE_UUID.to_owned(),
        formation_commit: B1OAPR_FORMATION_COMMIT.to_owned(),
        artifacts: artifacts
            .into_iter()
            .map(|(path, bytes)| B1OaprEvidenceArtifact {
                path: path.to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(bytes),
            })
            .collect(),
        fixture_only: true,
        candidate_material_authenticated: false,
        authority_admitted: false,
        physical_execution_authorized: false,
        non_authority_statement: B1OAPR_NON_AUTHORITY.to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 = b1oapr_evidence_manifest_digest(&manifest).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        to_b1oapr_evidence_manifest_machine_form(&manifest).unwrap(),
    )
    .unwrap();
}
