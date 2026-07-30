mod common;

use cantor_core::{
    PackageCompiler, SemanticId, TrustFaultKind, UnitKind, admit_package, package_content_digest,
    semantic_root_digest, source_root_digest, validate_package_structure,
};
use ed25519_dalek::SigningKey;

use common::{NOW, compiler, package_input, scope, trust_store};

#[test]
fn valid_two_file_package_is_admitted_with_verified_quotes() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("valid fixture package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let admitted =
        admit_package(&package, &store, &scope(), NOW).expect("valid package must be admitted");

    assert_eq!(admitted.content().sources.len(), 2);
    assert_eq!(admitted.content().semantic_units.len(), 2);
    assert_eq!(admitted.content().source_anchors.len(), 2);
    assert_eq!(admitted.content().quotes.len(), 2);
    assert!(
        admitted
            .content()
            .source_anchors
            .iter()
            .all(|anchor| anchor.package_id == admitted.package().package_id)
    );
    validate_package_structure(admitted.package()).expect("admitted package must remain valid");
}

#[test]
fn unsigned_package_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package.certificate = None;
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("unsigned package must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::UnsignedPackage);
}

#[test]
fn modified_source_without_recompilation_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package.content.sources[0].bytes[0] ^= 1;
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("modified source must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::PackageDigestMismatch);
}

#[test]
fn corrupted_exact_index_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package.content.exact_indexes.unit_positions.clear();
    let structure_fault = validate_package_structure(&package)
        .expect_err("structural validation must identify the corrupt index");
    assert_eq!(structure_fault.kind, TrustFaultKind::IndexCorruption);
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("corrupted index must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::PackageDigestMismatch);
}

#[test]
fn changed_anchor_package_identity_is_rejected_by_referential_gate() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package.content.source_anchors[0].package_id = common::id("package:substituted_identity");
    package.content.quotes[0].anchor.package_id = common::id("package:substituted_identity");
    let fault = validate_package_structure(&package)
        .expect_err("anchor package identity must bind to its enclosing package");
    assert_eq!(fault.kind, TrustFaultKind::ReferentialIntegrity);
}

#[test]
fn dependency_lock_mismatch_is_rejected() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let mut store = trust_store(&compiler, "1.0.0", &scope());
    store
        .required_dependency_lock
        .insert("fixture-schema".to_owned(), "2".to_owned());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("dependency drift must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::DependencyLockMismatch);
}

#[test]
fn noncanonical_collection_order_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package.content.semantic_units.swap(0, 1);
    let fault = validate_package_structure(&package)
        .expect_err("noncanonical collection order must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);
}

#[test]
fn stale_package_is_rejected() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let mut store = trust_store(&compiler, "1.0.0", &scope());
    store.stale_packages.insert(package.package_id.clone());
    let fault =
        admit_package(&package, &store, &scope(), NOW).expect_err("stale package must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::Stale);
}

#[test]
fn revoked_certificate_is_rejected() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let mut store = trust_store(&compiler, "1.0.0", &scope());
    store.revoked_certificates.insert(
        package
            .certificate
            .as_ref()
            .expect("compiled package is signed")
            .certificate_id
            .clone(),
    );
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("revoked certificate must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::Revoked);
}

#[test]
fn mixed_package_components_are_rejected() {
    let compiler = compiler("1.0.0");
    let mut first = compiler
        .compile(package_input(""))
        .expect("first fixture package must compile");
    let shifted = compiler
        .compile(package_input("# shifted source\n"))
        .expect("second fixture package must compile");
    first.content.sources[0] = shifted.content.sources[0].clone();
    first.content.source_anchors[0] = shifted.content.source_anchors[0].clone();
    first.content.quotes[0] = shifted.content.quotes[0].clone();
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&first, &store, &scope(), NOW)
        .expect_err("mixed package components must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::PackageDigestMismatch);
}

#[test]
fn compiler_downgrade_is_rejected_even_when_signature_is_valid() {
    let trusted = compiler("1.0.0");
    let downgraded = compiler("0.9.0");
    let package = downgraded
        .compile(package_input(""))
        .expect("downgraded fixture package can be signed");
    let store = trust_store(&trusted, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("unapproved compiler version must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::CompilerVersionRejected);
}

#[test]
fn scope_exceeding_request_is_rejected() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let mut requested = scope();
    requested.projects.insert("other-project".to_owned());
    let fault = admit_package(&package, &store, &requested, NOW)
        .expect_err("scope-exceeding request must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::ScopeViolation);
}

#[test]
fn line_shift_requires_recompile_but_preserves_semantic_identity() {
    let compiler = compiler("1.0.0");
    let original = compiler
        .compile(package_input(""))
        .expect("original fixture package must compile");
    let shifted = compiler
        .compile(package_input("# inserted line\n"))
        .expect("shifted fixture package must recompile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    admit_package(&original, &store, &scope(), NOW).expect("original package must admit");
    admit_package(&shifted, &store, &scope(), NOW).expect("shifted package must admit");

    assert_ne!(original.package_id, shifted.package_id);
    assert_ne!(
        package_content_digest(&original.content).expect("original digest"),
        package_content_digest(&shifted.content).expect("shifted digest")
    );
    assert_eq!(
        original.content.semantic_units[0].unit_id,
        shifted.content.semantic_units[0].unit_id
    );
    assert_eq!(
        original.content.source_anchors[0].span_digest,
        shifted.content.source_anchors[0].span_digest
    );
    assert_eq!(
        original.content.source_anchors[0].display_line_start + 1,
        shifted.content.source_anchors[0].display_line_start
    );
}

#[test]
fn invalid_signature_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package
        .certificate
        .as_mut()
        .expect("fixture package is signed")
        .authority_signature[0] ^= 1;
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("invalid signature must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::InvalidSignature);
}

#[test]
fn unsigned_validity_extension_is_rejected() {
    let compiler = compiler("1.0.0");
    let mut package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    package
        .certificate
        .as_mut()
        .expect("fixture package is signed")
        .not_after_epoch_seconds = 300;
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("unsigned validity extension must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::InvalidPackageIdentity);
}

#[test]
fn expired_certificate_is_rejected() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let fault = admit_package(&package, &store, &scope(), 201)
        .expect_err("expired certificate must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::Expired);
}

#[test]
fn signed_roots_match_the_compiled_package() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let certificate = package
        .certificate
        .as_ref()
        .expect("fixture package must be signed");
    assert_eq!(
        semantic_root_digest(&package.content).expect("semantic root"),
        certificate.semantic_root_digest
    );
    assert_eq!(
        source_root_digest(&package.content).expect("source root"),
        certificate.source_root_digest
    );
}

#[test]
fn deserialization_cannot_bypass_semantic_identity_validation() {
    let fault = serde_json::from_str::<SemanticId>("\"identity with spaces\"")
        .expect_err("invalid identity must fail during machine-form decoding");
    assert!(fault.to_string().contains("invalid semantic identity"));

    let oversized = format!("\"unit:{}\"", "a".repeat(600));
    let fault = serde_json::from_str::<SemanticId>(&oversized)
        .expect_err("oversized semantic identity must fail during machine-form decoding");
    assert!(fault.to_string().contains("byte_length=605"));
    assert!(
        fault.to_string().len() < 512,
        "invalid identity diagnostics must remain bounded"
    );
}

#[test]
fn trust_store_record_identity_must_match_its_lookup_key() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let mut store = trust_store(&compiler, "1.0.0", &scope());
    store
        .signers
        .get_mut(&compiler.authority_signer_id)
        .expect("authority signer record must exist")
        .signer_id = common::id("signer:substituted_record_identity");
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("mismatched signer record identity must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::SignerIdentityMismatch);
}

#[test]
fn compiler_rejects_shared_authority_and_compiler_key() {
    let shared_key = SigningKey::from_bytes(&[61_u8; 32]);
    let compiler = PackageCompiler::new(
        common::id("compiler:shared_key_fixture"),
        "1.0.0",
        common::id("signer:shared_key_authority"),
        common::id("signer:shared_key_compiler"),
        shared_key.clone(),
        shared_key,
    );
    let fault = compiler
        .compile(package_input(""))
        .expect_err("shared authority and compiler key must not compile");
    assert_eq!(fault.kind, TrustFaultKind::SignerSeparationViolation);
}

#[test]
fn admission_rejects_trust_policy_that_collapses_signer_keys() {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("fixture package must compile");
    let mut store = trust_store(&compiler, "1.0.0", &scope());
    let authority_key = store.signers[&compiler.authority_signer_id]
        .verifying_key
        .clone();
    store
        .signers
        .get_mut(&compiler.compiler_signer_id)
        .expect("compiler signer must exist")
        .verifying_key = authority_key;
    let fault = admit_package(&package, &store, &scope(), NOW)
        .expect_err("collapsed trust-policy keys must fail closed");
    assert_eq!(fault.kind, TrustFaultKind::SignerSeparationViolation);
}

#[test]
fn compiler_rejects_non_utf8_sop_source() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.sources[0].bytes.push(0xff);
    let fault = compiler
        .compile(input)
        .expect_err("non-UTF-8 SOP source must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::InvalidSourceEncoding);
}

#[test]
fn compiler_rejects_source_spans_inside_utf8_characters() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.sources[0].bytes = "é".as_bytes().to_vec();
    input.units[0].byte_start = 0;
    input.units[0].byte_end = 1;
    let fault = compiler
        .compile(input)
        .expect_err("mid-character source span must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::InvalidSourceSpan);
}

#[test]
fn compiler_rejects_duplicate_human_source_paths() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.sources[1].path = input.sources[0].path.clone();
    let fault = compiler
        .compile(input)
        .expect_err("ambiguous duplicate source paths must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::DuplicateIdentity);
}

#[test]
fn compiler_rejects_semantic_units_without_complete_context_identity() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.units[0].unit.context.scope.clear();
    let fault = compiler
        .compile(input)
        .expect_err("incomplete semantic context must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);
}

#[test]
fn compiler_rejects_units_outside_declared_kind_or_perspective_scope() {
    let compiler = compiler("1.0.0");
    let mut wrong_kind = package_input("");
    wrong_kind.units[0].unit.kind = UnitKind::Operation;
    let fault = compiler
        .compile(wrong_kind)
        .expect_err("unit kind outside declared authority must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::ScopeViolation);
    assert_eq!(fault.gate, "authority_scope_content");

    let mut wrong_perspective = package_input("");
    wrong_perspective.units[0].unit.context.perspective = "unrecognized".to_owned();
    let fault = compiler
        .compile(wrong_perspective)
        .expect_err("unit perspective outside declared authority must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::ScopeViolation);
    assert_eq!(fault.gate, "authority_scope_content");

    let mut missing_domain = package_input("");
    missing_domain.authority_scope.projects.clear();
    missing_domain.authority_scope.namespaces.clear();
    let fault = compiler
        .compile(missing_domain)
        .expect_err("authority scope without project or namespace must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::ScopeViolation);
    assert_eq!(fault.gate, "authority_scope_structure");
}

#[test]
fn compiler_rejects_blank_semantic_and_provenance_fields() {
    let compiler = compiler("1.0.0");

    let mut blank_meaning = package_input("");
    blank_meaning.units[0].unit.meaning = " ".to_owned();
    let fault = compiler
        .compile(blank_meaning)
        .expect_err("blank meaning must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut blank_alias = package_input("");
    blank_alias.units[0].unit.aliases.insert(" ".to_owned());
    let fault = compiler
        .compile(blank_alias)
        .expect_err("blank alias must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut missing_source_set = package_input("");
    missing_source_set.units[0].unit.source_set.clear();
    let fault = compiler
        .compile(missing_source_set)
        .expect_err("unit without provenance source set must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut blank_source_path = package_input("");
    blank_source_path.sources[0].path = " ".to_owned();
    let fault = compiler
        .compile(blank_source_path)
        .expect_err("blank source path must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut blank_relation_source = package_input("");
    blank_relation_source.relations[0].source_ref = " ".to_owned();
    let fault = compiler
        .compile(blank_relation_source)
        .expect_err("blank relation source must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut blank_proof = package_input("");
    blank_proof.proof_ids.push(" ".to_owned());
    let fault = compiler
        .compile(blank_proof)
        .expect_err("blank proof identity must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let mut blank_dependency = package_input("");
    blank_dependency
        .dependency_lock
        .insert("blank-version".to_owned(), " ".to_owned());
    let fault = compiler
        .compile(blank_dependency)
        .expect_err("blank dependency version must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);

    let fault = common::compiler("")
        .compile(package_input(""))
        .expect_err("blank compiler version must not be signed");
    assert_eq!(fault.kind, TrustFaultKind::MachineForm);
}
