use cantor_core::{
    ContentDigest, SemanticId, SjsLasSourceBindingClass, SjsLtoCoverageEdge, SjsLtoEffectAccount,
    SjsRcxElementKind, SjsRcxFaultCode, SjsRcxInputClass, build_sjs_rcx_evidence_bundle,
    compile_sjs_rcx, from_sjs_rcx_envelope_machine_form, from_sjs_rcx_evidence_bundle_machine_form,
    from_sjs_rcx_request_machine_form, seal_sjs_rcx_request, synthetic_sjs_rcx_request,
    to_sjs_rcx_envelope_machine_form, to_sjs_rcx_evidence_bundle_machine_form,
    to_sjs_rcx_request_machine_form, validate_sjs_rcx_envelope, validate_sjs_rcx_request,
    verify_sjs_rcx, verify_sjs_rcx_evidence_bundle,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test identity")
}

fn assert_refused<T>(result: Result<T, impl std::fmt::Debug>) {
    assert!(result.is_err(), "adversary must refuse");
}

#[test]
fn fixture_compiles_to_unchanged_exact_pool_result_and_zero_effects() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let envelope = compile_sjs_rcx(&request).expect("compile");
    let verification = verify_sjs_rcx(&envelope).expect("verify");

    assert_eq!(verification.record_count, 8);
    assert_eq!(verification.obligation_count, 6);
    assert_eq!(verification.coverage_edge_count, 12);
    assert_eq!(verification.admitted_subset_count, 92);
    assert_eq!(verification.selected_count, 3);
    assert_eq!(verification.rejected_count, 5);
    assert_eq!(verification.dominated_count, 1);
    assert_eq!(verification.uncovered_count, 0);
    assert_eq!(verification.effects, SjsLtoEffectAccount::default());
    assert!(!verification.execution_authorized);
    assert_eq!(envelope.receipt.admitted_record_count, 8);
    assert_eq!(envelope.receipt.refused_record_count, 0);
    assert_eq!(
        envelope.downstream_request.input_class,
        cantor_core::SjsLtoInputClass::SuppliedUnobservedCandidatePool
    );
}

#[test]
fn canonical_permutation_seals_to_identical_request_bytes() {
    let expected = synthetic_sjs_rcx_request().expect("fixture");
    let mut permuted = expected.clone();
    permuted.records.reverse();
    permuted.obligations.reverse();
    permuted.coverage_edges.reverse();
    for record in &mut permuted.records {
        record.candidate.invalidators.reverse();
    }
    let sealed = seal_sjs_rcx_request(permuted).expect("canonical seal");
    assert_eq!(
        to_sjs_rcx_request_machine_form(&sealed).expect("sealed bytes"),
        to_sjs_rcx_request_machine_form(&expected).expect("expected bytes")
    );
}

#[test]
fn supplied_unobserved_input_class_retains_same_provider_free_compilation() {
    let mut request = synthetic_sjs_rcx_request().expect("fixture");
    request.input_class = SjsRcxInputClass::SuppliedUnobservedRepositorySlice;
    let request = seal_sjs_rcx_request(request).expect("supplied slice");
    let verification =
        verify_sjs_rcx(&compile_sjs_rcx(&request).expect("compile")).expect("verification");
    assert_eq!(
        verification.input_class,
        SjsRcxInputClass::SuppliedUnobservedRepositorySlice
    );
    assert_eq!(verification.admitted_subset_count, 92);
}

#[test]
fn duplicate_element_candidate_and_semantic_identities_refuse() {
    for mutation in 0..3 {
        let mut request = synthetic_sjs_rcx_request().expect("fixture");
        match mutation {
            0 => request.records[1].element_id = request.records[0].element_id.clone(),
            1 => {
                request.records[1].candidate.candidate_id =
                    request.records[0].candidate.candidate_id.clone()
            }
            _ => {
                request.records[1].candidate.semantic_identity =
                    request.records[0].candidate.semantic_identity.clone()
            }
        }
        assert_refused(seal_sjs_rcx_request(request));
    }
}

#[test]
fn conflicting_locator_content_identity_refuses() {
    let mut request = synthetic_sjs_rcx_request().expect("fixture");
    request.records[1].locator = request.records[0].locator.clone();
    request.records[1].candidate.source_binding.locator = request.records[0].locator.clone();
    assert_ne!(
        request.records[1].content_digest,
        request.records[0].content_digest
    );
    let error = seal_sjs_rcx_request(request).expect_err("conflict");
    assert_eq!(error.code, SjsRcxFaultCode::InvalidLocator);
}

#[test]
fn invalid_and_uppercase_content_or_commit_digests_refuse() {
    let mut record = synthetic_sjs_rcx_request().expect("fixture");
    record.records[0].content_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "A".repeat(64),
    };
    assert_refused(seal_sjs_rcx_request(record));

    let mut commit = synthetic_sjs_rcx_request().expect("fixture");
    commit.scope.commit_digest.value.pop();
    assert_refused(seal_sjs_rcx_request(commit));
}

#[test]
fn absolute_drive_unc_backslash_traversal_device_stream_and_nul_locators_refuse() {
    for locator in [
        "/root/file.sop",
        "C:/Project/file.sop",
        "//server/share/file.sop",
        "folder\\file.sop",
        "folder/../file.sop",
        "folder/./file.sop",
        "folder//file.sop",
        "folder/con.txt",
        "folder/COM1",
        "folder/file:stream",
        "folder/file\0name",
    ] {
        let mut request = synthetic_sjs_rcx_request().expect("fixture");
        request.records[0].locator = locator.to_owned();
        request.records[0].candidate.source_binding.locator = locator.to_owned();
        assert_refused(seal_sjs_rcx_request(request));
    }
}

#[test]
fn projected_byte_and_metric_tamper_refuse() {
    let mut projected = synthetic_sjs_rcx_request().expect("fixture");
    projected.records[0].candidate.projected_bytes += 1;
    assert_refused(seal_sjs_rcx_request(projected));

    let mut metric = synthetic_sjs_rcx_request().expect("fixture");
    metric.records[0].candidate.metrics.decision_relevance += 1;
    assert_refused(validate_sjs_rcx_request(&metric));
}

#[test]
fn nonauthority_promotion_to_mandatory_coverage_refuses_preflight() {
    let mut request = synthetic_sjs_rcx_request().expect("fixture");
    let nonauthority_id = request.records[2].candidate.candidate_id.clone();
    let mandatory_id = request.obligations[0].obligation_id.clone();
    let edge = request
        .coverage_edges
        .iter_mut()
        .find(|edge| edge.candidate_id == nonauthority_id)
        .expect("nonauthority edge");
    edge.obligation_id = mandatory_id;
    let error = seal_sjs_rcx_request(request).expect_err("promotion");
    assert_eq!(error.code, SjsRcxFaultCode::InvalidAuthority);
}

#[test]
fn governing_class_with_nongoverning_element_kind_cannot_cover_mandatory() {
    let mut request = synthetic_sjs_rcx_request().expect("fixture");
    request.records[0].element_kind = SjsRcxElementKind::FileCoordinate;
    assert_refused(seal_sjs_rcx_request(request));
}

#[test]
fn dangling_edge_unknown_source_and_unreferenced_candidate_refuse() {
    let mut dangling = synthetic_sjs_rcx_request().expect("fixture");
    dangling.coverage_edges[0].candidate_id = id("candidate:84000000-0000-4000-8009-000000000001");
    assert_refused(seal_sjs_rcx_request(dangling));

    let mut source = synthetic_sjs_rcx_request().expect("fixture");
    source.records[0].candidate.source_binding.source_id =
        id("source:84000000-0000-4000-8009-000000000001");
    assert_refused(seal_sjs_rcx_request(source));

    let mut unreferenced = synthetic_sjs_rcx_request().expect("fixture");
    let candidate_id = unreferenced.records[7].candidate.candidate_id.clone();
    unreferenced
        .coverage_edges
        .retain(|edge| edge.candidate_id != candidate_id);
    assert_refused(seal_sjs_rcx_request(unreferenced));
}

#[test]
fn coverage_request_envelope_and_downstream_tamper_refuse() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let mut coverage = request.clone();
    coverage.coverage_edges[0].obligation_id = coverage.obligations[1].obligation_id.clone();
    assert_refused(validate_sjs_rcx_request(&coverage));

    let mut request_tamper = request.clone();
    request_tamper.scope.branch.push_str("-tamper");
    assert_refused(validate_sjs_rcx_request(&request_tamper));

    let envelope = compile_sjs_rcx(&request).expect("compile");
    let mut envelope_tamper = envelope.clone();
    envelope_tamper.receipt.admitted_record_count -= 1;
    assert_refused(validate_sjs_rcx_envelope(&envelope_tamper));

    let mut downstream = envelope;
    downstream.downstream_envelope.selected_candidates.pop();
    assert_refused(validate_sjs_rcx_envelope(&downstream));
}

#[test]
fn request_and_envelope_machine_forms_are_strict_canonical_json() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let request_json = to_sjs_rcx_request_machine_form(&request).expect("request JSON");
    assert_eq!(
        from_sjs_rcx_request_machine_form(&request_json).expect("request parse"),
        request
    );
    let duplicate = request_json.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert_refused(from_sjs_rcx_request_machine_form(&duplicate));
    assert_refused(from_sjs_rcx_request_machine_form(&format!(
        " {request_json}"
    )));
    assert_refused(from_sjs_rcx_request_machine_form(&format!(
        "{request_json}x"
    )));
    let unknown = request_json.replacen("{", "{\"unknown\":0,", 1);
    assert_refused(from_sjs_rcx_request_machine_form(&unknown));

    let envelope = compile_sjs_rcx(&request).expect("compile");
    let envelope_json = to_sjs_rcx_envelope_machine_form(&envelope).expect("envelope JSON");
    assert_eq!(
        from_sjs_rcx_envelope_machine_form(&envelope_json).expect("envelope parse"),
        envelope
    );
}

#[test]
fn over_depth_over_field_and_oversized_machine_forms_refuse() {
    let deep = format!("{}0{}", "[".repeat(41), "]".repeat(41));
    assert_refused(from_sjs_rcx_request_machine_form(&deep));
    let fields = (0..16_385)
        .map(|index| format!("\"f{index}\":0"))
        .collect::<Vec<_>>()
        .join(",");
    assert_refused(from_sjs_rcx_request_machine_form(&format!("{{{fields}}}")));
    let oversized = "x".repeat(cantor_core::SJS_RCX_MAX_MACHINE_FORM_BYTES + 1);
    assert_refused(from_sjs_rcx_request_machine_form(&oversized));
}

#[test]
fn four_file_evidence_is_lf_canonical_and_exactly_replayable() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let first = build_sjs_rcx_evidence_bundle(&request).expect("first bundle");
    let second = build_sjs_rcx_evidence_bundle(&request).expect("second bundle");
    assert_eq!(first, second);
    for body in [
        &first.request_file,
        &first.envelope_file,
        &first.verification_file,
        &first.manifest_file,
    ] {
        assert!(body.ends_with('\n'));
        assert!(!body[..body.len() - 1].contains('\n'));
    }
    let verification = verify_sjs_rcx_evidence_bundle(&first).expect("independent replay");
    assert_eq!(verification.record_count, 8);
    let machine = to_sjs_rcx_evidence_bundle_machine_form(&first).expect("bundle machine form");
    assert_eq!(
        from_sjs_rcx_evidence_bundle_machine_form(&machine).expect("bundle parse"),
        first
    );
}

#[test]
fn raw_evidence_and_manifest_tamper_refuse() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let bundle = build_sjs_rcx_evidence_bundle(&request).expect("bundle");
    let mut raw = bundle.clone();
    raw.request_file = raw.request_file.replacen(
        "codex/self-hosted-corpus",
        "codex/self-hosted-corpus-tamper",
        1,
    );
    assert_refused(verify_sjs_rcx_evidence_bundle(&raw));

    let mut manifest = bundle;
    manifest.manifest_file =
        manifest
            .manifest_file
            .replacen("\"replay_count\":2", "\"replay_count\":1", 1);
    assert_refused(verify_sjs_rcx_evidence_bundle(&manifest));
}

#[test]
fn source_class_set_is_not_broadened_by_extraction() {
    let request = synthetic_sjs_rcx_request().expect("fixture");
    let classes = request
        .records
        .iter()
        .map(|record| record.candidate.source_binding.class)
        .collect::<Vec<_>>();
    assert!(classes.contains(&SjsLasSourceBindingClass::GoverningAnchor));
    assert!(classes.contains(&SjsLasSourceBindingClass::PlanHint));
    assert!(classes.contains(&SjsLasSourceBindingClass::ObservedCoordinate));
    assert!(classes.contains(&SjsLasSourceBindingClass::NonauthorityEvidence));
}

#[test]
fn duplicate_coverage_coordinate_refuses_even_with_distinct_relation_identity() {
    let mut request = synthetic_sjs_rcx_request().expect("fixture");
    let original = request.coverage_edges[0].clone();
    request.coverage_edges[1] = SjsLtoCoverageEdge {
        relation_id: id("relation:84000000-0000-4000-8009-000000000001"),
        candidate_id: original.candidate_id,
        obligation_id: original.obligation_id,
    };
    assert_refused(seal_sjs_rcx_request(request));
}
