use cantor_core::{
    SemanticId, SjsLasSourceBindingClass, SjsLtoCandidateDisposition, SjsLtoCoverageEdge,
    SjsLtoFaultCode, SjsLtoInputClass, SjsLtoResultStatus, build_sjs_lto_evidence_bundle,
    from_sjs_lto_evidence_bundle_machine_form, from_sjs_lto_request_machine_form, optimize_sjs_lto,
    seal_sjs_lto_request, synthetic_sjs_lto_request, to_sjs_lto_envelope_machine_form,
    to_sjs_lto_evidence_bundle_machine_form, to_sjs_lto_request_machine_form,
    validate_sjs_lto_envelope, validate_sjs_lto_request, verify_sjs_lto,
    verify_sjs_lto_evidence_bundle,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test identity")
}

#[test]
fn fixture_selects_unique_exact_pool_optimum_and_complete_accounts() {
    let request = synthetic_sjs_lto_request().expect("fixture");
    let envelope = optimize_sjs_lto(&request).expect("optimization");
    let verification = verify_sjs_lto(&envelope).expect("verification");

    assert_eq!(envelope.receipt.status, SjsLtoResultStatus::SelectedExact);
    assert_eq!(envelope.receipt.admitted_subset_count, 92);
    assert_eq!(envelope.selected_candidates.len(), 3);
    assert_eq!(envelope.receipt.candidate_accounts.len(), 8);
    assert!(envelope.receipt.uncovered_accounts.is_empty());
    assert_eq!(verification.candidate_count, 8);
    assert_eq!(verification.obligation_count, 6);
    assert_eq!(verification.coverage_edge_count, 12);
    assert_eq!(verification.rejected_count, 5);
    assert_eq!(verification.dominated_count, 1);
    assert_eq!(verification.uncovered_count, 0);
    assert!(!verification.execution_authorized);
}

#[test]
fn selected_order_is_governing_then_plan_and_not_score_order() {
    let envelope =
        optimize_sjs_lto(&synthetic_sjs_lto_request().expect("fixture")).expect("optimization");
    let selected = envelope
        .selected_candidates
        .iter()
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        selected,
        vec![
            "candidate:83000000-0000-4000-8001-000000000001",
            "candidate:83000000-0000-4000-8001-000000000002",
            "candidate:83000000-0000-4000-8001-000000000003",
        ]
    );
}

#[test]
fn dominated_candidate_is_retained_with_comparator() {
    let envelope =
        optimize_sjs_lto(&synthetic_sjs_lto_request().expect("fixture")).expect("optimization");
    let dominated = envelope
        .receipt
        .candidate_accounts
        .iter()
        .find(|account| account.disposition == SjsLtoCandidateDisposition::Dominated)
        .expect("one dominated account");
    assert_eq!(
        dominated.candidate_id.as_str(),
        "candidate:83000000-0000-4000-8001-000000000004"
    );
    assert_eq!(
        dominated
            .comparator_id
            .as_ref()
            .expect("comparator")
            .as_str(),
        "candidate:83000000-0000-4000-8001-000000000001"
    );
}

#[test]
fn canonical_set_permutations_seal_to_identical_bytes() {
    let expected = synthetic_sjs_lto_request().expect("fixture");
    let mut permuted = expected.clone();
    permuted.candidates.reverse();
    permuted.obligations.reverse();
    permuted.coverage_edges.reverse();
    let resealed = seal_sjs_lto_request(permuted).expect("reseal");
    assert_eq!(resealed, expected);
    assert_eq!(
        to_sjs_lto_request_machine_form(&resealed).expect("machine form"),
        to_sjs_lto_request_machine_form(&expected).expect("machine form")
    );
}

#[test]
fn insufficient_budget_retains_best_partial_and_uncovered() {
    let mut request = synthetic_sjs_lto_request().expect("fixture");
    request.input_class = SjsLtoInputClass::SuppliedUnobservedCandidatePool;
    request.policy.maximum_selected_count = 2;
    let request = seal_sjs_lto_request(request).expect("reseal");
    let envelope = optimize_sjs_lto(&request).expect("bounded failure envelope");
    assert_eq!(
        envelope.receipt.status,
        SjsLtoResultStatus::InsufficientBudget
    );
    assert!(envelope.selected_candidates.is_empty());
    assert!(!envelope.receipt.best_partial_candidate_ids.is_empty());
    assert_eq!(envelope.receipt.uncovered_accounts.len(), 6);
}

#[test]
fn uncoverable_mandatory_is_explicit_and_authorizes_no_set() {
    let mut request = synthetic_sjs_lto_request().expect("fixture");
    request.input_class = SjsLtoInputClass::SuppliedUnobservedCandidatePool;
    let mandatory = request.obligations[1].obligation_id.clone();
    request
        .coverage_edges
        .retain(|edge| edge.obligation_id != mandatory);
    let request = seal_sjs_lto_request(request).expect("reseal");
    let envelope = optimize_sjs_lto(&request).expect("uncoverable envelope");
    assert_eq!(
        envelope.receipt.status,
        SjsLtoResultStatus::UncoverableMandatory
    );
    assert!(envelope.selected_candidates.is_empty());
    assert!(
        envelope
            .receipt
            .uncovered_accounts
            .iter()
            .any(|account| account.obligation_id == mandatory && account.mandatory)
    );
}

#[test]
fn nonauthority_candidate_cannot_cover_mandatory_obligation() {
    let mut request = synthetic_sjs_lto_request().expect("fixture");
    request.input_class = SjsLtoInputClass::SuppliedUnobservedCandidatePool;
    let mandatory = request.obligations[1].obligation_id.clone();
    let nonauthority = request
        .candidates
        .iter()
        .find(|candidate| {
            candidate.source_binding.class == SjsLasSourceBindingClass::NonauthorityEvidence
        })
        .expect("nonauthority candidate")
        .candidate_id
        .clone();
    request
        .coverage_edges
        .retain(|edge| edge.obligation_id != mandatory);
    request.coverage_edges.push(SjsLtoCoverageEdge {
        relation_id: id("relation:83000000-0000-4000-8002-000000000099"),
        candidate_id: nonauthority,
        obligation_id: mandatory,
    });
    let fault = seal_sjs_lto_request(request).expect_err("authority promotion must fail");
    assert_eq!(fault.code, SjsLtoFaultCode::InvalidAuthority);
}

#[test]
fn request_semantic_or_digest_tamper_refuses() {
    let mut request = synthetic_sjs_lto_request().expect("fixture");
    request.candidates[0].projected_surface = "tampered".to_owned();
    let fault = validate_sjs_lto_request(&request).expect_err("tamper must fail");
    assert!(matches!(
        fault.code,
        SjsLtoFaultCode::InvalidCandidate | SjsLtoFaultCode::InvalidDigest
    ));

    let mut digest_tamper = synthetic_sjs_lto_request().expect("fixture");
    digest_tamper.request_digest.value.replace_range(0..1, "f");
    assert_eq!(
        validate_sjs_lto_request(&digest_tamper)
            .expect_err("digest tamper")
            .code,
        SjsLtoFaultCode::InvalidDigest
    );
}

#[test]
fn duplicate_unknown_noncanonical_and_trailing_request_bytes_refuse() {
    let request = synthetic_sjs_lto_request().expect("fixture");
    let form = to_sjs_lto_request_machine_form(&request).expect("form");
    let duplicate = format!("{{\"profile\":\"duplicate\",{}", &form[1..]);
    let unknown = format!("{{\"unknown\":0,{}", &form[1..]);
    let noncanonical = format!(" {form}");
    for value in [duplicate, unknown, noncanonical, format!("{form}\n")] {
        assert!(from_sjs_lto_request_machine_form(&value).is_err());
    }
}

#[test]
fn envelope_tamper_and_double_replay_refuse_or_match_exactly() {
    let request = synthetic_sjs_lto_request().expect("fixture");
    let envelope = optimize_sjs_lto(&request).expect("optimization");
    let first = to_sjs_lto_envelope_machine_form(&envelope).expect("form");
    let second =
        to_sjs_lto_envelope_machine_form(&optimize_sjs_lto(&request).expect("second optimization"))
            .expect("form");
    assert_eq!(first, second);

    let mut tampered = envelope;
    tampered.selected_candidates.pop();
    assert!(validate_sjs_lto_envelope(&tampered).is_err());
}

#[test]
fn maximum_sixteen_candidate_search_is_exactly_bounded_and_seventeen_refuses() {
    let mut request = synthetic_sjs_lto_request().expect("fixture");
    request.input_class = SjsLtoInputClass::SuppliedUnobservedCandidatePool;
    request.policy.maximum_selected_count = 8;
    let originals = request.candidates.clone();
    let original_edges = request.coverage_edges.clone();
    let mut clones = Vec::new();
    for (index, original) in originals.iter().enumerate() {
        let mut clone = original.clone();
        clone.candidate_id = id(&format!(
            "candidate:83000000-0000-4000-8001-{:012}",
            101 + index
        ));
        clone.semantic_identity = format!("maximum-bound clone {}", index + 1);
        clones.push(clone);
    }
    for (index, edge) in original_edges.iter().enumerate() {
        let original_index = originals
            .iter()
            .position(|candidate| candidate.candidate_id == edge.candidate_id)
            .expect("original candidate");
        request.coverage_edges.push(SjsLtoCoverageEdge {
            relation_id: id(&format!(
                "relation:83000000-0000-4000-8002-{:012}",
                101 + index
            )),
            candidate_id: clones[original_index].candidate_id.clone(),
            obligation_id: edge.obligation_id.clone(),
        });
    }
    request.candidates.extend(clones);
    let request = seal_sjs_lto_request(request).expect("maximum request");
    let envelope = optimize_sjs_lto(&request).expect("maximum exact search");
    assert_eq!(envelope.receipt.admitted_subset_count, 39_202);
    assert_eq!(envelope.receipt.status, SjsLtoResultStatus::SelectedExact);

    let mut overbound = request;
    let mut seventeenth = overbound.candidates[0].clone();
    seventeenth.candidate_id = id("candidate:83000000-0000-4000-8001-000000000201");
    seventeenth.semantic_identity = "seventeenth overbound candidate".to_owned();
    overbound.candidates.push(seventeenth);
    assert_eq!(
        seal_sjs_lto_request(overbound)
            .expect_err("seventeen candidates must fail")
            .code,
        SjsLtoFaultCode::InvalidBound
    );
}

#[test]
fn evidence_bundle_round_trip_is_byte_deterministic_and_independently_verified() {
    let request = synthetic_sjs_lto_request().expect("fixture");
    let first = build_sjs_lto_evidence_bundle(&request).expect("bundle");
    let second = build_sjs_lto_evidence_bundle(&request).expect("bundle replay");
    assert_eq!(first, second);
    let form = to_sjs_lto_evidence_bundle_machine_form(&first).expect("bundle form");
    let parsed = from_sjs_lto_evidence_bundle_machine_form(&form).expect("bundle parse");
    assert_eq!(parsed, first);
    let verification = verify_sjs_lto_evidence_bundle(&parsed).expect("bundle verification");
    assert_eq!(verification.admitted_subset_count, 92);
    assert_eq!(verification.selected_count, 3);
    assert_eq!(verification.dominated_count, 1);
}

#[test]
fn raw_evidence_file_or_manifest_tamper_refuses() {
    let request = synthetic_sjs_lto_request().expect("fixture");
    let mut file_tamper = build_sjs_lto_evidence_bundle(&request).expect("bundle");
    file_tamper.request_file.replace_range(0..1, "[");
    assert!(verify_sjs_lto_evidence_bundle(&file_tamper).is_err());

    let mut manifest_tamper = build_sjs_lto_evidence_bundle(&request).expect("bundle");
    let digest_at = manifest_tamper
        .manifest_file
        .find("sha256")
        .expect("manifest digest field");
    manifest_tamper
        .manifest_file
        .replace_range(digest_at..digest_at + 1, "S");
    assert!(verify_sjs_lto_evidence_bundle(&manifest_tamper).is_err());
}
