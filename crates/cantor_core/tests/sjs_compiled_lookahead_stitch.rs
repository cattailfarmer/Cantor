use cantor_core::{
    SemanticId, SjsLasBoundaryKind, SjsLasFaultCode, SjsLasInputClass, SjsLasLifecycleState,
    SjsLasObservationKind, SjsLasSourceBindingClass, SjsLasTransitionDisposition,
    build_sjs_las_evidence_bundle, compile_sjs_las, from_sjs_las_envelope_machine_form,
    from_sjs_las_request_machine_form, seal_sjs_las_request, synthetic_sjs_las_request,
    to_sjs_las_envelope_machine_form, to_sjs_las_request_machine_form, verify_sjs_las,
    verify_sjs_las_evidence_bundle,
};

fn supplied(mut request: cantor_core::SjsLasRequest, suffix: &str) -> cantor_core::SjsLasRequest {
    request.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    request.request_id = SemanticId::new(format!("request:{suffix}")).unwrap();
    seal_sjs_las_request(request).unwrap()
}

#[test]
fn fixture_compiles_exact_lifecycle_and_projection_counts() {
    let request = synthetic_sjs_las_request().unwrap();
    let envelope = compile_sjs_las(&request).unwrap();
    let verification = verify_sjs_las(&envelope).unwrap();
    assert_eq!(verification.stitch_count, 2);
    assert_eq!(verification.hint_count, 8);
    assert_eq!(verification.source_binding_count, 4);
    assert_eq!(verification.observation_count, 6);
    assert_eq!(verification.coordinate_count, 4);
    assert_eq!(verification.projection_count, 4);
    assert_eq!(verification.projected_inclusion_count, 5);
    assert_eq!(verification.activation_count, 2);
    assert_eq!(verification.fulfillment_count, 1);
    assert_eq!(verification.invalidation_count, 1);
    assert_eq!(verification.release_count, 0);
    assert_eq!(verification.refused_transition_count, 0);
    assert_eq!(verification.initial_boundary_count, 1);
    assert_eq!(verification.stop_boundary_count, 1);
    assert_eq!(verification.tool_result_boundary_count, 1);
    assert_eq!(verification.reentry_boundary_count, 1);
    assert_eq!(
        envelope
            .projection_records
            .iter()
            .map(|record| record.active_stitch_ids.len())
            .collect::<Vec<_>>(),
        vec![2, 2, 1, 0]
    );
    assert_eq!(
        envelope.final_states[0].state,
        SjsLasLifecycleState::Fulfilled
    );
    assert_eq!(
        envelope.final_states[1].state,
        SjsLasLifecycleState::Invalidated
    );
    assert!(!verification.execution_authorized);
    assert_eq!(verification.effects, Default::default());
}

#[test]
fn request_and_envelope_round_trip_canonical_bytes() {
    let request = synthetic_sjs_las_request().unwrap();
    let request_bytes = to_sjs_las_request_machine_form(&request).unwrap();
    assert_eq!(
        from_sjs_las_request_machine_form(&request_bytes).unwrap(),
        request
    );
    let envelope = compile_sjs_las(&request).unwrap();
    let envelope_bytes = to_sjs_las_envelope_machine_form(&envelope).unwrap();
    assert_eq!(
        from_sjs_las_envelope_machine_form(&envelope_bytes).unwrap(),
        envelope
    );
}

#[test]
fn evidence_double_replay_is_byte_deterministic() {
    let request = synthetic_sjs_las_request().unwrap();
    let first = build_sjs_las_evidence_bundle(&request).unwrap();
    let second = build_sjs_las_evidence_bundle(&request).unwrap();
    assert_eq!(first, second);
    let verification = verify_sjs_las_evidence_bundle(&first).unwrap();
    assert_eq!(verification.projected_inclusion_count, 5);
}

#[test]
fn unknown_duplicate_noncanonical_and_trailing_request_bytes_refuse() {
    let request = synthetic_sjs_las_request().unwrap();
    let machine = to_sjs_las_request_machine_form(&request).unwrap();
    let unknown = machine.replacen('{', "{\"unknown\":0,", 1);
    assert_eq!(
        from_sjs_las_request_machine_form(&unknown)
            .unwrap_err()
            .code,
        SjsLasFaultCode::InvalidMachineForm
    );
    let duplicate = machine.replacen(
        "{\"profile\":",
        "{\"profile\":\"cantor-sjs-compiled-lookahead-stitch-request/0.1\",\"profile\":",
        1,
    );
    assert_eq!(
        from_sjs_las_request_machine_form(&duplicate)
            .unwrap_err()
            .code,
        SjsLasFaultCode::InvalidMachineForm
    );
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(&machine).unwrap())
            .unwrap();
    assert_eq!(
        from_sjs_las_request_machine_form(&pretty).unwrap_err().code,
        SjsLasFaultCode::InvalidMachineForm
    );
    assert_eq!(
        from_sjs_las_request_machine_form(&(machine + " "))
            .unwrap_err()
            .code,
        SjsLasFaultCode::InvalidMachineForm
    );
}

#[test]
fn stale_request_digest_refuses() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.scope.objective.push_str(" drift");
    assert_eq!(
        compile_sjs_las(&request).unwrap_err().code,
        SjsLasFaultCode::InvalidDigest
    );
}

#[test]
fn raw_evidence_byte_tamper_refuses() {
    let request = synthetic_sjs_las_request().unwrap();
    let mut bundle = build_sjs_las_evidence_bundle(&request).unwrap();
    bundle.request_file = bundle.request_file.replacen(
        "lightweight scope-persistent",
        "lightweighx scope-persistent",
        1,
    );
    assert_eq!(
        verify_sjs_las_evidence_bundle(&bundle).unwrap_err().code,
        SjsLasFaultCode::InvalidEvidence
    );
}

#[test]
fn fully_redigested_synthetic_semantic_tamper_refuses() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.stitches[0].subject_anchor = "tampered lookahead subject".to_owned();
    assert_eq!(
        seal_sjs_las_request(request).unwrap_err().code,
        SjsLasFaultCode::InvalidInputClass
    );
}

#[test]
fn known_fixture_cannot_be_relabeled() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    assert_eq!(
        seal_sjs_las_request(request).unwrap_err().code,
        SjsLasFaultCode::InvalidInputClass
    );
}

#[test]
fn nonauthority_source_cannot_carry_imported_authority() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    request.request_id = SemanticId::new("request:83000000-0000-4000-8000-000000000001").unwrap();
    assert_eq!(
        request.stitches[0].source_bindings[1].class,
        SjsLasSourceBindingClass::PlanHint
    );
    request.stitches[0].source_bindings[1].authority_identity =
        Some("laundered-authority".to_owned());
    assert_eq!(
        seal_sjs_las_request(request).unwrap_err().code,
        SjsLasFaultCode::InvalidAuthority
    );
}

#[test]
fn duplicate_hint_and_overbound_stitch_count_refuse() {
    let mut duplicate = synthetic_sjs_las_request().unwrap();
    duplicate.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    duplicate.request_id = SemanticId::new("request:83000000-0000-4000-8000-000000000002").unwrap();
    duplicate.stitches[0].key_hints[1] = duplicate.stitches[0].key_hints[0].clone();
    assert_eq!(
        seal_sjs_las_request(duplicate).unwrap_err().code,
        SjsLasFaultCode::InvalidStitch
    );

    let mut overbound = synthetic_sjs_las_request().unwrap();
    overbound.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
    overbound.request_id = SemanticId::new("request:83000000-0000-4000-8000-000000000003").unwrap();
    for ordinal in 1..=7 {
        let mut additional = overbound.stitches[1].clone();
        additional.stitch_id =
            SemanticId::new(format!("stitch:83000000-0000-4000-8000-{ordinal:012}")).unwrap();
        overbound.stitches.push(additional);
    }
    assert_eq!(
        seal_sjs_las_request(overbound).unwrap_err().code,
        SjsLasFaultCode::InvalidStitch
    );
}

#[test]
fn coordinate_provider_tool_authority_interval_and_receipt_drift_refuse() {
    for (index, mutation) in ["provider", "tool", "authority", "interval", "receipt"]
        .into_iter()
        .enumerate()
    {
        let mut request = synthetic_sjs_las_request().unwrap();
        request.input_class = SjsLasInputClass::SuppliedUnobservedDeclaration;
        request.request_id =
            SemanticId::new(format!("request:83000000-0000-4000-8000-{index:012}")).unwrap();
        match mutation {
            "provider" => request.coordinates[0].provider_profile.push_str("-drift"),
            "tool" => request.coordinates[0].tool_policy.push_str("-drift"),
            "authority" => request.coordinates[0].authority_ceiling.push_str("-drift"),
            "interval" => request.coordinates[0].invocation_ordinal = 99,
            _ => {
                request.coordinates[0].last_accepted_receipt_id =
                    Some(SemanticId::new("receipt:83000000-0000-4000-8000-000000000999").unwrap())
            }
        }
        assert_eq!(
            seal_sjs_las_request(request).unwrap_err().code,
            SjsLasFaultCode::InvalidCoordinate
        );
    }
}

#[test]
fn replacement_before_predecessor_terminal_is_witnessed_refusal() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.stitches[1].predecessor_id = Some(request.stitches[0].stitch_id.clone());
    let request = supplied(request, "83000000-0000-4000-8000-000000000010");
    let verification = verify_sjs_las(&compile_sjs_las(&request).unwrap()).unwrap();
    assert_eq!(verification.activation_count, 1);
    assert_eq!(verification.refused_transition_count, 1);
}

#[test]
fn invalidator_has_precedence_over_completion() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.stitches[0].invalidators = vec![request.stitches[0].completion_cue.clone()];
    let request = supplied(request, "83000000-0000-4000-8000-000000000011");
    let envelope = compile_sjs_las(&request).unwrap();
    assert_eq!(
        envelope.final_states[0].state,
        SjsLasLifecycleState::Invalidated
    );
    let receipt = envelope
        .lifecycle_receipts
        .iter()
        .find(|r| r.observation_id.as_str().ends_with("104"))
        .unwrap();
    assert_eq!(receipt.reason, "invalidation_precedence_admitted");
}

#[test]
fn scope_exit_releases_active_stitch() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.observations[5].fields.clear();
    request.observations[5]
        .fields
        .insert("scope_state".to_owned(), "exited".to_owned());
    let request = supplied(request, "83000000-0000-4000-8000-000000000012");
    let verification = verify_sjs_las(&compile_sjs_las(&request).unwrap()).unwrap();
    assert_eq!(verification.release_count, 1);
    assert_eq!(verification.invalidation_count, 0);
}

#[test]
fn terminal_or_already_active_reactivation_is_refused() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.observations[5].kind = SjsLasObservationKind::Activate;
    request.observations[5].fields.clear();
    let request = supplied(request, "83000000-0000-4000-8000-000000000013");
    let envelope = compile_sjs_las(&request).unwrap();
    let last = envelope.lifecycle_receipts.last().unwrap();
    assert_eq!(
        last.disposition,
        SjsLasTransitionDisposition::TransitionRefused
    );
    assert_eq!(last.reason, "only_proposed_may_activate");
}

#[test]
fn unmatched_signal_is_witnessed_without_state_change() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.observations[5].fields.clear();
    request.observations[5]
        .fields
        .insert("unrelated".to_owned(), "value".to_owned());
    let request = supplied(request, "83000000-0000-4000-8000-000000000014");
    let envelope = compile_sjs_las(&request).unwrap();
    assert_eq!(envelope.final_states[1].state, SjsLasLifecycleState::Active);
    assert_eq!(
        envelope.lifecycle_receipts.last().unwrap().disposition,
        SjsLasTransitionDisposition::TransitionRefused
    );
    assert_eq!(
        envelope
            .projection_records
            .last()
            .unwrap()
            .active_stitch_ids
            .len(),
        1
    );
}

#[test]
fn projected_byte_budget_refuses_without_partial_envelope() {
    let mut request = synthetic_sjs_las_request().unwrap();
    request.stitches[0].key_hints = (0..8)
        .map(|index| format!("{index}-{}", "x".repeat(2000)))
        .collect();
    let request = supplied(request, "83000000-0000-4000-8000-000000000015");
    assert_eq!(
        compile_sjs_las(&request).unwrap_err().code,
        SjsLasFaultCode::InvalidBound
    );
}

#[test]
fn envelope_effect_and_projection_tamper_refuse() {
    let request = synthetic_sjs_las_request().unwrap();
    let mut effect = compile_sjs_las(&request).unwrap();
    effect.effects.provider_effect_count = 1;
    assert_eq!(
        verify_sjs_las(&effect).unwrap_err().code,
        SjsLasFaultCode::InvalidAuthority
    );

    let mut projection = compile_sjs_las(&request).unwrap();
    projection.projection_records[0].active_stitch_ids.clear();
    assert_eq!(
        verify_sjs_las(&projection).unwrap_err().code,
        SjsLasFaultCode::InvalidProjection
    );
}

#[test]
fn all_four_boundary_kinds_are_retained_in_order() {
    let envelope = compile_sjs_las(&synthetic_sjs_las_request().unwrap()).unwrap();
    assert_eq!(
        envelope
            .projection_records
            .iter()
            .map(|record| record.coordinate.boundary_kind)
            .collect::<Vec<_>>(),
        vec![
            SjsLasBoundaryKind::Initial,
            SjsLasBoundaryKind::ResumeAfterStop,
            SjsLasBoundaryKind::ResumeAfterToolResult,
            SjsLasBoundaryKind::Reentry
        ]
    );
}
