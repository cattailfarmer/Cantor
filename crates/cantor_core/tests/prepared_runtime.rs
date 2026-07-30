mod common;

use std::{
    sync::{Arc, Barrier},
    thread,
};

use cantor_core::{
    ContentDigest, ExitClass, InspectRequest, PreparedRuntime, PreparedRuntimeSlot,
    ProtocolOperation, ProtocolOutcome, ProtocolStatus, RuntimeTransitionDisposition,
    embedded_environment_digest, execute_protocol_request, verify_protocol_response,
    verify_protocol_response_against_environment,
};

use common::{id, protocol_fixture, query_request};

fn assert_exact_equivalence(
    environment: &cantor_core::EmbeddedRuntimeEnvironment,
    request: &cantor_core::ProtocolRequest,
    runtime: &PreparedRuntime,
) {
    let direct = execute_protocol_request(environment, request.clone());
    let prepared = runtime.execute(request.clone());
    assert_eq!(prepared, direct);
    assert_eq!(
        serde_json::to_vec(&prepared).expect("prepared response must encode"),
        serde_json::to_vec(&direct).expect("direct response must encode")
    );
    if request.expected_environment_digest
        == embedded_environment_digest(environment).expect("fixture environment must encode")
    {
        verify_protocol_response(request, &prepared).expect("prepared response must verify");
        verify_protocol_response_against_environment(environment, request, &prepared)
            .expect("prepared response must verify against its environment");
    }
}

#[test]
fn direct_and_prepared_paths_are_exact_across_success_partial_and_request_faults() {
    let (environment, base) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    let runtime = PreparedRuntime::new(environment.clone()).expect("runtime must construct");

    let mut cases = vec![base.clone()];

    let mut unresolved = base.clone();
    unresolved.request = ProtocolOperation::Query {
        query: Box::new(query_request("unknown-term")),
    };
    cases.push(unresolved);

    let mut ambiguous_query = query_request("bank");
    ambiguous_query.subject = None;
    ambiguous_query.source_scopes.clear();
    let mut ambiguous = base.clone();
    ambiguous.request = ProtocolOperation::Query {
        query: Box::new(ambiguous_query),
    };
    cases.push(ambiguous);

    let mut budget = base.clone();
    if let ProtocolOperation::Query { query } = &mut budget.request {
        query.budget.maximum_records = 0;
    }
    cases.push(budget);

    let mut wrong_digest = base.clone();
    wrong_digest.expected_environment_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "00".repeat(32),
    };
    cases.push(wrong_digest);

    let mut wrong_protocol = base.clone();
    wrong_protocol.protocol_version = "cantor-protocol/999".to_owned();
    cases.push(wrong_protocol);

    let mut denied = base.clone();
    denied.caller_context.effect_boundary = "write".to_owned();
    cases.push(denied);

    let mut empty_expected = base.clone();
    empty_expected.expected_packages.clear();
    cases.push(empty_expected);

    let mut envelope_mismatch = base.clone();
    if let ProtocolOperation::Query { query } = &mut envelope_mismatch.request {
        query.purpose = "different purpose".to_owned();
    }
    cases.push(envelope_mismatch);

    let mut excessive_scope = base.clone();
    if let ProtocolOperation::Query { query } = &mut excessive_scope.request {
        query.authority_context.allowed_package_scopes =
            ["outside".to_owned()].into_iter().collect();
    }
    cases.push(excessive_scope);

    let inspect_targets = [
        InspectRequest::Fabric,
        InspectRequest::Package {
            package_id: environment.packages[0].package_id.clone(),
        },
        InspectRequest::Certificate {
            package_id: environment.packages[0].package_id.clone(),
        },
        InspectRequest::SemanticUnit {
            unit_id: id("unit:bank_financial"),
        },
        InspectRequest::SemanticUnit {
            unit_id: id("unit:unknown"),
        },
    ];
    for inspect in inspect_targets {
        let mut request = base.clone();
        request.request = ProtocolOperation::Inspect { inspect };
        cases.push(request);
    }

    for request in &cases {
        assert_exact_equivalence(&environment, request, &runtime);
    }
    let metrics = runtime.metrics();
    assert_eq!(metrics.projection_preparations, 1);
    assert!(metrics.projection_hits >= 1);
}

#[test]
fn invalid_trust_state_is_exact_and_never_becomes_a_projection() {
    let (mut environment, mut request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let certificate_id = environment.packages[0]
        .certificate
        .as_ref()
        .expect("fixture is signed")
        .certificate_id
        .clone();
    environment
        .trust_store
        .revoked_certificates
        .insert(certificate_id);
    request.expected_environment_digest =
        embedded_environment_digest(&environment).expect("revoked environment must encode");

    let direct = execute_protocol_request(&environment, request.clone());
    let runtime = PreparedRuntime::new(environment).expect("runtime identity must construct");
    let prepared = runtime.execute(request);
    assert_eq!(prepared, direct);
    assert_eq!(prepared.exit_class, ExitClass::TrustFailure);
    assert_eq!(runtime.metrics().projection_preparations, 0);
    assert_eq!(
        runtime.prepared_scope().expect("lock must be available"),
        None
    );
}

#[test]
fn structurally_different_scopes_replace_instead_of_reusing_projection() {
    let (environment, original) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let runtime = PreparedRuntime::new(environment.clone()).expect("runtime must construct");
    assert_exact_equivalence(&environment, &original, &runtime);

    let mut narrower = original.clone();
    narrower.requested_scope.perspectives.clear();
    assert_ne!(narrower.requested_scope, original.requested_scope);
    assert_exact_equivalence(&environment, &narrower, &runtime);
    assert_eq!(
        runtime.prepared_scope().expect("lock must be available"),
        Some(narrower.requested_scope.clone())
    );

    assert_exact_equivalence(&environment, &original, &runtime);
    let metrics = runtime.metrics();
    assert_eq!(metrics.projection_preparations, 3);
    assert_eq!(metrics.projection_replacements, 2);
}

#[test]
fn generation_identity_changes_with_trust_time_and_trust_store_content() {
    let (environment, _) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let base = PreparedRuntime::new(environment.clone()).expect("base runtime must construct");

    let mut later = environment.clone();
    later.now_epoch_seconds += 1;
    let later = PreparedRuntime::new(later).expect("later runtime must construct");
    assert_ne!(
        base.generation().generation_id,
        later.generation().generation_id
    );

    let mut revoked = environment;
    revoked
        .trust_store
        .revoked_packages
        .insert(revoked.packages[0].package_id.clone());
    let revoked = PreparedRuntime::new(revoked).expect("revoked identity must construct");
    assert_ne!(
        base.generation().generation_id,
        revoked.generation().generation_id
    );
}

#[test]
fn concurrent_reads_are_deterministic_and_share_one_complete_projection() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    let direct = execute_protocol_request(&environment, request.clone());
    let runtime = Arc::new(PreparedRuntime::new(environment).expect("runtime must construct"));
    let barrier = Arc::new(Barrier::new(17));
    let mut joins = Vec::new();
    for _ in 0..16 {
        let runtime = Arc::clone(&runtime);
        let barrier = Arc::clone(&barrier);
        let request = request.clone();
        joins.push(thread::spawn(move || {
            barrier.wait();
            runtime.execute(request)
        }));
    }
    barrier.wait();
    for join in joins {
        assert_eq!(join.join().expect("reader must finish"), direct);
    }
    assert_eq!(runtime.metrics().projection_preparations, 1);
}

#[test]
fn prepared_runtime_and_slot_are_send_sync_snapshot_types() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PreparedRuntime>();
    assert_send_sync::<PreparedRuntimeSlot>();
}

#[test]
fn concurrent_generation_replacement_exposes_only_complete_old_or_new_results() {
    let (old_environment, old_request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let old_runtime = PreparedRuntime::prepare(old_environment.clone(), &old_request)
        .expect("old runtime must prepare");
    let old_id = old_runtime.generation().generation_id.clone();

    let mut new_environment = old_environment.clone();
    new_environment.now_epoch_seconds += 1;
    let mut new_request = old_request.clone();
    new_request.expected_environment_digest =
        embedded_environment_digest(&new_environment).expect("new environment must encode");
    let new_runtime = PreparedRuntime::prepare(new_environment.clone(), &new_request)
        .expect("new runtime must prepare");

    let allowed_old_request = [
        execute_protocol_request(&old_environment, old_request.clone()),
        execute_protocol_request(&new_environment, old_request.clone()),
    ];
    let allowed_new_request = [
        execute_protocol_request(&old_environment, new_request.clone()),
        execute_protocol_request(&new_environment, new_request.clone()),
    ];

    let slot = Arc::new(PreparedRuntimeSlot::with_active(old_runtime));
    let barrier = Arc::new(Barrier::new(9));
    let mut joins = Vec::new();
    for ordinal in 0..8 {
        let slot = Arc::clone(&slot);
        let barrier = Arc::clone(&barrier);
        let request = if ordinal % 2 == 0 {
            old_request.clone()
        } else {
            new_request.clone()
        };
        joins.push(thread::spawn(move || {
            barrier.wait();
            (0..100)
                .map(|_| slot.execute(request.clone()))
                .collect::<Vec<_>>()
        }));
    }
    barrier.wait();
    let receipt = slot.replace(Some(&old_id), new_runtime);
    assert_eq!(receipt.disposition, RuntimeTransitionDisposition::Activated);

    for (ordinal, join) in joins.into_iter().enumerate() {
        for response in join.join().expect("generation reader must finish") {
            let response = response.expect("old or new generation must be available");
            let allowed = if ordinal % 2 == 0 {
                &allowed_old_request
            } else {
                &allowed_new_request
            };
            assert!(allowed.contains(&response));
        }
    }
}

#[test]
fn generation_slot_transitions_are_atomic_stale_safe_and_reversible() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let first = PreparedRuntime::prepare(environment.clone(), &request)
        .expect("first runtime must prepare");
    let first_id = first.generation().generation_id.clone();
    let slot = PreparedRuntimeSlot::with_active(first);

    let stale = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "11".repeat(32),
    };
    let rejected = slot.invalidate(Some(&stale));
    assert_eq!(
        rejected.disposition,
        RuntimeTransitionDisposition::RejectedStaleExpectation
    );
    assert_eq!(
        slot.active_generation().expect("slot must be readable"),
        Some(first_id.clone())
    );

    let mut next_environment = environment.clone();
    next_environment.now_epoch_seconds += 1;
    let mut next_request = request.clone();
    next_request.expected_environment_digest =
        embedded_environment_digest(&next_environment).expect("next environment must encode");
    let next = PreparedRuntime::prepare(next_environment.clone(), &next_request)
        .expect("next runtime must prepare");
    let next_id = next.generation().generation_id.clone();
    let replaced = slot.replace(Some(&first_id), next);
    assert_eq!(
        replaced.disposition,
        RuntimeTransitionDisposition::Activated
    );
    assert_eq!(
        slot.active_generation().expect("slot must be readable"),
        Some(next_id.clone())
    );
    assert_eq!(
        slot.execute(next_request.clone())
            .expect("slot must execute"),
        execute_protocol_request(&next_environment, next_request)
    );

    let invalidated = slot.invalidate(Some(&next_id));
    assert_eq!(
        invalidated.disposition,
        RuntimeTransitionDisposition::Invalidated
    );
    assert!(slot.execute(request.clone()).is_err());

    let prior =
        PreparedRuntime::prepare(environment.clone(), &request).expect("prior must reprepare");
    let rollback = slot.rollback(None, prior);
    assert_eq!(
        rollback.disposition,
        RuntimeTransitionDisposition::RolledBack
    );
    assert_eq!(
        slot.execute(request.clone())
            .expect("rollback must execute"),
        execute_protocol_request(&environment, request)
    );
}

#[test]
fn failed_demanded_security_replacement_deactivates_the_expected_generation() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let active =
        PreparedRuntime::prepare(environment.clone(), &request).expect("active must prepare");
    let active_id = active.generation().generation_id.clone();
    let slot = PreparedRuntimeSlot::with_active(active);

    let mut revoked = environment;
    revoked
        .trust_store
        .revoked_packages
        .insert(revoked.packages[0].package_id.clone());
    let mut revoked_request = request;
    revoked_request.expected_environment_digest =
        embedded_environment_digest(&revoked).expect("revoked environment must encode");

    let receipt = slot.replace_or_invalidate(Some(&active_id), revoked, &revoked_request);
    assert_eq!(
        receipt.disposition,
        RuntimeTransitionDisposition::InvalidatedAfterFailedReplacement
    );
    assert!(receipt.fault.is_some());
    assert_eq!(
        slot.active_generation().expect("slot must be readable"),
        None
    );
    assert!(slot.execute(revoked_request).is_err());
}

#[test]
fn prepared_success_partial_and_fault_shapes_remain_visible() {
    let (environment, mut request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("unknown-term")),
    });
    let runtime = PreparedRuntime::new(environment).expect("runtime must construct");
    let partial = runtime.execute(request.clone());
    assert_eq!(partial.status, ProtocolStatus::Partial);
    assert!(matches!(partial.result, ProtocolOutcome::Query(_)));

    request.expected_packages.clear();
    let fault = runtime.execute(request);
    assert_eq!(fault.status, ProtocolStatus::Fault);
    assert!(matches!(fault.result, ProtocolOutcome::Fault));
}
