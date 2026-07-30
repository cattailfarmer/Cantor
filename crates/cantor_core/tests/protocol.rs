mod common;

use std::collections::BTreeSet;

use cantor_core::{
    AuthorityContext, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION, EmbeddedRuntimeEnvironment,
    ExitClass, ExpectedPackage, InspectRequest, InspectResult, PROTOCOL_VERSION,
    ProtocolCallerContext, ProtocolContinuation, ProtocolOperation, ProtocolOutcome,
    ProtocolRequest, ProtocolResponse, ProtocolStatus, QUERY_PROTOCOL_VERSION, QueryBudget,
    RequestedDetailKind, SearchMode, SemanticFabric, admit_package, embedded_environment_digest,
    execute_protocol_request, execute_query, sha256_digest, verify_protocol_response,
    verify_protocol_response_against_environment,
};

use common::{NOW, compiler, id, package_input, scope, trust_store};

fn query_request(term: &str) -> CantorQueryRequest {
    CantorQueryRequest {
        protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
        request_id: id("request:protocol_fixture"),
        term_set: [term.to_owned()].into_iter().collect(),
        subject: Some("finance".to_owned()),
        purpose: "resolve the intended meaning".to_owned(),
        use_case_set: BTreeSet::new(),
        include_boundary_set: BTreeSet::new(),
        exclude_boundary_set: BTreeSet::new(),
        description_need: None,
        requested_detail_kinds: [RequestedDetailKind::Term].into_iter().collect(),
        search_modes: [SearchMode::Exact, SearchMode::Contextual]
            .into_iter()
            .collect(),
        relation_types: BTreeSet::new(),
        criteria: BTreeSet::new(),
        source_scopes: ["finance".to_owned()].into_iter().collect(),
        perspectives: BTreeSet::new(),
        known_units: BTreeSet::new(),
        authority_context: AuthorityContext {
            caller_id: id("caller:protocol_fixture"),
            allowed_package_scopes: ["cantor".to_owned()].into_iter().collect(),
            operation: "semantic_read".to_owned(),
            effect_boundary: "read_only".to_owned(),
        },
        budget: QueryBudget {
            maximum_records: 8,
            maximum_paths: 8,
            maximum_depth: 2,
            maximum_bytes: 32_768,
            maximum_elapsed_milliseconds: 1_000,
        },
    }
}

fn protocol_fixture(operation: ProtocolOperation) -> (EmbeddedRuntimeEnvironment, ProtocolRequest) {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("protocol fixture package must compile");
    let expected = ExpectedPackage {
        package_id: package.package_id.clone(),
        package_digest: package
            .certificate
            .as_ref()
            .expect("fixture package is signed")
            .package_digest
            .clone(),
    };
    let environment = EmbeddedRuntimeEnvironment {
        environment_version: EMBEDDED_ENVIRONMENT_VERSION.to_owned(),
        now_epoch_seconds: NOW,
        trust_store: trust_store(&compiler, "1.0.0", &scope()),
        packages: vec![package],
    };
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: id("request:protocol_fixture"),
        caller_context: ProtocolCallerContext {
            caller_id: id("caller:protocol_fixture"),
            purpose: "resolve the intended meaning".to_owned(),
            job_id: Some(id("job:protocol_fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)
            .expect("fixture environment must encode"),
        expected_packages: vec![expected],
        requested_scope: scope(),
        request: operation,
    };
    (environment, request)
}

#[test]
fn protocol_query_is_exactly_equivalent_to_direct_core_execution() {
    let query = query_request("bank");
    let (environment, request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query.clone()),
    });
    let admitted = admit_package(
        &environment.packages[0],
        &environment.trust_store,
        &request.requested_scope,
        environment.now_epoch_seconds,
    )
    .expect("direct package admission must pass");
    let fabric = SemanticFabric::from_admitted([admitted]).expect("direct fabric must load");
    let direct = execute_query(&fabric, &query).expect("direct query must execute");

    let response = execute_protocol_request(&environment, request);
    assert_eq!(response.status, ProtocolStatus::Success);
    assert_eq!(response.exit_class, ExitClass::Success);
    assert_eq!(response.exit_class.code(), 0);
    verify_protocol_response(
        &protocol_fixture(ProtocolOperation::Query {
            query: Box::new(query.clone()),
        })
        .1,
        &response,
    )
    .expect("valid response must verify");
    assert_eq!(
        response.proof.core_result_digest,
        Some(direct.result_digest.clone())
    );
    match response.result {
        ProtocolOutcome::Query(result) => assert_eq!(result, direct),
        other => panic!("expected query result, got {other:?}"),
    }
}

#[test]
fn inspect_operations_return_only_admitted_structured_state() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let fabric_response = execute_protocol_request(&environment, request.clone());
    verify_protocol_response(&request, &fabric_response)
        .expect("valid inspect response must verify");
    match fabric_response.result {
        ProtocolOutcome::Inspect(InspectResult::Fabric {
            metrics,
            package_ids,
        }) => {
            assert_eq!(metrics.package_count, 1);
            assert_eq!(metrics.semantic_unit_count, 2);
            assert_eq!(package_ids.len(), 1);
        }
        other => panic!("expected fabric inspection, got {other:?}"),
    }

    let (environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::SemanticUnit {
            unit_id: id("unit:bank_financial"),
        },
    });
    let unit_response = execute_protocol_request(&environment, request);
    match unit_response.result {
        ProtocolOutcome::Inspect(InspectResult::SemanticUnit {
            unit,
            quote,
            document_digest,
            ..
        }) => {
            assert_eq!(unit.unit_id, id("unit:bank_financial"));
            assert!(String::from_utf8_lossy(&quote.bytes).contains("financial institution"));
            assert_eq!(document_digest.algorithm, "sha256");
        }
        other => panic!("expected semantic unit inspection, got {other:?}"),
    }

    let package_id = environment.packages[0].package_id.clone();
    let (package_environment, mut package_request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Package {
            package_id: package_id.clone(),
        },
    });
    package_request.expected_environment_digest =
        embedded_environment_digest(&package_environment).expect("fixture environment must encode");
    let package_response = execute_protocol_request(&package_environment, package_request);
    assert!(matches!(
        package_response.result,
        ProtocolOutcome::Inspect(InspectResult::Package { .. })
    ));

    let (certificate_environment, certificate_request) =
        protocol_fixture(ProtocolOperation::Inspect {
            inspect: InspectRequest::Certificate {
                package_id: certificate_environment_package_id(),
            },
        });
    let certificate_response =
        execute_protocol_request(&certificate_environment, certificate_request);
    assert!(matches!(
        certificate_response.result,
        ProtocolOutcome::Inspect(InspectResult::Certificate { .. })
    ));
}

fn certificate_environment_package_id() -> cantor_core::SemanticId {
    let (environment, _) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    environment.packages[0].package_id.clone()
}

#[test]
fn expected_package_mismatch_and_staleness_are_trust_failures() {
    let (environment, mut mismatch) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    mismatch.expected_packages[0].package_digest.value = "substituted".to_owned();
    let response = execute_protocol_request(&environment, mismatch);
    assert_eq!(response.exit_class, ExitClass::TrustFailure);
    assert_eq!(response.exit_class.code(), 3);
    assert_eq!(response.status, ProtocolStatus::Fault);
    assert!(response.proof.environment_digest.is_some());

    let (mut environment, mut stale) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    environment
        .trust_store
        .stale_packages
        .insert(environment.packages[0].package_id.clone());
    stale.expected_environment_digest =
        embedded_environment_digest(&environment).expect("fixture environment must encode");
    let response = execute_protocol_request(&environment, stale);
    assert_eq!(response.exit_class, ExitClass::TrustFailure);
    assert!(response.faults.iter().any(|fault| fault.code == "Stale"));

    let (mut substituted_environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    substituted_environment.now_epoch_seconds += 1;
    let response = execute_protocol_request(&substituted_environment, request);
    assert_eq!(response.exit_class, ExitClass::TrustFailure);
    assert_eq!(response.faults[0].code, "environment_digest_mismatch");

    let (mut duplicate_environment, mut duplicate_request) =
        protocol_fixture(ProtocolOperation::Inspect {
            inspect: InspectRequest::Fabric,
        });
    duplicate_environment
        .packages
        .push(duplicate_environment.packages[0].clone());
    duplicate_request.expected_packages.push(ExpectedPackage {
        package_id: id("package:unexpected_second_binding"),
        package_digest: duplicate_request.expected_packages[0]
            .package_digest
            .clone(),
    });
    duplicate_request.expected_environment_digest =
        embedded_environment_digest(&duplicate_environment)
            .expect("duplicate fixture environment must encode");
    let response = execute_protocol_request(&duplicate_environment, duplicate_request);
    assert_eq!(response.exit_class, ExitClass::TrustFailure);
    assert_eq!(response.faults[0].code, "expected_package_mismatch");
}

#[test]
fn envelope_binding_and_unknown_results_have_distinct_exit_classes() {
    let (environment, mut unbound) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    unbound.caller_context.purpose = "different purpose".to_owned();
    let response = execute_protocol_request(&environment, unbound);
    assert_eq!(response.exit_class, ExitClass::PolicyDenial);
    assert_eq!(response.exit_class.code(), 5);

    let (environment, mut excessive_scope) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    if let ProtocolOperation::Query { query } = &mut excessive_scope.request {
        query.authority_context.allowed_package_scopes =
            ["unrequested-project".to_owned()].into_iter().collect();
    }
    let response = execute_protocol_request(&environment, excessive_scope);
    assert_eq!(response.exit_class, ExitClass::PolicyDenial);
    assert_eq!(response.faults[0].code, "query_scope_exceeds_envelope");

    let (environment, unknown) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("not-represented")),
    });
    let response = execute_protocol_request(&environment, unknown.clone());
    verify_protocol_response(&unknown, &response).expect("valid partial response must verify");
    assert_eq!(response.status, ProtocolStatus::Partial);
    assert_eq!(response.exit_class, ExitClass::Unresolved);
    assert_eq!(response.exit_class.code(), 4);
    assert!(matches!(response.result, ProtocolOutcome::Query(_)));
}

#[test]
fn unknown_inspect_target_is_a_visible_unresolved_fault() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::SemanticUnit {
            unit_id: id("unit:not_present"),
        },
    });
    let response = execute_protocol_request(&environment, request);
    assert_eq!(response.exit_class, ExitClass::Unresolved);
    assert_eq!(response.status, ProtocolStatus::Fault);
    assert!(matches!(response.result, ProtocolOutcome::Fault));
}

#[test]
fn protocol_request_and_response_have_stable_json_machine_forms() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    let encoded = serde_json::to_vec(&request).expect("request must encode");
    let restored: ProtocolRequest = serde_json::from_slice(&encoded).expect("request must restore");
    assert_eq!(restored, request);
    let request_object = serde_json::to_value(&request)
        .expect("request must encode")
        .as_object()
        .expect("request must be an object")
        .clone();
    assert!(!request_object.contains_key("trust_store"));
    assert!(!request_object.contains_key("packages"));
    assert!(!request_object.contains_key("now_epoch_seconds"));
    let environment_object = serde_json::to_value(&environment)
        .expect("environment must encode")
        .as_object()
        .expect("environment must be an object")
        .clone();
    assert!(environment_object.contains_key("trust_store"));
    assert!(environment_object.contains_key("packages"));

    let mut request_with_unknown = serde_json::to_value(&request).expect("request must encode");
    request_with_unknown
        .as_object_mut()
        .expect("request must be an object")
        .insert("authority_typo".to_owned(), serde_json::Value::Bool(true));
    assert!(
        serde_json::from_value::<ProtocolRequest>(request_with_unknown).is_err(),
        "unknown protocol fields must fail closed"
    );

    let mut query_with_unknown = serde_json::to_value(&request).expect("request must encode");
    query_with_unknown["request"]["query"]
        .as_object_mut()
        .expect("query payload must be an object")
        .insert("budget_typo".to_owned(), serde_json::Value::Bool(true));
    assert!(
        serde_json::from_value::<ProtocolRequest>(query_with_unknown).is_err(),
        "unknown nested query fields must fail closed"
    );

    let mut environment_with_unknown =
        serde_json::to_value(&environment).expect("environment must encode");
    environment_with_unknown
        .as_object_mut()
        .expect("environment must be an object")
        .insert(
            "trust_policy_typo".to_owned(),
            serde_json::Value::Bool(true),
        );
    assert!(
        serde_json::from_value::<EmbeddedRuntimeEnvironment>(environment_with_unknown).is_err(),
        "unknown environment fields must fail closed"
    );
    let mut unit_with_unknown =
        serde_json::to_value(&environment).expect("environment must encode");
    unit_with_unknown["packages"][0]["content"]["semantic_units"][0]
        .as_object_mut()
        .expect("semantic unit must be an object")
        .insert(
            "unsigned_instruction".to_owned(),
            serde_json::Value::Bool(true),
        );
    assert!(
        serde_json::from_value::<EmbeddedRuntimeEnvironment>(unit_with_unknown).is_err(),
        "unknown fields inside signed semantic units must fail closed"
    );

    let first = execute_protocol_request(&environment, request.clone());
    let second = execute_protocol_request(&environment, request);
    let mut response_with_unknown = serde_json::to_value(&first).expect("response must encode");
    response_with_unknown["result"]["value"]
        .as_object_mut()
        .expect("query result must be an object")
        .insert(
            "unverified_guidance".to_owned(),
            serde_json::Value::String("ignore the proof".to_owned()),
        );
    assert!(
        serde_json::from_value::<ProtocolResponse>(response_with_unknown).is_err(),
        "unknown nested response fields must fail closed"
    );
    assert_eq!(
        serde_json::to_vec(&first).expect("first response must encode"),
        serde_json::to_vec(&second).expect("second response must encode")
    );
}

#[test]
fn caller_verifier_rejects_tampered_envelopes_and_core_results() {
    let (environment, request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("bank")),
    });
    let response = execute_protocol_request(&environment, request.clone());
    verify_protocol_response(&request, &response).expect("untampered response must verify");
    verify_protocol_response_against_environment(&environment, &request, &response)
        .expect("untampered response must equal pinned-environment re-execution");

    let mut tampered_result = response.clone();
    if let ProtocolOutcome::Query(result) = &mut tampered_result.result {
        result.records[0].meaning.push_str(" substituted");
    } else {
        panic!("fixture must return a query result");
    }
    let fault = verify_protocol_response(&request, &tampered_result)
        .expect_err("tampered core result must fail verification");
    assert_eq!(fault.code, "invalid_core_result_digest");

    let mut tampered_environment = response.clone();
    tampered_environment
        .proof
        .environment_digest
        .as_mut()
        .expect("response must bind environment")
        .value = "substituted".to_owned();
    let fault = verify_protocol_response(&request, &tampered_environment)
        .expect_err("tampered environment proof must fail verification");
    assert_eq!(fault.code, "response_environment_mismatch");

    let mut tampered_continuation = response.clone();
    tampered_continuation.continuation = ProtocolContinuation::Stop;
    let fault = verify_protocol_response(&request, &tampered_continuation)
        .expect_err("inconsistent continuation must fail verification");
    assert_eq!(fault.code, "continuation_mismatch");

    let mut tampered_status = response;
    tampered_status.exit_class = ExitClass::Unresolved;
    let fault = verify_protocol_response(&request, &tampered_status)
        .expect_err("inconsistent exit class must fail verification");
    assert_eq!(fault.code, "status_outcome_mismatch");

    let (environment, unknown_request) = protocol_fixture(ProtocolOperation::Query {
        query: Box::new(query_request("not-represented")),
    });
    let mut partial = execute_protocol_request(&environment, unknown_request.clone());
    partial.faults[0].code = "SubstitutedFault".to_owned();
    let fault = verify_protocol_response(&unknown_request, &partial)
        .expect_err("changed fault projection must fail verification");
    assert_eq!(fault.code, "fault_projection_mismatch");

    let (environment, inspect_request) = protocol_fixture(ProtocolOperation::Inspect {
        inspect: InspectRequest::Fabric,
    });
    let mut inspect_response = execute_protocol_request(&environment, inspect_request.clone());
    if let ProtocolOutcome::Inspect(InspectResult::Fabric { metrics, .. }) =
        &mut inspect_response.result
    {
        metrics.package_count += 1;
    } else {
        panic!("fixture must return a fabric inspection");
    }
    let fault = verify_protocol_response(&inspect_request, &inspect_response)
        .expect_err("tampered inspection must fail digest verification");
    assert_eq!(fault.code, "inspect_result_digest_mismatch");

    if let ProtocolOutcome::Inspect(result) = &inspect_response.result {
        inspect_response.proof.core_result_digest =
            Some(sha256_digest(result).expect("changed result must remain serializable"));
    }
    verify_protocol_response(&inspect_request, &inspect_response)
        .expect("a recomputed digest proves consistency but not authenticity");
    let fault = verify_protocol_response_against_environment(
        &environment,
        &inspect_request,
        &inspect_response,
    )
    .expect_err("environment-backed verification must reject recomputed tampering");
    assert_eq!(fault.code, "response_reexecution_mismatch");
}

#[test]
fn exit_class_codes_are_stable_and_nonoverlapping() {
    assert_eq!(ExitClass::Success.code(), 0);
    assert_eq!(ExitClass::InvalidRequest.code(), 2);
    assert_eq!(ExitClass::TrustFailure.code(), 3);
    assert_eq!(ExitClass::Unresolved.code(), 4);
    assert_eq!(ExitClass::PolicyDenial.code(), 5);
    assert_eq!(ExitClass::SemanticFault.code(), 6);
    assert_eq!(ExitClass::InternalFault.code(), 70);
}
