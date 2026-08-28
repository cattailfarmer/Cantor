use std::collections::BTreeMap;

use cantor_core::{
    ContentDigest, InnerLaunchCancellationState, InnerLaunchOutputDeclaration, InnerLaunchPlan,
    InnerLaunchPlanAction, InnerLaunchPlanAuthorization,
    InnerLaunchPlanAuthorizationConsumptionState, InnerLaunchPlanAuthorizationDisposition,
    InnerLaunchPlanState, InnerLaunchStdinDeclaration, InnerLaunchTargetProfile,
    NESTED_INNER_LAUNCH_PLAN_NON_AUTHORITY, NESTED_INNER_LAUNCH_PLAN_REQUEST_PROFILE,
    NestedInnerLaunchPlanFaultCode, NestedInnerLaunchPlanRequest,
    NestedInnerModelAdmissionEnvelope, NestedInnerModelAdmissionRequest,
    NestedInnerModelAdmissionVerification, SemanticId, from_inner_launch_plan_machine_form,
    inner_launch_plan_digest, nested_inner_launch_plan_required_terminal_outcomes,
    nested_inner_launch_plan_required_unresolved_account, nested_inner_launch_plan_upstream_digest,
    seal_inner_launch_plan, seal_nested_inner_launch_plan_request,
    to_inner_launch_plan_machine_form,
};

const UPSTREAM_REQUEST: &str =
    include_str!("../../../experiments/nested_inner_model_admission_p0/artifacts/request.json");
const UPSTREAM_ENVELOPE: &str =
    include_str!("../../../experiments/nested_inner_model_admission_p0/artifacts/envelope.json");
const UPSTREAM_VERIFICATION: &str = include_str!(
    "../../../experiments/nested_inner_model_admission_p0/artifacts/verification.json"
);

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test semantic identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn upstream() -> (
    NestedInnerModelAdmissionRequest,
    NestedInnerModelAdmissionEnvelope,
    NestedInnerModelAdmissionVerification,
) {
    (
        serde_json::from_str(UPSTREAM_REQUEST).expect("retained request"),
        serde_json::from_str(UPSTREAM_ENVELOPE).expect("retained envelope"),
        serde_json::from_str(UPSTREAM_VERIFICATION).expect("retained verification"),
    )
}

fn unsealed_plan() -> InnerLaunchPlan {
    InnerLaunchPlan {
        plan_id: sid("inner-launch-plan:cb3a9ea1-777e-4ff4-83d1-5bc6395e9628"),
        state: InnerLaunchPlanState::ProposedEffectless,
        target_profile: InnerLaunchTargetProfile::DirectNoShell,
        executable_ref: sid("opaque-executable:fixture"),
        working_directory_ref: sid("opaque-working-directory:fixture"),
        argv: vec!["--model-ref".to_owned(), "opaque-model:fixture".to_owned()],
        environment: BTreeMap::from([(
            "CANTOR_PROFILE".to_owned(),
            sid("opaque-environment-value:fixture"),
        )]),
        stdin: InnerLaunchStdinDeclaration::Closed,
        stdout: InnerLaunchOutputDeclaration::CapturedBounded,
        stderr: InnerLaunchOutputDeclaration::CapturedBounded,
        context_token_ceiling: 4096,
        memory_byte_ceiling: 8_589_934_592,
        thread_ceiling: 8,
        gpu_layer_ceiling: 0,
        startup_millis_ceiling: 30_000,
        runtime_millis_ceiling: 300_000,
        output_byte_ceiling: 1_048_576,
        descendant_count_ceiling: 0,
        cancellation_grace_millis_ceiling: 5_000,
        cancellation_state: InnerLaunchCancellationState::NoneRequested,
        terminal_outcomes: nested_inner_launch_plan_required_terminal_outcomes(),
        quarantine_owner_ref: sid("recovery-owner:operator"),
        plan_digest: empty_digest(),
    }
}

fn unsigned_request() -> NestedInnerLaunchPlanRequest {
    let (upstream_request, upstream_envelope, upstream_verification) = upstream();
    let mut plan = unsealed_plan();
    plan.context_token_ceiling = upstream_request.instance.context_token_ceiling;
    plan.memory_byte_ceiling = upstream_request.instance.memory_byte_ceiling;
    plan.thread_ceiling = upstream_request.instance.thread_ceiling;
    plan.gpu_layer_ceiling = upstream_request.instance.gpu_layer_ceiling;
    let plan = seal_inner_launch_plan(plan).expect("valid plan");
    let upstream_bundle_digest = nested_inner_launch_plan_upstream_digest(
        &upstream_request,
        &upstream_envelope,
        &upstream_verification,
    )
    .expect("upstream digest");
    let authorization = InnerLaunchPlanAuthorization {
        authorization_id: sid(
            "inner-launch-plan-authorization:c7a19864-7a68-43bd-b4c4-4491a450de64",
        ),
        issuer_ref: sid("issuer:fixture"),
        subject_inner_cantor_id: upstream_request
            .authorization
            .subject_inner_cantor_id
            .clone(),
        plan_id: plan.plan_id.clone(),
        action: InnerLaunchPlanAction::InnerLaunchPlanCompile,
        policy_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "1".repeat(64),
        },
        nonce_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "2".repeat(64),
        },
        sequence_lower_bound: 1,
        sequence_upper_bound: 1,
        attempt_limit: 1,
        retry_limit: 0,
        disposition: InnerLaunchPlanAuthorizationDisposition::AuthorizedForLaterSingleAttemptPlan,
        consumption_state: InnerLaunchPlanAuthorizationConsumptionState::Unconsumed,
        verifying_key_hex: upstream_request.authorization.verifying_key_hex.clone(),
        signature_hex: "0".repeat(128),
    };
    NestedInnerLaunchPlanRequest {
        profile: NESTED_INNER_LAUNCH_PLAN_REQUEST_PROFILE.to_owned(),
        request_id: sid("inner-launch-plan-request:67fb2056-81be-47b8-8e2a-7a3ac22c906a"),
        upstream_request,
        upstream_envelope,
        upstream_verification,
        upstream_bundle_digest,
        plan,
        authorization,
        evidence_refs: [sid("evidence:nested-inner-launch-plan-fixture")]
            .into_iter()
            .collect(),
        unresolved_account: nested_inner_launch_plan_required_unresolved_account(),
        non_authority: NESTED_INNER_LAUNCH_PLAN_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    }
}

#[test]
fn plan_sealing_is_deterministic_and_self_excluding() {
    let first = seal_inner_launch_plan(unsealed_plan()).expect("first plan");
    let second = seal_inner_launch_plan(unsealed_plan()).expect("second plan");
    assert_eq!(first, second);
    assert_eq!(first.plan_digest, inner_launch_plan_digest(&first).unwrap());
    assert_ne!(first.plan_digest, empty_digest());
}

#[test]
fn strict_plan_machine_form_allows_repeated_argv_but_refuses_duplicate_sets() {
    let plan = seal_inner_launch_plan(unsealed_plan()).expect("plan");
    let machine = to_inner_launch_plan_machine_form(&plan).expect("machine form");
    assert_eq!(
        from_inner_launch_plan_machine_form(&machine).expect("round trip"),
        plan
    );

    let unknown = machine.replacen('{', "{\"unknown\":true,", 1);
    assert_eq!(
        from_inner_launch_plan_machine_form(&unknown)
            .unwrap_err()
            .code,
        NestedInnerLaunchPlanFaultCode::InvalidMachineForm
    );

    let mut repeated = unsealed_plan();
    repeated.argv = vec!["--model-ref".to_owned(), "--model-ref".to_owned()];
    let repeated = seal_inner_launch_plan(repeated).expect("repeated argv plan");
    let repeated_machine = to_inner_launch_plan_machine_form(&repeated).expect("repeated machine");
    assert_eq!(
        from_inner_launch_plan_machine_form(&repeated_machine).expect("repeated round trip"),
        repeated
    );

    let duplicate = machine.replace(
        "\"terminal_outcomes\":[\"prelaunch_refused\",\"launch_blocked\"",
        "\"terminal_outcomes\":[\"prelaunch_refused\",\"prelaunch_refused\"",
    );
    assert_eq!(
        from_inner_launch_plan_machine_form(&duplicate)
            .unwrap_err()
            .code,
        NestedInnerLaunchPlanFaultCode::InvalidMachineForm
    );
}

#[test]
fn plan_refuses_empty_argv_lowercase_environment_and_terminal_drift() {
    let mut empty = unsealed_plan();
    empty.argv.clear();
    assert_eq!(
        seal_inner_launch_plan(empty).unwrap_err().code,
        NestedInnerLaunchPlanFaultCode::InvalidPlan
    );

    let mut ambient = unsealed_plan();
    ambient.environment = BTreeMap::from([("Path".to_owned(), sid("opaque:value"))]);
    assert_eq!(
        seal_inner_launch_plan(ambient).unwrap_err().code,
        NestedInnerLaunchPlanFaultCode::InvalidPlan
    );

    let mut terminal = unsealed_plan();
    terminal.terminal_outcomes.pop_first();
    assert_eq!(
        seal_inner_launch_plan(terminal).unwrap_err().code,
        NestedInnerLaunchPlanFaultCode::InvalidPlan
    );

    let mut zero_ceiling = unsealed_plan();
    zero_ceiling.memory_byte_ceiling = 0;
    assert_eq!(
        seal_inner_launch_plan(zero_ceiling).unwrap_err().code,
        NestedInnerLaunchPlanFaultCode::InvalidPlan
    );
}

#[test]
fn retained_nhc03_bundle_digest_is_deterministic() {
    let (request, envelope, verification) = upstream();
    let first = nested_inner_launch_plan_upstream_digest(&request, &envelope, &verification)
        .expect("first digest");
    let second = nested_inner_launch_plan_upstream_digest(&request, &envelope, &verification)
        .expect("second digest");
    assert_eq!(first, second);
    assert_ne!(first, empty_digest());
}

#[test]
fn unsigned_supplied_authorization_fails_closed_without_output() {
    let error = seal_nested_inner_launch_plan_request(unsigned_request()).unwrap_err();
    assert_eq!(error.code, NestedInnerLaunchPlanFaultCode::InvalidSignature);
}

#[test]
fn duplicate_uuid_coordinate_refuses_before_signature_check() {
    let mut request = unsigned_request();
    let upstream_uuid = request.upstream_request.descriptor.artifact_id.as_str();
    let uuid = upstream_uuid.rsplit_once(':').unwrap().1;
    request.plan.plan_id = sid(&format!("inner-launch-plan:{uuid}"));
    request.plan.plan_digest = inner_launch_plan_digest(&request.plan).unwrap();
    request.authorization.plan_id = request.plan.plan_id.clone();
    let error = seal_nested_inner_launch_plan_request(request).unwrap_err();
    assert_eq!(
        error.code,
        NestedInnerLaunchPlanFaultCode::IdentityCollision
    );
}
