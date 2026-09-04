//! Partial A6 comparison tests. These do not claim complete A5/raw-bundle replay.
use cantor_core::sha256_bytes;
use cantor_ecosystem::*;

struct Fixture {
    request: B1CDriveProductionPreparationPlanRequest,
    plan: B1CDriveProductionPreparationPlan,
    bundle: EocvObservationBundle,
    carrier: String,
    proposed_ref: String,
}
impl Fixture {
    fn new() -> Self {
        let request = from_b1_cdrive_production_preparation_request_machine_form(
            include_str!("../../../experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence/request.json").trim_end_matches('\n'),
        ).unwrap();
        let plan = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
        let proposal_request =
            canonical_b1_cdrive_production_preparation_commission_proposal_request().unwrap();
        let proposal =
            compile_b1_cdrive_production_preparation_commission_proposal(&proposal_request)
                .unwrap();
        assert_eq!(proposal.inherited_plan_sha256, plan.plan_sha256);
        let carrier = "f".repeat(40);
        let bundle = EocvObservationBundle {
            profile: EOCV_BUNDLE_PROFILE.to_owned(),
            bundle_uuid: "12345678-1234-4234-8234-123456789abc".to_owned(),
            a5_receipt_sha256: sha256_bytes(b"comparison-only fixture; not verified A5"),
            expected_carrier_commit: carrier.clone(),
            observed_carrier_commit: carrier.clone(),
            observed_branch: request.branch.clone(),
            observed_remote: request.canonical_remote.clone(),
            observed_project: request.working_project.clone(),
            observed_unix_ms: 7,
            observed_cdrive_free_bytes: request.minimum_cdrive_free_bytes,
            build_junctions: request
                .build_junctions
                .iter()
                .map(|j| EocvJunctionObservation {
                    source: j.source.clone(),
                    kind: EocvJunctionKind::Junction,
                    target: Some(j.target.clone()),
                })
                .collect(),
            upstream_identities: request.upstream_identities.clone(),
            role_observations: plan
                .roles
                .iter()
                .map(|role| EocvRoleObservation {
                    kind: role.kind,
                    path: role.path.clone(),
                    state: EocvPresenceAssertion::Absent,
                })
                .collect(),
            reserved_ref_observation: EocvReservedRefObservation {
                reference: proposal.proposed_ref.clone(),
                state: EocvPresenceAssertion::Absent,
            },
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: vec!["opaque:comparison-only".to_owned()],
            bundle_sha256: sha256_bytes(b"not a full A6 canonical bundle"),
        };
        Self {
            request,
            plan,
            bundle,
            carrier,
            proposed_ref: proposal.proposed_ref,
        }
    }
    fn compare(&self) -> Result<EocvComparisonAccount, EocvFault> {
        compare_eocv_supplied_values(
            &self.bundle,
            &self.request,
            &self.plan,
            &self.carrier,
            7,
            &self.proposed_ref,
        )
    }
}

#[test]
fn all_1024_comparison_subsets_have_exact_ordered_reasons() {
    let base = Fixture::new();
    for mask in 0_u16..1024 {
        let mut bundle = base.bundle.clone();
        if mask & 1 != 0 {
            bundle.observed_carrier_commit = "e".repeat(40);
        }
        if mask & 2 != 0 {
            bundle.observed_branch = "codex/other".to_owned();
        }
        if mask & 4 != 0 {
            bundle.observed_remote.push_str(".git");
        }
        if mask & 8 != 0 {
            bundle.observed_project = r"D:\another-project".to_owned();
        }
        if mask & 16 != 0 {
            bundle.observed_unix_ms = 8;
        }
        if mask & 32 != 0 {
            bundle.observed_cdrive_free_bytes = base.request.minimum_cdrive_free_bytes - 1;
        }
        if mask & 64 != 0 {
            bundle.build_junctions[0].target = Some(r"D:\different".to_owned());
        }
        if mask & 128 != 0 {
            bundle.upstream_identities[0].artifact_sha256 = sha256_bytes(b"different");
        }
        if mask & 256 != 0 {
            bundle.role_observations[0].state = EocvPresenceAssertion::Present;
        }
        if mask & 512 != 0 {
            bundle.reserved_ref_observation.state = EocvPresenceAssertion::Present;
        }
        let account = compare_eocv_supplied_values(
            &bundle,
            &base.request,
            &base.plan,
            &base.carrier,
            7,
            &base.proposed_ref,
        )
        .unwrap();
        let reasons: Vec<_> = EOCV_MISMATCH_REASONS
            .iter()
            .enumerate()
            .filter_map(|(index, reason)| (mask & (1 << index) != 0).then_some(*reason))
            .collect();
        assert_eq!(account.mismatch_reasons, reasons, "subset {mask}");
        assert_eq!(account.all_expectations_match, mask == 0, "subset {mask}");
        validate_eocv_comparison_account(&account).unwrap();
    }
}

#[test]
fn adverse_presence_and_junction_assertions_are_valid_mismatches() {
    let mut fixture = Fixture::new();
    for kind in [
        EocvJunctionKind::Missing,
        EocvJunctionKind::Other,
        EocvJunctionKind::Unknown,
    ] {
        fixture.bundle.build_junctions[0].kind = kind;
        fixture.bundle.build_junctions[0].target = None;
        assert_eq!(
            fixture.compare().unwrap().mismatch_reasons,
            vec![EocvMismatchReason::BuildJunctionMismatch]
        );
    }
    fixture.bundle = Fixture::new().bundle;
    for state in [
        EocvPresenceAssertion::Present,
        EocvPresenceAssertion::Unknown,
    ] {
        fixture.bundle.role_observations[4].state = state;
        fixture.bundle.reserved_ref_observation.state = state;
        assert_eq!(
            fixture.compare().unwrap().mismatch_reasons,
            vec![
                EocvMismatchReason::RoleNotAbsent,
                EocvMismatchReason::ReservedRefNotAbsent
            ]
        );
    }
}

#[test]
fn malformed_junction_conditional_targets_refuse() {
    let mut fixture = Fixture::new();
    fixture.bundle.build_junctions[0].target = None;
    assert_eq!(fixture.compare().unwrap_err().code, EocvFaultCode::Shape);
    fixture.bundle.build_junctions[0].kind = EocvJunctionKind::Unknown;
    fixture.bundle.build_junctions[0].target = Some("not-null".to_owned());
    assert_eq!(fixture.compare().unwrap_err().code, EocvFaultCode::Shape);
    fixture.bundle.build_junctions[0].kind = EocvJunctionKind::Junction;
    fixture.bundle.build_junctions[0].target = Some(String::new());
    assert_eq!(fixture.compare().unwrap_err().code, EocvFaultCode::Shape);
}

#[test]
fn coordinate_counts_order_and_paths_refuse() {
    for case in 0..8 {
        let mut f = Fixture::new();
        match case {
            0 => {
                f.bundle.build_junctions.pop();
            }
            1 => f.bundle.build_junctions.swap(0, 1),
            2 => {
                f.bundle.upstream_identities.pop();
            }
            3 => f.bundle.upstream_identities.swap(0, 1),
            4 => {
                f.bundle.role_observations.pop();
            }
            5 => f.bundle.role_observations.swap(0, 1),
            6 => f.bundle.role_observations[0].path.push_str("\\different"),
            _ => f
                .bundle
                .reserved_ref_observation
                .reference
                .push_str("-different"),
        }
        assert_eq!(
            f.compare().unwrap_err().code,
            EocvFaultCode::Coordinate,
            "case {case}"
        );
    }
}

#[test]
fn capacity_and_supplied_time_support_u64_boundaries() {
    let mut f = Fixture::new();
    for (bytes, expected) in [
        (0, false),
        (f.request.minimum_cdrive_free_bytes - 1, false),
        (f.request.minimum_cdrive_free_bytes, true),
        (u64::MAX, true),
    ] {
        f.bundle.observed_cdrive_free_bytes = bytes;
        assert_eq!(f.compare().unwrap().capacity_meets_minimum, expected);
    }
    for time in [0, u64::MAX] {
        f.bundle.observed_unix_ms = time;
        let account = compare_eocv_supplied_values(
            &f.bundle,
            &f.request,
            &f.plan,
            &f.carrier,
            time,
            &f.proposed_ref,
        )
        .unwrap();
        assert!(account.observation_time_matches_a4);
        assert!(!f.compare().unwrap().observation_time_matches_a4);
    }
}

#[test]
fn forged_summary_conjunction_reasons_and_order_refuse() {
    let f = Fixture::new();
    let base = f.compare().unwrap();
    let mut a = base.clone();
    a.all_expectations_match = false;
    assert_eq!(
        validate_eocv_comparison_account(&a).unwrap_err().code,
        EocvFaultCode::Receipt
    );
    a = base.clone();
    a.mismatch_reasons
        .push(EocvMismatchReason::CarrierCommitMismatch);
    assert!(validate_eocv_comparison_account(&a).is_err());
    a = base;
    a.carrier_commit_matches = false;
    a.branch_matches = false;
    a.all_expectations_match = false;
    a.mismatch_reasons = vec![
        EocvMismatchReason::CarrierCommitMismatch,
        EocvMismatchReason::BranchMismatch,
    ];
    validate_eocv_comparison_account(&a).unwrap();
    a.mismatch_reasons.swap(0, 1);
    assert!(validate_eocv_comparison_account(&a).is_err());
    a.mismatch_reasons = vec![EocvMismatchReason::CarrierCommitMismatch; 2];
    assert!(validate_eocv_comparison_account(&a).is_err());
}

#[test]
fn reference_text_commit_and_digest_shapes_are_bounded() {
    let mut f = Fixture::new();
    f.bundle.evidence_references = (0..48).map(|i| format!("opaque:{i}")).collect();
    assert!(f.compare().unwrap().all_expectations_match);
    f.bundle.evidence_references.push("opaque:extra".to_owned());
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Size);
    f.bundle.evidence_references = vec!["same".to_owned(), "same".to_owned()];
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Size);
    f.bundle.evidence_references = vec!["opaque".to_owned()];
    f.bundle.observed_branch = "x".repeat(8193);
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Shape);
    f.bundle.observed_branch = f.request.branch.clone();
    f.bundle.observed_carrier_commit = "A".repeat(40);
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Expectation);
    f.bundle.observed_carrier_commit = f.carrier.clone();
    f.bundle.upstream_identities[0].artifact_sha256.algorithm = "other".to_owned();
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Shape);
}

#[test]
fn historical_plan_mutation_refuses_and_new_capacity_is_separate() {
    let mut f = Fixture::new();
    assert_ne!(
        f.bundle.observed_cdrive_free_bytes,
        f.request.observed_cdrive_free_bytes
    );
    assert_ne!(f.carrier, f.request.expected_current_commit);
    assert!(f.compare().unwrap().all_expectations_match);
    f.request.expected_current_commit = f.carrier.clone();
    f.request.request_sha256 = b1_cdrive_production_preparation_request_digest(&f.request).unwrap();
    assert_eq!(f.compare().unwrap_err().code, EocvFaultCode::Plan);
}

#[test]
fn unit_enum_and_unknown_struct_fields_reject() {
    assert!(serde_json::from_str::<EocvPresenceAssertion>("\"missing\"").is_err());
    assert!(serde_json::from_str::<EocvJunctionKind>("\"absent\"").is_err());
    assert!(
        serde_json::from_str::<EocvReservedRefObservation>(
            r#"{"reference":"opaque","state":"absent","authorized":true}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<EocvReservedRefObservation>(
            r#"{"reference":"opaque","state":"absent","state":"present"}"#
        )
        .is_err()
    );
}
