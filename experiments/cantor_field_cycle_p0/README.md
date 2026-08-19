# Field Attention Cycle P0 Evidence

This directory preserves the complete bounded corpus for the `FIELD_ATTEND → DELINEATE → LATCH` experiment. Reports contain sanitized exact requests/responses and can be replayed with `cantor-field-cycle verify`; event states, ordinals, evidence-reference labels, and the derived verification-assurance class are checked against canonical trajectories.

Accepted fixtures:

- `attention_cycle_field.json`: ordinary five-identity field; canonical field digest `136955ea1f1931de88c22cef392377f3a1fa4e6d4bd1de53450cb7e1f598c8e0`.
- `attention_cycle_forbidden_comembership_field.json`: hostile co-membership boundary field; canonical field digest `1fe069762f31c4afe7a2478b210c9a332191eb4099602a6333eb179654c54a71`.
- `attention_cycle_forbidden_relation_field.json`: one forbidden typed edge for observing model avoidance or host rejection.
- `attention_cycle_forbidden_relation_all_kinds_field.json`: all six typed edge kinds forbidden for one repeatedly adjacent identity pair.

Preserved reports:

- `deterministic_fixture_report.json`: model-free positive construction.
- `evox2_live_v1.json`: replay-valid rejected free-text profile.
- `evox2_live_v2.json`: replay-valid rejected prompt-hardened free-text profile.
- `evox2_live_v3_fault.json`: replay-valid repeated-array/token-limit fault.
- `evox2_live_v4_fault.json`: replay-valid strict-attribution compiler fault.
- `evox2_live_v5.json`: replay-valid completed typed profile.
- `evox2_control_v5.json`: replay-valid one-pass control with no latch eligibility.
- `evox2_hostile_boundary_v5.json`: replay-valid 4-of-4 convergence rejected before candidate promotion by the host boundary.
- `evox2_forbidden_relation_v1.json`: replay-valid model rejection that avoids the single prohibited relation kind.
- `evox2_forbidden_relation_all_kinds_v1.json`: replay-valid model-supported delineation rejected by the host `boundary_conflict` gate.
- `campaign-field-attend-h1/`: thirteen replay-valid reports from five positive, five control, and three hostile repetitions under the identity-hardened verifier.
- `smoke-field-attend-h2/`: final resource-bounded verifier smoke with one positive, one control, and one hostile report.
- `smoke-field-attend-h3/`: final network-closed verifier smoke after disabling proxies and redirects.
- `smoke-field-attend-h4/`: final current-thread-runtime smoke with the same three structural outcomes.
- remote `cantor-field-cycle-p0-h5.exe`: exact-event-reference verifier that replays all thirty-one provider reports without new inference.
- remote `cantor-field-cycle-p0-h6.exe`: final assurance-aware verifier that classifies twenty-nine stored-provider and two response-backed-fault reports without new inference.
- remote `cantor-field-cycle-p0-h7.exe`: contract-discoverable assurance verifier with the same exact remote replay distribution.
- remote `cantor-field-cycle-p0-h8.exe`: final same-handle bounded-file-read verifier with the same exact remote replay distribution.
- `attention_cost_summary_v1.json`: token, cache, provider-compute, exchange, and evidence-byte statistics over all thirty-one provider reports.
- `closure_audit_v1.json`: effect-free reconciliation of preserved sources, proof references, receipts, assurance distribution, complete cost corpus, and final h8 identity.
- `evox2_h8_read_only_audit_2026-08-18.json`: a fresh read-only h8 byte, 31-report replay, llama process/listener, and inherited deployment-ACL observation.
- `cross_pass_tension_policy_analysis_v1.json`: effect-free retrospective evidence falsifying raw signal-array presence as a P1 semantic-pertinence rule; it grants no successor runtime authority.
- `requirement_coverage_audit_v1.json`: effect-free reconciliation of all thirteen requirements across specification, matrix, completion review, and proof plus plan, fault, residual, deployment-observation, and P1 authority boundaries.
- `preflight_and_cli_boundary_observation_v1.json`: effect-free reproduction of missing pre-report discovery evidence and non-exact CLI argument admission.
- `checkpoint_audit_v1.json`: one-command composite of offline acceptance, closure, requirement disposition, tension-policy analysis, manifest freshness, and read-only EVO-X2 identity replay.

The repeatability campaign holds the positive candidate and relation sequence constant, keeps every control latch-ineligible, and rejects every hostile field. It also preserves the warning that all twenty positive probes assess the whole proposal as `conflicted` before the separate delineation pass says `supported`.

These records establish mechanism behavior for one Qwen3.5-0.8B Q4_0 llama.cpp endpoint. They do not establish semantic correctness, truth, production trust, or general model reliability.

Run `scripts/audit_cantor_field_attention_evox2_deployment.ps1` to repeat the live read-only deployment check when EVO-X2 is reachable. Its known `passed_with_open_acl_residual` result is deliberate: the deployed bytes match, but the inherited `Authenticated Users` Modify grant remains unsuitable for a production trust root.
