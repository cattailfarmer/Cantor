# Deterministic temporal runtime

`cantor_core::temporal_runtime` is the first executable runtime over the CTPR
forms. It is a pure value transformer, not a service: evaluation receives one
content-bound `RuntimeSnapshot` and one closed `RuntimeOperation`, then returns
either an immutable successor plus `RuntimeReceipt` or a typed `RuntimeFault`.
The prior snapshot is never modified.

The runtime profile is `cantor-cdra-runtime/0.1`. A root pins the exact CTPR
form version, policies, explicit limits, caller-controlled logical clock,
in-memory repository, Calendar, Planner, Tandem, and fixed compiler-fixture
projections, and a
deterministic trace. Compact JSON over ordered maps and sets is the canonical
machine form;
restoration rejects unknown fields, unsupported versions, invalid digests, and
valid but non-normalized JSON.

## Closed operations

- `advance_logical_time` advances only the supplied logical counter.
- `compare_and_append` verifies the expected root and branch generation,
  content bytes, record digests, predecessor set, event frontier, and optional
  snapshot before returning a new in-memory generation and rebuilt index.
- `classify_materiality` applies the pinned materiality-policy revision and
  returns capture, aggregate, or omit with its rule and evidence.
- `revise_calendar` admits an immutable item/recurrence revision while ordinary
  revisions preserve lifecycle state.
- `evaluate_calendar_state` checks the exact latest revision and supplied
  logical time, applies the closed lifecycle table, and returns a material-event
  candidate. It does not admit an event or perform an action.
- `expand_recurrence` filters caller-supplied occurrence keys through explicit
  inclusions, exceptions, occurrence limits, and runtime horizons.
- `evaluate_wake` returns only a wake candidate after exact task, plan,
  repository generation, capsule, policy, authority-evidence, lifecycle, and
  requirement checks.
- `propose_plan` validates the pinned repository and Calendar views, proof gates,
  recognized resource identities, and objective dependency graph. It uses
  declared priority followed by stable semantic identity and returns a proposal,
  never a commitment or execution.
- `open_tandem` binds a clean capsule to the current repository and plan, exact
  prospective/optional execution/retrospective lanes, work packets, closed
  barriers, and count-bounded lag policies.
- `transition_capsule` and `transition_lane` enforce the closed CTPR lifecycle,
  immutable coordinates, monotonic evidence, typed lane outputs, and explicit
  timeout identities. Execution lanes can return only a caller-supplied
  simulated outcome already named by the capsule; no effect is performed.
- `append_lane_message` and `acknowledge_lane_message` preserve named sender and
  receiver identity, same-capsule scope, logical time, causal predecessors, and
  explicit required acknowledgment.
- `reconcile_observer` derives the complete lane-return set from runtime state,
  requires settled lanes and acknowledged messages, rechecks the current plan,
  repository, materiality, lag, and authority subjects, and records the exact
  Observer disposition.
- `evaluate_release_barrier` opens only an exact dependency set cited by an
  admitting or qualifying Observer join; blocking and unresolved dispositions
  cannot release work.
- `reenter_lane` creates a new prepared cursor only from an exact terminal
  predecessor while preserving capsule, task, plan, repository, authority,
  message, and dependency evidence.
- `register_compiler_fixture` admits only a fixed, bounded, content-digest
  verified set of SOP source, SemanticIR, BuildIR, target metadata,
  correspondence, independent correspondence, proof, impact, and all eight
  diff classes. It does not parse or compile source.
- `run_compiler_forward` deterministically projects changed identities,
  invalidations, dependencies, targets, diagnostics, proof needs, and explicit
  unknowns from the supplied candidate generation and `CompilerImpact`.
- `run_compiler_rear` independently reconstructs observed source and semantic
  changes, invalidations, unknowns, and preserved unrelated state from the
  eight supplied `DiffRecord` classes. A mismatch preserves the rear evidence
  and invalidates only the candidate, forward prediction, candidate targets,
  and the union of explicitly predicted and independently observed affected
  identities.
- `check_compiler_fixture` reaches `proof_checked` only after exact forward/rear
  agreement, disjoint independent correspondence evidence, complete diff
  classes, and an admitting or qualifying Observer disposition over every
  compiler proof subject. It emits a new immutable checked generation whose
  sole predecessor is the compared candidate; it never rewrites the candidate
  under its existing identity.

Every operation carries a unique operation identity, caller, expected root
digest, and narrower input/emission/graph limits. Refusal preserves the prior
root and reports operation, subjects, expected and observed values, evidence,
safe residual, and trace location.

## Determinism and limits

No operation reads a system clock, locale, environment, filesystem, database,
network, provider, process, thread schedule, model, or hardware device. Content
bytes live only in the supplied root. Ordered collections, normalized JSON,
explicit logical time, deterministic priority ties, and caller-supplied
recurrence candidates make replay byte-stable for identical inputs.

Root and operation limits bound form records, payload bytes, operation bytes,
emitted identities, graph visits, recurrence occurrences, trace length, and
replay length. Limit exhaustion is a typed refusal, not a partial successor.

## Deliberate limits

This slice does not calculate civil recurrence dates; callers supply candidate
occurrence keys under a declared zone, calendar, and horizon, and the runtime
applies the signed recurrence policy deterministically. It does not classify
truth or authority from time, commit schedules, run work, persist state, call a
provider, issue notifications, perform Git operations, interpret process
procedures, or execute FPGA logic. The compiler surface is a fixed
correspondence fixture, not a general parser, compiler, backend, native/WASM
artifact producer, target executor, or self-certifier. Tandem execution
observations are inert fixture data, not tool calls or evidence that an external
effect occurred.

Run the focused proof with:

```powershell
cargo test -p cantor_core --test temporal_runtime --locked
cargo test -p cantor_core --test temporal_tandem --locked
cargo test -p cantor_core --test temporal_compiler_fixture --locked
```
