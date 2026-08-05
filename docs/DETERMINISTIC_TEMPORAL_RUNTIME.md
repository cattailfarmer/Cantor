# Deterministic temporal runtime

`cantor_core::temporal_runtime` is the first executable runtime over the CTPR
forms. It is a pure value transformer, not a service: evaluation receives one
content-bound `RuntimeSnapshot` and one closed `RuntimeOperation`, then returns
either an immutable successor plus `RuntimeReceipt` or a typed `RuntimeFault`.
The prior snapshot is never modified.

The runtime profile is `cantor-cdra-runtime/0.1`. A root pins the exact CTPR
form version, policies, explicit limits, caller-controlled logical clock,
in-memory repository, Calendar and Planner projections, and a deterministic
trace. Compact JSON over ordered maps and sets is the canonical machine form;
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
procedures, or execute FPGA logic. Tandem lanes and compiler correspondence are
separate dependency-ordered slices.

Run the focused proof with:

```powershell
cargo test -p cantor_core --test temporal_runtime --locked
```
