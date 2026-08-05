# Cantor Process Procedure machine forms

`cantor_core::procedure` defines the pure data ABI for the first
`cantor-process-procedure-experiment/0.1` slice. The profile is inspired by
Simula's durable process identity and passivation/reactivation model, but it is
not a Simula parser or runtime.

The module separates these identities:

- authored `ProcedureCandidate`;
- exact `CompiledProcedureIdentity` and portable `CantorProcessIr`;
- immutable `ProcessInstanceState`, `SerializedContinuation`, and `ProcessStep`;
- named participants, typed messages, negotiated frames, sessions, and exact
  `TokenRingPass` observations;
- validation, compilation, verification, admission, catalogue, and revocation
  records;
- bounded invocation request, result, semantic trace, and typed fault records.

All maps and sets use ordered collections. Every struct and tagged union denies
unknown fields during deserialization. Operation, lifecycle, message, trace,
phase, effect, and prohibited-operation vocabularies are closed enums.

## Authority boundary

The `procedure` module supplies forms, not behavior. Separately authorized pure
passes now validate, compile, statically verify, issue a fake Observer admission
disposition, maintain an immutable in-memory catalogue, interpret one local
process, and coordinate one exact two-process experiment. These passes do not
invoke a model or perform an external effect.

The only first-profile effect class is `Effectless`. Its read and write classes
are also closed: typed invocation input and pinned admitted in-memory artifacts
may be represented as reads; returned values, messages, successor state,
semantic traces, receipts, and faults may be represented as outputs. The
machine form does not itself authorize any of them.

CPPE-I02 supplies deterministic inspection of the already-formed data through:

- `validate_procedure_forms` for exact versions, identities, map keys,
  references, finite bounds, closed schema kinds, effect walls, process regions,
  negotiation participants, and phase lineage;
- `to_normalized_procedure_form` and `from_normalized_procedure_form` for exact
  normalized aggregate JSON;
- `compute_candidate_source_digest`, `compute_schema_set_digest`,
  `compute_process_ir_digest`, and `compute_compiled_procedure_digest` for
  self-verifying content identities; and
- `to_normalized_process_ir` and `from_normalized_process_ir` for the canonical
  Process IR machine encoding.

The IR digest is SHA-256 over the complete IR record with its own digest value
replaced by an empty SHA-256 placeholder. Candidate source, schema set, compiled
procedure, and IR substitution therefore fail closed under their respective
identity checks.

CPPE-I03 adds `compile_procedure_candidate`, the deterministic
`cantor-process-compiler/0.1` assembly pass. It accepts only a passed,
digest-valid validation receipt bound to the exact candidate source digest and
only the normalized machine-form source lane. It derives the type table, source
map, cost estimate, canonical Process IR, compiled procedure identity, and a
content-bound `CompilationReceipt`. A refused compilation returns a receipt and
no partial IR or procedure identity.

The compiler does not parse text; a text-source candidate receives a typed
compilation refusal. Successful compilation retains explicit “verification not
performed” and “Observer admission not performed” residuals. No live provider,
persistence, service, filesystem, network, process, clock, model execution,
unsafe code, device, or FPGA behavior is part of this profile.

CPPE-I04 adds `verify_compiled_procedure`, an independent
`cantor-process-verifier/0.1` pass. It requires exact digest-valid validation
and compilation evidence but does not treat compiler success as sufficient.
It independently re-derives compiler identities and cost, then checks schema
and type closure, complete source-map derivation, reachable terminating process
graphs, finite bounds, the full effectless prohibition wall, exact recognized
SOP anchors, lifecycle relations, and normalized IR replay. Its receipt binds
the exact candidate source, compiler, IR, compiled procedure, anchor set,
effect declaration, and bound set.

`build_fake_observer_policy` creates a self-digesting policy for one exact
candidate and `fake_observer_admit` consumes that policy plus all prior phase
evidence. A successful `AdmissionDisposition` names permitted invocation
contexts and revocation conditions; a stale receipt, changed policy, or other
substitution returns refusal with no invocation context. This fake admission
does not insert a catalogue entry and cannot invoke the procedure.

CPPE-I05 adds an immutable in-memory catalogue and the
`cantor-effectless-interpreter/0.1` local execution profile. Catalogue insert,
lookup, alias projection, suspension, revocation, and supersession operate by
returning a new digest-bound value; rejected insertions return an evidence-rich
receipt and no successor. Catalogue entries and invocation requests pin exact
procedure, admission, schema, SOP-anchor-set, and policy digests.

The local interpreter validates the active catalogue generation and all pinned
lineage before its first step. It executes bind, inspect, compare, branch,
select, bounded identity-map, return, and fault operations one transition at a
time under explicit logical-time, step, memory, message, and trace budgets.
Every successful or faulted execution returns immutable process states, steps,
a digest-bound causal trace, consumed budgets, residuals, and a typed result or
fault. Emit, receive, yield, wait-logical, reactivate, join, and multi-process
scheduling return a typed CPPE-I06 residual; they are not silently simulated.

CPPE-I06 adds `cantor-effectless-coordinator/0.1`, a deterministic scheduler
for exactly two admitted process definitions. It executes one process state per
scheduler step and represents all cross-process influence as immutable
`ProcedureMessage`, `SerializedContinuation`, `ProcessStep`, session-successor,
and trace records. Emit and receive use declared tags and participant message
kinds. Yield creates a passivated continuation; reactivate submits an explicit
wake request; logical waits use supplied integer time; join resumes only after
the exact process-instance set is terminal. Resumed continuations remain in the
historical archive while a separate active-continuation map becomes empty.

`cantor-token-ring/0.1` records a pass only from the exact current required
token holder. Passes bind the immutable frame generation, complete participant
set, SOP-anchor set, policy, predecessor pass, and monotonic logical time. One
complete pass cycle over the same generation yields `StableCandidate`; it does
not yield truth or Observer admission. A real frame-content change advances the
generation and clears the active pass set. Silence, missing participants,
forged set digests, stale generations, and out-of-turn passes fail closed.

`verify_coordination_replay` runs the same supplied immutable inputs twice and
returns a self-digesting receipt only for byte-equivalent outcomes. The I06
runtime creates no thread, socket, clock read, filesystem access, provider or
model call, persistence write, notification, external process, or hardware
action. Model-shaped versus hand-authored candidate parity remains CPPE-I07.

## Verification

```text
cargo test -p cantor_core --test procedure_forms --locked
cargo test -p cantor_core --test procedure_validation --locked
cargo test -p cantor_core --test procedure_compiler --locked
cargo test -p cantor_core --test procedure_verifier --locked
cargo test -p cantor_core --test procedure_runtime --locked
cargo test -p cantor_core --test procedure_coordination --locked
cargo test -p cantor_core --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```
