# Resumable Coordination Checkpoint P0

Cantor's process-procedure runtime already had most of the requested
executable attention-frame anatomy:

| Requested idea | Existing CPPE form |
| --- | --- |
| execution frame | `ProcessInstanceState` |
| variables | typed `local_state` |
| program counter | `definition_ref`, `region_ref`, `instruction_index` |
| trajectory | generation, logical time, `ProcessStep`, `SemanticTraceEvent` |
| bounded memory and work | remaining process budgets plus invocation bounds |
| suspendable process | `SerializedContinuation` for waiting or passivated state |
| cooperating routines | two bounded process definitions, messages, yield, wait, reactivate, and join |

The missing boundary was whole-scheduler reentry. The public coordinator ran
all processes from genesis until return, fault, or budget refusal in one host
call. Per-process continuation alone cannot resume that execution because the
next scheduler choice also depends on the other process states, messages,
delivery frontier, wake set, returns, trace, logical clock, and negotiation
session.

P0 now serializes that complete frontier as a
`CoordinationCheckpoint` and advances it through a bounded pure stepper.

## State and transition

```text
exact admitted procedure inputs
          |
          | begin_coordination_checkpoint
          v
digest-bound genesis checkpoint
          |
          | advance_coordination_checkpoint(maximum_steps > 0)
          v
existing deterministic scheduler
          |
          +-- caller quota reached --> successor checkpoint
          |
          +-- all processes return --> existing returned CoordinationOutcome
          |
          +-- semantic/runtime fault --> existing faulted CoordinationOutcome
          |
          +-- invocation bound hit --> existing budget-refused CoordinationOutcome
```

Caller quota is a transport and attention-chunk boundary. It is not an
invocation budget. Reaching it returns `paused`, not a fault. Existing step,
trace, message, memory, logical-time, and IR bounds retain their original
meaning and take precedence over pause.

## Checkpoint contents

The strict machine form binds:

- exact invocation, procedure, IR, admission, and catalogue identities and
  digests;
- canonical digests of the complete invocation request and initial
  negotiation session;
- slice index and predecessor checkpoint digest;
- every current process state and prior process step;
- all serialized process continuations and active continuation references;
- messages, delivered-message frontier, and pending reactivations;
- terminal returns;
- semantic trace events and logical clock;
- the initial negotiation session; and
- a canonical SHA-256 digest over the whole form with only its own digest
  field cleared.

It deliberately contains no native stack address, thread, future, closure,
file handle, process-global cache, KV cache, or transformer hidden state.

## Exact resume wall

Every advance first reruns the existing invocation and coordination gates and
then verifies the checkpoint. Validation includes:

- checkpoint profile and digest;
- request, session, catalogue, procedure, IR, and admission binding;
- slice/predecessor shape;
- process definition map, state identities, program regions and instruction
  indexes, lifecycle, clock, and remaining budgets;
- continuation keys, digests, procedure binding, and current active state;
- message keys, participants, session, frame, anchors, evidence, time, and
  causal references;
- delivered, inbox, outbox, and pending-reactivation subsets;
- terminal return ownership;
- process-step identities and referenced messages; and
- trace indexes, procedure identity, event identities, and exact predecessor
  chain.

A stale, changed, corrupt, cross-invocation, structurally invalid, or
zero-quota request returns an `EvaluationFault` before a successor checkpoint
is constructed. Inputs and predecessor checkpoints are immutable values.

SHA-256 binds content and detects drift. It does not authenticate who produced
that content. An authenticated or signed checkpoint channel is a separate
layer.

## Compatibility

`coordinate_catalogued_procedure` retains its original public signature and
typed invalid-input behavior. It now uses the same initialization and drive
machinery with no caller slice ceiling. There is one interpreter, not a
separate attention runtime.

The fixture proves that quotas of 1, 2, 4, mixed 1/2/4, and 64 all reach the
same byte-equal fifteen-step terminal `CoordinationOutcome` as uninterrupted
execution. Slice boundaries do not enter the semantic trace or returned
meaning.

## What remains deferred

The P0 frame can move among existing control regions but does not yet add:

- logical call frames, `call`, or `return-from-subroutine` instructions;
- recursion or native stack capture;
- a source syntax or parser for defining a `main` and named subroutines;
- IDE visualization or editing;
- MCP exposure;
- storage inside the attention reentry ledger;
- durable persistence or crash recovery;
- provider or llama.cpp invocation; or
- external effects.

Those should build on the now-explicit checkpoint rather than introduce a
parallel interpreter. In particular, a future logical call stack should be a
bounded typed value inside process state and remain distinct from the native
Rust stack.

## Verification

The governing specification is
[`Cantor_Resumable_Coordination_Checkpoint_P0.sop`](../specifications/Cantor_Resumable_Coordination_Checkpoint_P0.sop).
The selected dictated source remains separate under
[`source_documents/2026-08-19_resumable_coordination_checkpoint`](../source_documents/2026-08-19_resumable_coordination_checkpoint/).

Focused verification:

```powershell
cargo test -p cantor_core --test procedure_coordination --all-features
cargo clippy -p cantor_core --all-targets --all-features -- -D warnings
```

The focused suite covers deterministic genesis, strict JSON, one-step pause,
predecessor binding, multi-quota terminal equivalence, terminal global-budget
refusal, request and session substitution, digest corruption, and independently
root-rehashed process-state, continuation, message, and trace corruption.
