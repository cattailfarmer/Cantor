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

This slice supplies forms, not behavior. It does not semantically validate or
normalize a candidate, calculate a digest, compile source, verify a procedure,
admit or catalogue an identity, select a process, execute an instruction,
stabilize a token ring, invoke a model, or perform an external effect.

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

This is still not a compiler: CPPE-I03 owns source-to-IR lowering and compiler
diagnostics. No live provider, persistence, service, filesystem, network,
process, clock, model execution, unsafe code, device, or FPGA behavior is part
of this profile.

## Verification

```text
cargo test -p cantor_core --test procedure_forms --locked
cargo test -p cantor_core --test procedure_validation --locked
cargo test -p cantor_core --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```
