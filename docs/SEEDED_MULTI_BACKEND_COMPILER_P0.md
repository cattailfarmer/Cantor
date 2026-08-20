# Seeded multi-backend compiler P0

Cantor now has a strict semantic front end for three non-substitutable compiler
backends. The first backend can project a normalized, source-anchored attention
procedure through the existing CPPE compiler. It emits an inert compiled
candidate; it does not authorize or execute that candidate.

```text
signed SOP generation + proof-bearing SemanticAddress values
  -> SopSeed
  -> TypedSopIr
  -> exactly one CandidateCompilationPlan
       | attention_procedure
       | inference_host_integration
       ` native_artifact
  -> CompilerCapabilityReceipt
  -> optional SelfAssemblyLedger observations
```

## What the forms establish

- `SopSeed` binds independent Honesty, Security, authority, and compiler trust
  root references; dependency roots; discovery and successor policies; exactly
  three backend profiles; one capability ceiling; and predecessor identity.
- `TypedSopIr` binds typed semantic nodes to exact `SemanticAddress` values and
  source-map entries. Every dependency and type reference resolves, and the
  dependency graph is acyclic.
- `CandidateCompilationPlan` selects one backend profile registered by the
  seed. It binds exact inputs, typed outputs, verifier and rollback references,
  unresolved items, and a capability subset.
- `CompilerCapabilityReceipt` partitions the exact request into admitted and
  denied capabilities under the seed ceiling. It does not authorize execution.
- `SelfAssemblyLedger` records a contiguous prefix of self-description,
  self-ordering, self-hosting, and self-revision. A recognized successor exists
  only when the final entry cites candidate, Honesty, Security, external
  recognition, and evidence identities.

All aggregate digests are SHA-256 values with distinct domain separators.
Unknown JSON fields, changed digests, missing source maps, unresolved types,
dependency cycles, backend/profile substitution, capability excess, faulty
accounting, stage skips, and false successor recognition fail closed.

## First compiled backend: attention procedures

Slice 3 adds `AttentionProcedureBackendRequest` and
`AttentionProcedureBackendProjection`. Before the adapter calls CPPE, it:

- replays the seed, typed IR, and exact attention-procedure plan;
- restricts the plan to semantic and source reads;
- requires normalized machine form and forbids textual-source parsing;
- binds the candidate purpose and provenance to the plan and IR;
- requires a passed receipt from a verifier named by the plan, with the plan
  and IR retained as evidence;
- maps every IR node exactly once to a distinct procedure anchor whose package,
  version, digest, and source clause equal the node's `SemanticAddress`; and
- validates the complete CPPE candidate and output lineage.

The result contains the exact CPPE compilation receipt, Process IR, and
`CompiledProcedureIdentity`. Its fixed non-authority boundary still says that
verification, admission, catalogue insertion, attention loading, invocation,
installation, effects, and successor recognition have not occurred.

## Deliberate non-capabilities

Slice 2 adds one narrow lowering seam. A strict `SelfOrderingRequest` explicitly
assigns semantic roles to selected proof-bearing addresses. Cantor replays the
lookup and exact source projection against the admitted fabric, then derives a
`TypedSopIr`, one `CandidateCompilationPlan`, and a `SelfAssemblyLedger` that
stops after observed self-description and candidate self-ordering. Lexical
matching never assigns semantic roles by itself.

The tracked self-hosted corpus is the first provider-free fixture for this
path. It resolves `Cantor`, `SemanticUnit`, and `PreparedRuntime` from three
signed SOP documents and projects an inert attention-procedure plan. Public
deterministic fixture keys are test material, not production trust roots.

These slices do not author an attention procedure from prose, invoke Cargo or
another native compiler as a backend, build a binary, alter llama.cpp, install,
load, or execute a candidate, contact a model, or recognize a successor. An
inference-host plan may name a future internal llama.cpp addon, but such work
remains separately governed and requires measured evidence that the preferred
external seam is insufficient.

## Verification

```powershell
cargo test -p cantor_core --test semantic_compiler_forms -- --test-threads=1
cargo test --release -p cantor_core --test semantic_compiler_forms -- --test-threads=1
cargo test -p cantor_core --test semantic_compiler_self_ordering -- --test-threads=1
cargo test --release -p cantor_core --test semantic_compiler_self_ordering -- --test-threads=1
cargo test -p cantor_core --test semantic_compiler_attention_backend -- --test-threads=1
cargo test --release -p cantor_core --test semantic_compiler_attention_backend -- --test-threads=1
cargo clippy -p cantor_core --all-targets --all-features -- -D warnings
```

The governing source, SJS review, plan, requirement matrix, phase lock,
solution, and proof remain separate records. The next compiler work should
first define attention-procedure authorship or separately activate the
inference-host adapter; native artifact projection and every execution boundary
remain separate authority slices.
