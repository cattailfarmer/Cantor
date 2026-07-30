# Cantor supervised mock loop

`cantor_ecosystem` is the first executable proof of the commissioned
Cantor–Codex coordination protocol. It runs one deterministic, effect-free
cycle in memory. The worker and Cantor participant are caller-supplied
adapters; the Phase 1 proof uses a two-step mock worker and the existing
`cantor_core` protocol engine over a compiled, signed SOP package.

This is a protocol library, not a live Codex controller. It does not open a
Codex task, invoke a model, use the network, start a process, persist a
session, notify another participant, execute an effect, or create a second
worker.

## Exact cycle

The only successful Phase 1 route is:

| Tick | Message | Sender | Recipient | Depth |
| ---: | --- | --- | --- | ---: |
| activation + 1 | `commission` | principal | manager | 0 |
| activation + 2 | `assignment` | manager | Codex worker | 1 |
| activation + 3 | `cantor_query` | Codex worker | Cantor participant | 2 |
| activation + 4 | `cantor_return` | Cantor participant | Codex worker | 2 |
| activation + 5 | `candidate` | Codex worker | Observer | 1 |
| activation + 6 | `review` | Observer | manager | 1 |
| activation + 7 | `decision` | manager | principal | 0 |

Every non-root message names an already admitted causal predecessor. That
predecessor must have handed control to the current sender, declared the
current message kind as its expected response, and supplied a deadline that
has not passed. Sender and recipient must also match the fixed route for the
message kind. A participant cannot acquire authority merely by being known to
the commission.

The complete outcome is not trusted because it deserializes. Call
`CycleOutcome::validate` with the governing commission and work packet. The
validator replays all seven envelopes through admission, verifies the
`cantor_core` response, reproduces the Observer review, checks the final
decision, and recomputes the metrics. It rejects divergence between a
top-level result and the corresponding transcript payload.

## Authority and effects

Authority is a closed set in five independent dimensions:

- project;
- semantic operation;
- tool capability;
- data scope; and
- exterior effect class.

Work-packet authority must be a subset of commission authority. Every
non-root message must be contained by both. Intersection is deterministic and
cannot invent a value.

Phase 1 rejects a commission containing any exterior effect class. A
candidate retains its `requested_effects` for inspection, but any nonempty
request forces revision. There is no EffectBroker participant and no fault
envelope control path in this profile. Runtime faults are returned out of band
with the immutable accepted transcript prefix.

## Admission and termination

Admission is fail-closed and append-atomic. Before a message is appended, the
transcript validates:

- profile and typed payload kind;
- exact consumer, participant identity, and route;
- commission correlation and work-packet frame digest;
- commission and work-packet authority containment;
- causal handoff and expected-response contract;
- commission lifetime and monotonic logical time;
- message, serialized-byte, logical-tick, and call-depth budgets;
- unique message and idempotency identities; and
- absence of an equivalent semantic-state cycle.

Text values are nonempty, NUL-free, and limited to 4,096 bytes. Profile-owned
collections are limited to 256 items. Digests use lowercase hexadecimal
SHA-256. Serde machine forms reject unknown struct fields.

The runtime performs no retry, recursion, automatic revision, worker spawn, or
effect. It returns after the first decision or the first typed fault.

## Deterministic Observer

The Observer is deliberately mechanical. It is not a claim of implemented
model-based faculties. It records exactly five checks:

- Honesty: criterion claims are known and declared evidence and proof
  references are present.
- Security: authority remains contained and the candidate requests no effect.
- Protocol: the Cantor response is successful and passes the core verifier.
- Acceptance criteria: every work-packet criterion is claimed.
- Effect boundary: the candidate remains effect-free.

Acceptance requires each check exactly once, every check passing, and no
failure reason. An effect request, omitted criterion, unknown criterion,
missing proof, or invalid protocol response produces revision or a typed
fault without performing an action.

References in this mock profile prove exact identifier presence and lineage;
they do not independently authenticate an exterior artifact. Authenticity of
the SOP answer comes from the admitted signed `cantor_core` package and its
verified protocol response.

## Verification

Run the slice tests:

```powershell
cargo test -p cantor_ecosystem --locked --offline
```

The successful fixture compiles a real one-document SOP corpus with distinct
deterministic test signers, executes an `inspect fabric` request through
`cantor_core`, and validates the transported cycle. Public fixture seeds are
test material and grant no production authority.

The canonical SHA-256 digest of the current deterministic fixture outcome is
`2ef72ed3edf4bf58e80e24c5d86bea18572ba10324e27e02aacc63569cd78b3c`.
The test recomputes it, so a machine-form or protocol change is visible and
must be reviewed rather than silently accepted.

The governing contract is
`specifications/Cantor_Supervised_Mock_Loop_Activation.sop`. Its preserved
source, explosion, justification, feature slice, requirement matrix,
solution, proof, operational-fault record, and file-change record form the
SJS trace.
