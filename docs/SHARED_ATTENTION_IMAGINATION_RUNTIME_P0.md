# Shared Attention and Imagination Runtime P0

Cantor P0 now provides the external semantic state machine that a host can put
between independent LLM passes. It does not merge neural hidden states. Each
model keeps its own context; Cantor preserves the small, inspectable frame they
are coordinating around.

The implemented cycle is:

```text
working frame
  -> typed deltas against exact generation + digest
  -> atomic deterministic reconciliation or typed backpressure/refusal
  -> frozen candidate
  -> exact-digest faculty attestations
  -> sealed checkpoint or revision/defer/incomplete result
```

An orchestration host can feed a sealed or working frame to a model, validate
the model's proposed delta through Cantor, and supply the returned successor to
the next inference pass. Repeating that loop creates frame-by-frame shared
attention without injecting material into a token generation already in
progress.

## What “shared” means

A `SharedAttentionFrame` is a deterministic replicated semantic object. It
contains:

- a stable frame identity, generation, predecessor digest, purpose, and policy;
- named participants and their declared faculty roles;
- propositions with explicit epistemic status;
- constraints, SOP anchors, evidence, unresolved challenges, and current focus;
- a bounded attention-capacity account;
- applied delta and settlement-attestation lineage;
- a semantic digest over meaning-bearing content; and
- a frame digest over the complete generation and lifecycle state.

The semantic digest is unchanged when a working frame is merely frozen or
sealed. The full frame digest changes because generation, status, predecessor,
and proof lineage change. A participant must attest the full frozen-candidate
digest, not a prose summary.

This is shared semantic state, not:

- shared KV cache or transformer hidden state;
- arbitrary mid-token prompt insertion;
- proof that agreeing participants are externally correct;
- distributed Byzantine consensus;
- autonomous authority or effect execution; or
- a claim that a language model solves NP-complete problems generally.

## Atomic deltas

Every `AttentionFrameDelta` binds one exact:

- author participant;
- policy;
- base generation;
- base frame digest;
- logical-time observation;
- operation list;
- causal predecessor set; and
- canonical SHA-256 digest.

P0 supports these closed operations:

```text
add_proposition       replace_proposition     remove_proposition
add_constraint        remove_constraint
pin_anchor            release_anchor
attach_evidence
raise_challenge       resolve_challenge
set_focus             release_focus
```

The runtime sorts a batch by delta identity, refuses duplicate deltas and
multiple mutations of the same semantic target, validates every operation
against the unchanged base, and then applies the whole batch to a clone. Any
fault returns no successor. This deliberately disallows hidden order-dependent
subroutines inside one batch: a later delta cannot rely on an object that an
earlier delta in the same batch would create. Such work must use two explicit
generations.

Ordinary reality-frame deltas cannot introduce `imagined` propositions. The
accepted epistemic classes are:

```text
observed   inferred   assumed   verified
```

`imagined` belongs only inside a `DreamFrame` until a reviewed promotion is
projected as `assumed` or `inferred`.

## Backpressure

The working capacity equation is:

```text
pinned anchors
+ current focus
+ retrieved associations
+ recent stream
+ reserved headroom
<= context budget
```

P0 uses canonical JSON UTF-8 bytes as a deterministic proxy. This is not a
token count and must not be compared directly with a model context size. A
later provider adapter may calculate tokenizer-specific accounts under a new
profile.

Before applying a valid batch, Cantor measures its canonical byte size. If the
batch exceeds reserved headroom, the result is `buffered`; the frame is
unchanged and the receipt contains exact required and available capacity plus
the recovery sequence:

```text
freeze frame
preserve event log
classify novelty
cluster novelty
prioritize authority, identity, and security
split subordinate frames
compact the working set
reconcile, then resume
```

Invalid content is refused before this capacity decision. A malformed or
epistemically invalid update cannot hide behind a `buffered` label.

`compact` is an exact-base transition owned by a declared Refiner participant.
It may retain a subset of current focus and reduce the focus, retrieved
association, and recent-stream byte accounts. It cannot increase those
accounts, alter the context budget, reduce the pinned-anchor account, remove
semantic records, or operate without evidence. Cantor recomputes headroom,
records the compaction identity in the successor, and returns an ordinary
working generation. The buffered delta must then be rebound to that new exact
generation and digest before reconciliation; stale payloads are not silently
retargeted.

## Settlement

Settlement has two phases.

1. `prepare` moves an unchallenged working frame to `candidate_frozen`, advances
   its generation, and gives it a new full digest.
2. `settle` validates attestations against that exact generation and digest.

Every required participant must acknowledge. Acknowledged role coverage must
also contain Observer, Honesty, and Security. A participant may carry multiple
roles but must make each gate obligation explicit through a role-bound
attestation. The result is one of:

```text
sealed              all required participants and gate faculties acknowledge
revision_required   at least one participant challenges
deferred            no challenge, but at least one participant defers
incomplete          required participant or gate acknowledgement is missing
```

Only `sealed` produces a successor. That frame retains the attestation
identities that justified its status. Settlement does not change a
proposition's epistemic label; in particular, agreement cannot turn an
assumption into an observation.

## DreamFrame

A `DreamFrame` is a bounded hypothetical branch. Forking requires an exact
sealed parent digest and declares:

- purpose;
- preserved parent invariants;
- relaxed assumptions;
- forbidden effects;
- `imagined` hypotheses with exact dream lineage;
- predicted consequences;
- required evidence;
- falsification conditions; and
- current and maximum branch depth.

At least one forbidden effect, invariant, hypothesis, evidence requirement,
and falsifier is mandatory. The branch states are `open`, `testing`,
`verified`, and `discarded`.

Evidence moves an open branch to testing. Verification requires all declared
evidence and exact-dream-digest acknowledgements from Observer, Honesty, and
Security. The verified branch retains its review identities. Verification here
means the declared branch review contract was satisfied; it is not universal
truth.

Promotion never edits the sealed parent. It produces a normal frame delta
against that parent's exact digest, converts hypotheses only to `assumed` or
`inferred`, carries dream and review lineage, and then re-enters ordinary
reconciliation and settlement. The parent stays byte-identical.

## Three-node faculty mapping

The user's proposed deployment topology maps naturally onto the participant
form:

| Node | Faculties | Settlement responsibility |
| --- | --- | --- |
| guard | Honesty, Security | representation consistency and boundary/effect gate |
| projection | Planner, Weaver | path and association proposal |
| server | Observer, Scribe, Refiner | frame custody, observation, refinement, and final coordination |

P0 does not open a network between these nodes. A future transport can deliver
the same frames, deltas, and attestations over local processes or separate
machines. Transport authentication, retry, ordering, liveness, and participant
signatures remain separate work.

## JSON shell

Build the shell with:

```powershell
cargo build -p cantor_cli --bin cantor-shared-attention --release
```

It reads one closed JSON request from standard input or `--input <path>` and
writes one response. Supported operations are:

```text
validate_frame
reconcile
compact
prepare
settle
fork_dream
validate_dream
record_dream_evidence
review_dream
discard_dream
project_dream_promotion
```

The request is tagged by `operation`; every variant and every nested runtime
form rejects unknown fields. The response profile is
`cantor-shared-attention-cli/0.1` and always repeats three nonclaims: no hidden
state sharing, no external effect, and no truth-by-settlement.

Exit codes are:

| Code | Meaning |
| ---: | --- |
| 0 | typed success or typed buffered backpressure result |
| 2 | transport/request envelope invalid |
| 3 | semantic transition refused |
| 4 | shell-internal failure |

This shell and the MCP adapter use the same provider-neutral request, result,
response, and pure dispatch function. An Ollama, llama.cpp, Codex, or custom
host can call that contract between passes without changing the core state
machine.

## Stateless MCP adapter

Build the native MCP process with:

```powershell
cargo build -p cantor_shared_attention_mcp --release
```

It exposes exactly one STDIO tool, `coordinate_attention`. Tool arguments have
one required `request` property containing the same closed operation union used
by the JSON shell. Input and output JSON Schemas are generated from the same
Rust types used for deserialization and serialization.

The adapter is intentionally stateless: every call carries its complete frame
or DreamFrame and returns its complete typed successor, backpressure receipt,
or refusal as `structuredContent`. That makes process restart and replay
straightforward and prevents a server-local “current frame” from becoming
hidden authority. Succeeded and buffered responses are MCP successes; refused
or malformed calls retain a structured response and set the MCP error flag.

This adapter is the callable between-pass seam. It does not register itself
with a host, invoke a model, insert material into an active generation, open a
network listener, persist a session, or authorize any external effect. A later
digest-addressed frame store can reduce payload repetition under separate SJS
authority without changing the operation contract.

## Authority and proof

The governing specification is
[`Cantor_Shared_Attention_Imagination_Runtime_P0.sop`](../specifications/Cantor_Shared_Attention_Imagination_Runtime_P0.sop).
The raw dictated source remains separate under
[`source_documents/2026-08-19_shared_attention_imagination_runtime`](../source_documents/2026-08-19_shared_attention_imagination_runtime/).

Focused verification:

```powershell
cargo test -p cantor_core --test shared_attention
cargo test -p cantor_cli --test shared_attention_cli
cargo test -p cantor_shared_attention_mcp --test mcp_protocol
cargo clippy -p cantor_core --all-targets --all-features -- -D warnings
cargo clippy -p cantor_cli -p cantor_shared_attention_mcp --all-targets --all-features -- -D warnings
```

The current P0 deliberately defers network streaming, model calls, persistent
frame storage, participant cryptographic signing, token-aware capacity,
distributed fault tolerance, autonomous effects, and FPGA lowering.
