# Attention Reentry Ledger P0

The attention reentry ledger gives Cantor a small, explicit memory surface
between independent inference passes. A caller sends one complete
`SharedAttentionFrame` when it opens a session. Later calls send an operation
and an exact continuation handle instead of repeating that base frame.

The ledger is a content-addressed state machine, not model memory. It stores
validated semantic frames, an append-only event history, and the current head
of each session. It does not access a model's KV cache or hidden state.

## Transition shape

```text
complete frame
    |
    | OPEN(expected ledger digest, new session identity)
    v
session head + continuation + open event
    |
    | APPLY(expected ledger digest, sequence, head digest, operation)
    v
core shared-attention dispatch
    |
    +-- advancing result --> store successor --> advance head
    |
    +-- buffered/refused/incomplete --> retain head
    |
    v
append exact event --> recompute session and ledger digests --> continuation
```

Every admitted `open` or `apply` appends one event and increments the session
sequence once. An admitted semantic refusal is therefore history, not a
transport failure. A stale compare-and-set command is not admitted and returns
no successor ledger.

## Content-addressed forms

`AttentionLedger` contains deterministic maps of:

- complete `SharedAttentionFrame` values keyed by lowercase SHA-256 digest;
- `AttentionSessionState` values keyed by semantic session identity; and
- `AttentionLedgerEvent` values keyed by derived semantic event identity.

The ledger, every session, every event, and every stored frame carries its own
digest. Validation recomputes the root and each nested digest, checks map keys,
walks each event chain, and requires the resulting cursor to equal the declared
session head. Orphaned or multiply referenced events are invalid.

The returned `AttentionContinuation` is the compact reentry handle. It binds:

```text
ledger identity + ledger digest
session identity + session sequence
head frame digest + generation + lifecycle status
latest event identity
```

The handle is a locator and compare-and-set witness. It is not a signature,
authorization, truth judgment, or durable recovery record.

## Closed commands

The pure core accepts five commands:

| Command | Purpose | Produces a ledger successor |
| --- | --- | --- |
| `open` | Validate and store a complete initial frame under a new session | Yes |
| `apply` | Resolve the current head internally and run one core operation | Yes, when admitted, even when the semantic result does not advance the head |
| `inspect` | Return the current continuation for one session | No |
| `read_frame` | Return one complete frame by exact digest | No |
| `read_event` | Return one event by exact semantic identity | No |

`apply` supports the existing pure shared-attention operations:

```text
reconcile   compact   prepare   settle
```

It deliberately does not accept a caller-supplied base frame. Cantor resolves
the frame named by the current session head. The embedded delta, compaction, or
attestation still has to name the exact base expected by the underlying core;
ledger custody does not weaken those checks.

## Compare-and-set and races

Every command carries the exact current ledger digest. `apply` additionally
carries the session sequence and head frame digest. If any value is stale, the
operation refuses before core dispatch and returns no successor.

The local MCP host serializes access to its in-process ledger, but it does not
remove compare-and-set requirements. If two callers submit operations from the
same continuation, one may advance the ledger and the other observes a typed
stale refusal. Callers must inspect or otherwise obtain the new continuation
before deciding whether to formulate a new operation. Cantor never silently
retargets an old operation to a new head.

## Advancing and non-advancing results

These core results select and store a new head:

- applied reconciliation;
- valid Refiner compaction;
- candidate preparation; and
- sealed settlement.

Buffered reconciliation, semantic refusal, incomplete settlement, deferred
settlement, and revision-required settlement retain the old head. Their exact
core response is still hashed into a new append-only event, so later reasoning
can inspect the attempt without confusing it with an accepted frame change.

## Volatile MCP process

Build and start the adapter with:

```powershell
cargo build -p cantor_attention_ledger_mcp --release
.\target\release\cantor-attention-ledger-mcp.exe --ledger-id ledger:local-session
```

The STDIO process exposes exactly one tool:

```text
continue_attention_session
```

Its arguments contain one required `request` property whose value is a closed
`AttentionLedgerCommand`. The complete typed result or fault is returned in
MCP `structuredContent`; the text block is only a short status summary.

The process owns one `Arc<Mutex<AttentionLedger>>`. That mutex is process
coordination, not semantic authority. The pure
`execute_attention_ledger_command` function remains independently callable and
returns an immutable optional successor plus response.

The adapter declares itself mutating, non-destructive, non-idempotent as a
whole, and closed-world. Individual read commands are pure, but the combined
tool cannot advertise read-only or idempotent behavior because `open` and
`apply` append history.

## Fault boundary

Commands fail closed for, among other cases:

- wrong or malformed ledger digest;
- stale session sequence or head digest;
- duplicate session identity;
- unknown session, frame, or event;
- corrupt frame, session, event, or root digest;
- discontinuous event history or an orphan event;
- unequal frames claiming one digest; and
- any fault returned by the existing shared-attention runtime.

Transport-envelope faults, semantic refusals, and successful results retain
distinct typed statuses. A short text message never replaces their machine
form.

## P0 boundary

P0 is intentionally volatile. Restarting the MCP process loses all sessions.
It provides no:

- database or file persistence;
- network listener or multi-host replication;
- authentication or participant signatures;
- host registration;
- model invocation or prompt insertion;
- DreamFrame custody;
- external effect execution; or
- claim that an event, settlement, or participant agreement is externally
  true.

Persistence should be a later adapter around immutable ledger transitions,
with its own crash-consistency, retention, authentication, and migration
specification. Distributed shared inference likewise needs transport identity,
ordering, retry, liveness, and conflict policy beyond this local P0.

## Verification

The governing specification is
[`Cantor_Attention_Reentry_Ledger_P0.sop`](../specifications/Cantor_Attention_Reentry_Ledger_P0.sop).
The raw source remains separate under
[`source_documents/2026-08-19_attention_reentry_ledger`](../source_documents/2026-08-19_attention_reentry_ledger/).

Focused verification:

```powershell
cargo test -p cantor_core --test attention_ledger
cargo test -p cantor_attention_ledger_mcp --test mcp_protocol
cargo clippy -p cantor_core --all-features -p cantor_attention_ledger_mcp --all-targets -- -D warnings
```

The tests prove deterministic replay from equal inputs, exact frame and event
reads, head advancement, non-advancing outcome history, settlement trajectory,
stale refusal, nested corruption detection, strict command forms, direct MCP
behavior, same-head race exclusion, and a real RMCP client/server subprocess.
