# Compact Coordination Session P0

Cantor now has a volatile, content-addressed coordination session that turns a
large exact execution frame into a small control handle. It is implemented as
a separate local STDIO process, `cantor-compact-coordination-mcp`, with one
tool: `continue_procedure_session`.

The stateless checkpoint tool remains the semantic reference and rollback
path. This session layer does not reinterpret instructions; it retains the
exact admitted context and current checkpoint, then delegates every execution
step to the same pure dispatcher.

## Lifecycle

```text
OPEN(context_json, expected registry digest, session id)
    -> strict typed parse
    -> core BEGIN
    -> record(context + genesis checkpoint)
    -> ready handle(sequence 1)

ADVANCE(handle lineage, maximum_steps)
    -> registry + sequence + record compare-and-set
    -> core ADVANCE
    -> record(successor checkpoint or terminal outcome)
    -> next handle

INSPECT(current registry digest, session id)
    -> current compact handle

READ(current registry digest, session id)
    -> current handle + exact retained record_json + record digest
```

Every record carries exactly one checkpoint or terminal outcome. Registry,
record, and handle values have independent SHA-256 content digests. Successful
mutations increment both registry generation and session sequence. A stale,
duplicate, terminal, malformed, corrupt, or zero-quota command leaves the
registry byte-identical.

## Compact model-facing surface

The tool schema does not recursively expand `CoordinationToolContext`,
`CoordinationCheckpoint`, or `CoordinationOutcome`. `OPEN` imports context as a
bounded JSON string, and `READ` exports exact record JSON the same way. Cantor
strictly parses that string into the authoritative typed form before use.

Measured against the preceding stateless baseline:

| Surface | Stateless | Compact session |
|---|---:|---:|
| Complete tool metadata | 56,243 bytes | 4,951 bytes |
| Ordinary quota-eight advance argument | up to 49,681 bytes | 367 bytes |

Tool metadata is about 91% smaller, and the ordinary advance argument is more
than 99% smaller than the measured stateless maximum. These are structured
JSON byte comparisons, not token, latency, or memory measurements.

The first `OPEN` remains deliberately large because it transfers exact context
once. `READ` is also deliberately large because inspectability takes priority
over hiding process-owned state. Normal `ADVANCE` and `INSPECT` operations are
the compact control path.

## Concurrency and identity boundary

The MCP process serializes transitions through one mutex. A mutation must
match:

- complete registry digest;
- session identity;
- session sequence; and
- record digest.

Two callers using one equal predecessor therefore produce exactly one
successor; the other receives a stale refusal. A session identifier cannot be
reused, and a terminal record cannot advance.

`READ` prevents the handle from becoming hidden authority: it returns the
complete retained typed record as compact JSON, which can be parsed and
independently compared with its digest.

## Running

```powershell
cargo build -p cantor_compact_coordination_mcp --release
.\target\release\cantor-compact-coordination-mcp.exe
```

The process accepts no arguments and creates the deterministic local registry
identity `registry:compact-coordination-local`. An MCP host discovers
`continue_procedure_session` and submits one command under `request`.
`structuredContent` is authoritative; the accompanying text is only an
operator summary.

## Volatile boundary

Stopping or restarting the process loses every session. An old handle cannot
reenter the empty replacement process. P0 has no disk storage, close/delete
operation, restart recovery, authentication, authorization, remote listener,
provider call, model call, prompt insertion, automatic tool selection, or
external effect.

Content digests bind values but do not identify or authorize their producer.
Durable session storage and signature verification require separate governed
specifications after the volatile state machine is measured.

Canonical authority is
[`specifications/Cantor_Compact_Coordination_Session_P0.sop`](../specifications/Cantor_Compact_Coordination_Session_P0.sop),
with preserved source under
[`source_documents/2026-08-19_compact_coordination_session`](../source_documents/2026-08-19_compact_coordination_session/).

