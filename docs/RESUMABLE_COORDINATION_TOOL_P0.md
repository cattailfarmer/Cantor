# Resumable Coordination Tool P0

Cantor can now expose its deterministic procedure scheduler as an ordinary
structured tool without modifying an inference engine. The implementation has
two deliberately separate layers:

- `cantor_procedure_tool::execute_coordination_tool_request` is a pure,
  provider-neutral Rust dispatcher; and
- `cantor-coordination-mcp` is a stateless local STDIO transport with exactly
  one tool, `step_procedure_coordination`.

The tool is an inference coprocessor only in the concrete sense that a host can
call it between model passes and supply its exact result to the next pass. It
does not enter a live forward pass, alter tokens or KV cache, or share hidden
neural state.

## Execution flow

```text
model pass or deterministic host policy
                 |
                 | structured BEGIN request
                 v
       step_procedure_coordination
                 |
                 | pure core validation + genesis
                 v
    complete digest-bound checkpoint
                 |
                 | host appends structuredContent
                 v
              next pass
                 |
                 | ADVANCE(context, checkpoint, quota)
                 v
       bounded deterministic scheduler
          /                         \
   PAUSED + successor          terminal outcome
          \                         /
           structuredContent to host
```

Every call is self-contained. `BEGIN` supplies a
`CoordinationToolContext`; `ADVANCE` supplies that same exact context, the
predecessor checkpoint, and a positive `maximum_steps` value.

## Minimal context

The context contains only the six values required by the checkpoint core:

1. admitted procedure catalogue;
2. compiled procedure identity;
3. executable process IR;
4. admission disposition;
5. invocation request; and
6. initial negotiation session.

It deliberately excludes the candidate, validation and compilation history,
prior full coordination outcome, replay receipt, and later stable session.
Those records remain important provenance, but repeating them would not add
runtime authority to this call.

## Provider-neutral request

The public request is a strict tagged union:

```json
{
  "operation": "begin",
  "context": {
    "catalogue": {},
    "procedure": {},
    "ir": {},
    "admission": {},
    "request": {},
    "initial_session": {}
  }
}
```

The empty objects above are placeholders for the exact typed forms, not valid
values. Generate or project the context from admitted
`AuthorshipLaneEvidence`; do not hand-invent authority fields.

An advance has this outer shape:

```json
{
  "operation": "advance",
  "context": {},
  "checkpoint": {},
  "maximum_steps": 8
}
```

Unknown fields, malformed variants, a zero quota, changed input lineage, or a
corrupt checkpoint fail closed and return no successor result.

## Running the local server

Build and start the STDIO process:

```powershell
cargo build -p cantor_coordination_mcp --release
.\target\release\cantor-coordination-mcp.exe
```

An MCP-capable host should spawn that executable, discover
`step_procedure_coordination`, and place the provider-neutral request under the
tool's `request` argument. The complete machine response is in
`structuredContent`; accompanying text is only a short operator summary.

The tool advertises read-only, non-destructive, idempotent, closed-world
metadata and rejects arguments over 32 MiB. “Read-only” describes external
effects: the returned checkpoint is a new immutable value, and equal calls
return equal responses.

No host registration is performed automatically. Registration, prompt policy,
provider-specific tool syntax, and decisions about when a model may call the
tool remain host responsibilities.

## Proven behavior

Focused tests establish:

- the six-field context projection contains no full-lane history;
- direct `BEGIN` equals `begin_coordination_checkpoint` byte for byte;
- direct `ADVANCE` equals `advance_coordination_checkpoint` byte for byte;
- equal requests replay identically;
- strict JSON, zero-quota, changed-lineage, malformed, and oversized requests
  fail closed;
- MCP metadata exposes exactly one bounded tool; and
- an official RMCP client initializes a real subprocess, discovers the tool,
  receives the exact structured response, and shuts down cleanly.

These are execution and transport claims. Digest binding is not authentication
of a producer, and a valid coordination result is not proof that an arbitrary
real-world proposition is true.

## Deferred work

P0 intentionally does not include server-held context, durable storage,
signature verification at the transport boundary, model invocation, automatic
tool selection, external effects, an IDE, or mid-generation insertion. The
repeated context should be measured before a context registry is considered;
that registry would introduce custody, concurrency, and recovery obligations
and requires its own governed slice.

Canonical authority is in
[`specifications/Cantor_Resumable_Coordination_Tool_P0.sop`](../specifications/Cantor_Resumable_Coordination_Tool_P0.sop),
with preserved source in
[`source_documents/2026-08-19_resumable_coordination_tool`](../source_documents/2026-08-19_resumable_coordination_tool/).

