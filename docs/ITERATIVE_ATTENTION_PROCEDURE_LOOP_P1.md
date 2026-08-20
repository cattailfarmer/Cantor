# Iterative attention procedure loop P1 specification

P1 is the next bounded state machine after the proven one-call compact
reflection loop. It is designed for a procedure that returns `READY` because
one advancement quota cannot reach terminal state.

```text
OPEN exact context
      |
      v
model call -> validate -> ADVANCE
                         |
             +-----------+-----------+
             |                       |
           READY                  TERMINAL
             |                       |
   verified ReadyProjection   exact READ + TerminalProjection
             |                       |
   new inference checkpoint      no-tool reflection
             |                       |
             +-> next call           +-> complete report

any cap, refusal, or fault -> stopped report + current live reentry handle
```

Cantor retains context, checkpoints, registry digests, and compare-and-set
custody. The model sees only verified progress projections and emits one closed
quota call at each checkpoint. A `READY` result can never be described as
complete; a provider answer before terminal is a protocol fault.

The run policy bounds step quota, tool calls, provider calls, and timeout.
Exhausting a cap produces a replayable `stopped` report with the current handle,
not a fabricated failure or completion. Reentry remains possible only while
the volatile owning compact process and exact handle are still live.

The complete report is an ordered causal transcript. Replay must reconstruct
every request, parsed call, compact transition, ready or terminal projection,
stop state, and final reflection without contacting a provider or executing
the procedure. Exact records remain host-side and are not duplicated into
model attention.

The original checkpoint began as specification and planning authority. Its
provider-free implementation now covers strict run forms, deterministic
READY-to-terminal advancement, stopped and terminal-pending reentry, exact
replay, dual transcript evidence, digest-bound transport, phase checkpoints,
compact handle custody, typed custody queries, structural handle discovery,
and a staged discovery-to-inspection witness. Each slice was activated only
after source preservation, SJS review, and an artifact-bound phase lock.

The smallest executable entry witness is:

```text
bootstrap discovery (no root, maximum 1)
  -> pin returned root + full checkpoint digest
  -> rediscover identical handle and entry digest
  -> inspect exact custody entry
  -> validate compact metadata and workflow digest
```

Run it without a provider:

```powershell
cargo run -p cantor_compact_reflection_loop -- witness-scripted-discovery-inspection
```

Its deterministic first handle is a fixture policy, not semantic relevance.
The next independent frontier is a governed semantic anchor catalogue that can
rank subject-to-purpose candidates while leaving signed compilation and exact
custody admission authoritative.

P1 still represents separate provider calls joined by explicit host state. It
does not create one shared transformer forward pass, mutate hidden state,
persist sessions, execute effects, or contact EVO-X2 or OneDrive automatically.
