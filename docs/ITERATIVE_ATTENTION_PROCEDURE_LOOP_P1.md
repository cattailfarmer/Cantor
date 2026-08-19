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

This checkpoint is specification and planning authority only. Implementation
requires a separate activation review, then pure forms, deterministic stepping,
provider protocol, two-call loopback proof, stopped reentry, replay mutation
tests, transport measurement, and a full release checkpoint in that dependency
order.

P1 still represents separate provider calls joined by explicit host state. It
does not create one shared transformer forward pass, mutate hidden state,
persist sessions, execute effects, or contact EVO-X2 or OneDrive automatically.

