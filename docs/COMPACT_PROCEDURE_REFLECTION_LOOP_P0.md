# Compact procedure reflection loop P0

This executable is the first direct composition of Cantor's compiled procedure
runtime with an ordinary model tool call and a later reflection pass. It uses
an unmodified loopback OpenAI-compatible endpoint such as llama.cpp.

```text
exact CoordinationToolContext JSON
        |
        v
host OPEN -> hidden compact handle
        |
        v
model pass 1 -> advance_attention_procedure({maximum_steps})
        |
        v
host validates call -> ADVANCE(hidden handle) -> terminal -> READ exact record
        |
        v
model pass 2 receives exact terminal observation -> digest-bound final JSON
```

The model does not receive the registry digest, session sequence, record
digest, checkpoint, or original context as tool arguments. The host retains
those identities and converts the model's single validated quota into the
exact compare-and-set command. P0 requires that one call reach terminal state;
a paused successor fails rather than silently adding another provider pass.

## Run

Build the executable and provide an exact serialized
`CoordinationToolContext` already admitted by the procedure compiler path:

```powershell
cargo build --release -p cantor_compact_reflection_loop --locked
.\target\release\cantor-compact-reflection-loop.exe `
  --context C:\path\to\coordination-context.json `
  --prompt "Run and reflect over the bound attention procedure." `
  --base-url http://127.0.0.1:8081/v1 `
  --maximum-steps 64 `
  --output C:\path\to\compact-reflection-report.json
```

The endpoint must be unauthenticated loopback HTTP and advertise exactly one
model at `/v1/models`. The output path is create-new. Provider response bodies,
the context file, prompt, timeout, and quota are bounded. Provider-private
reasoning fields are recursively omitted from the preserved report.

## What is proven

- the run-scoped model tool argument is only `maximum_steps`;
- the host-owned compact binding reaches a terminal outcome byte-identical to
  the direct stateless procedure core for the governed fixture;
- exact terminal session and outcome digests survive the tool/result/reflection
  boundary;
- wrong names, counts, quotas, premature content, remote URLs, altered final
  digests, empty contexts, and existing output paths fail closed; and
- the host compiles and passes deterministic protocol and CLI tests without a
  live provider.

Live model acceptance remains a separate deployment checkpoint. This P0 does
not modify llama.cpp, inject information during a live token stream, access
hidden state, persist or authenticate sessions, execute effects, establish
external truth, contact EVO-X2 automatically, or access OneDrive.

