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
`CoordinationToolContext` already admitted by the procedure compiler path. For
an effectless local proof only, the executable can emit a deterministic,
explicitly non-authoritative fixture:

```powershell
.\target\release\cantor-compact-reflection-loop.exe fixture-context `
  --output C:\path\to\experimental-context.json
```

Then run the host:

```powershell
cargo build --release -p cantor_compact_reflection_loop --locked
.\target\release\cantor-compact-reflection-loop.exe `
  --context C:\path\to\coordination-context.json `
  --prompt "Run and reflect over the bound attention procedure." `
  --base-url http://127.0.0.1:8081/v1 `
  --model exact-advertised-model-id `
  --maximum-steps 64 `
  --output C:\path\to\compact-reflection-report.json
```

The endpoint must be unauthenticated loopback HTTP. If it advertises several
models at `/v1/models`, `--model` must exactly match one advertised identifier;
when it advertises one, selection may be implicit. The output path is create-new. Provider response bodies,
the context file, prompt, timeout, and quota are bounded. Provider-private
reasoning fields are recursively omitted from the preserved report.

Replay-verify or compactly inspect a saved report without contacting the
provider, executing the procedure, or rereading the historical context path:

```powershell
.\target\release\cantor-compact-reflection-loop.exe verify `
  --report C:\path\to\compact-reflection-report.json
.\target\release\cantor-compact-reflection-loop.exe inspect `
  --report C:\path\to\compact-reflection-report.json
```

Replay verification reconstructs the deterministic first request, validates
the model call, rebuilds and validates the fresh one-session terminal compact
registry, reconstructs the reflection request, admits the final response, and
requires recursive absence of private reasoning fields and the exact compiled
nonclaim set. `inspect` emits a small identity projection only after that full
verification succeeds.

## Transport measurement

`measure-fixture` regenerates the exact governed structured-byte measurement:

```powershell
.\target\release\cantor-compact-reflection-loop.exe measure-fixture
```

For the deterministic fixture, the model-facing tool arguments are 20 bytes
and the terminal handle is 679 bytes. The exact terminal record is 67,522
bytes, the reflection request is 86,092 bytes, and the complete report is
162,385 bytes. The record therefore occupies 78.43% of the reflection request
and 41.58% of the report. This selects a verified compact terminal projection
as the next optimization candidate, provided exact `READ` remains available.

These are compact UTF-8 JSON bytes, not model tokens, latency, memory, quality,
or a general performance result. The canonical artifact is
`experiments/compact_reflection_transport_measurement/artifacts/compact_reflection_transport_measurement_v1.json`.

## What is proven

- the run-scoped model tool argument is only `maximum_steps`;
- the host-owned compact binding reaches a terminal outcome byte-identical to
  the direct stateless procedure core for the governed fixture;
- exact terminal session and outcome digests survive the tool/result/reflection
  boundary;
- wrong names, counts, quotas, premature content, remote URLs, altered final
  digests, empty contexts, and existing output paths fail closed; and
- the complete executable performs root health, multi-model discovery, first
  HTTP pass, compact execution, terminal READ, second HTTP pass, sanitization,
  and create-new report against a deterministic loopback provider; and
- valid report replay succeeds while profile, request, terminal digest, final
  digest, privacy, and nonclaim tampering fails closed; and
- the transport measurement validates and regenerates byte for byte.

Live generative-model acceptance remains a separate deployment checkpoint. This P0 does
not modify llama.cpp, inject information during a live token stream, access
hidden state, persist or authenticate sessions, execute effects, establish
external truth, contact EVO-X2 automatically, or access OneDrive.
