# Cantor reflection loop P0

Cantor now has a bounded, working externalized-attention prototype on EVO-X2.
An unmodified llama.cpp model is told to call the existing `route_attention`
tool, the Rust host validates and executes that call through the reviewed MCP
adapter, and a separate model pass reflects the structured result into a
closed output. The no-tool control skips Cantor entirely.

This is experimental evidence. It is not signed SOP authority, a hidden-state
integration, an effect executor, or a general agent runtime.

## Governing development policy

Prototype work graduates in this order:

```text
preserved dictation
    -> high-leverage feature choice
    -> basic feature flowchart
    -> typed executable flow and fault states
    -> minimum implementation
    -> positive + refusal + control evidence
    -> iterate, abandon, or separately promote
```

Each stage must remain traceable to the stage before it. A diagram is not an
implementation contract, a passing prototype is not trusted authority, and a
failed predecessor is retained when it explains the successor design.

The canonical policy and P0 contract are in
[`Cantor_Prototype_Graduation_And_Reflection_Loop_P0.sop`](../specifications/Cantor_Prototype_Graduation_And_Reflection_Loop_P0.sop).
The exact user dictation is separately preserved in
[`Dictated_Prototype_Graduation_Reflection_Loop_Source.sop`](../source_documents/2026-08-18_prototype_graduation_reflection_loop/Dictated_Prototype_Graduation_Reflection_Loop_Source.sop).

## Executable flow

```text
command
  |
  v
first llama.cpp request -- tool required, thinking disabled
  |
  +-- no/excess/wrong/changed call --------------------------> fail closed
  |
  v
exact route_attention call
  |
  v
host validates name + closed arguments
  |
  v
ephemeral MCP child -> verified frame OR verified refusal
  |
  +-- malformed/unverified result ---------------------------> fail closed
  |
  v
second llama.cpp request -- tool disabled, closed JSON schema
  |
  +-- changed evidence / repeated tool / invalid output -----> fail closed
  |
  v
sanitized ordered trace + independently replayable report

control: command -> llama.cpp with no tools -> closed control output
```

The implementation is the safe-Rust crate
[`cantor_reflection_loop`](../crates/cantor_reflection_loop). Its `verify`
operation reconstructs the exact governed requests, re-parses the admitted
tool call, re-admits the structured result, re-extracts the model output, and
requires the exact state path. `inspect` first performs that verification and
then emits a compact human-facing projection.

## Current live result

The current reviewed experimental binary is:

- EVO-X2 path:
  `C:\AI\services\cantor-reflection-loop\cantor-reflection-loop-v15.exe`
- SHA-256:
  `b1ba0fd7b9700b79ea40eb08de6e77e31207fb860dbeb01d00287c393e6741c3`
- report contract: `cantor-reflection-loop-report/0.2`
- accepted report:
  [`script_acceptance_verified_v15.json`](../experiments/cantor_reflection_loop_p0/script_acceptance_verified_v15.json)
- report SHA-256:
  `c5f1450933ab02eecd42eb4e2a8a9211d53e3b27fbee350fe53c400587d4a015`

The accepted run proves these bounded observations:

| Case | Model tool pass | Cantor result | Reflection result |
| --- | --- | --- | --- |
| positive | one exact call | `route_selected` | frame applied and evidence linked |
| refusal | one exact call | `runtime_refused` | no frame applied and refusal linked |
| control | no tool surface | not applicable | `no_tool_control` |

Before and after the run, llama.cpp remained PID `12780` with the same start
identity. The attention adapter and reflection loop both had zero persistent
processes, and their binary/configuration digests remained unchanged.

Four additional consecutive profile-0.2 runs also pass exact replay with
stable dependency identities. Their immutable hashes, case timings, and final
process audit are recorded in
[`v9_repeatability_acceptance_2026-08-18.json`](../experiments/cantor_reflection_loop_p0/v9_repeatability_acceptance_2026-08-18.json).

## Reproduce and inspect

From the repository root:

```powershell
.\scripts\test_cantor_reflection_loop_p0.ps1
.\scripts\run_cantor_reflection_loop_p0.ps1
cargo run -q -p cantor_reflection_loop -- contract
cargo run -q -p cantor_reflection_loop -- verify --report .\experiments\cantor_reflection_loop_p0\script_acceptance_verified_v15.json
cargo run -q -p cantor_reflection_loop -- inspect --report .\experiments\cantor_reflection_loop_p0\script_acceptance_verified_v15.json
```

The first command is offline and effect-free. It checks source and evidence
digests, the bounded signature marker, twenty-eight focused tests, deny-warning
Clippy, contract/report compatibility, verification, inspection, current
manifest freshness, deployment identity, four malformed or escaping parameters,
and refusal to overwrite an existing evidence path.

The reproduction script closes host, remote path, executable leaf, digest, and
local-output containment parameters before SSH use. It audits process and
dependency identity before and after the run. It does not restart llama.cpp,
change Codex configuration, or create a resident service.

`contract` is effect-free and prints the exact case set, report and trace
profiles, state paths, call/pass limits, authority boundary, and excluded
private fields for programmatic discovery.
The deployed command and post-command process audit are preserved in
[`contract_acceptance_v15.json`](../experiments/cantor_reflection_loop_p0/contract_acceptance_v15.json).

## What the prototype taught us

- llama.cpp's ordinary tool-call checkpoint is sufficient; no llama.cpp fork
  was needed.
- Externalized attention is naturally a multi-pass host protocol: propose a
  call, admit a result, then reflect.
- Tiny-model structured jobs benefit from disabling template thinking and from
  making non-semantic prose fields closed rather than leaving them generative.
- Exact replay needs more than headline status checks. Request, arguments,
  imported result, output, evidence links, dependency identity, and state order
  are all part of the observed computation.
- The P0 demonstrates a seam for growing Cantor. It does not yet demonstrate
  dynamic procedure stacks, arbitrary user jobs, effects, shared inference,
  learned procedure creation, or production trust.

## Reentry

The next high-leverage slice should use this stable shell without widening all
dimensions at once. A suitable P1 is one caller-supplied but still effectless
subject request selected from a closed fixture set, with the same positive,
refusal, control, replay, and authority boundaries. Dynamic procedure creation
and multi-agent coordination remain later, separately governed experiments.
