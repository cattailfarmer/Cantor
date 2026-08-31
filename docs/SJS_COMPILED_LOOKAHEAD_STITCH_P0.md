# SJS Compiled Lookahead Stitch P0

This checkpoint makes the smallest persistent unit of SOP Compiled Lookahead
executable as provider-free data. It does not inject a prompt or call a model.

The canonical formation is
[`Cantor_SJS_Compiled_Lookahead_Stitch_P0.sop`](../specifications/Cantor_SJS_Compiled_Lookahead_Stitch_P0.sop),
under canonical UUID `5b57d004-0a43-4d89-9c5a-6dc671a2a05a` and satisfaction
signature `2b743f94-ec0a-48cb-a68c-f5cb0b62bc68`.

## Executable boundary

`cantor_core::sjs_compiled_lookahead_stitch` accepts one strict canonical JSON
request containing:

- one exact objective/phase/feature/requirement/artifact scope;
- one or two stitch declarations;
- one through eight ordered, unique key hints per stitch;
- exact source bindings classified as governing anchor, plan hint, observed
  coordinate, or nonauthority evidence;
- one completion cue and one through eight invalidators per stitch;
- an ordered observation sequence; and
- ordered invocation coordinates for initial, stop-resume,
  tool-result-resume, or reentry boundaries.

Only a governing-anchor binding may carry an imported authority identity. A
plan hint or evidence binding cannot become a requirement or permission by
passing through the compiler.

## Lifecycle and continuity

Every declaration begins `proposed`. Exact activation moves it to `active`.
An exact invalidator has precedence over an exact completion cue; completion
has precedence over exact scope exit. Terminal `fulfilled`, `invalidated`, and
`released` states never reactivate. Replacement uses a new stitch identity and
can activate only after its named predecessor is terminal.

Every transition attempt yields a content-bound receipt. Each invocation
coordinate must identify the latest receipt available at that point. The
compiler then emits one projection record containing every active stitch
exactly once in lexical identity order. This makes stop, tool-result, resume,
and reentry continuity independently auditable without claiming that a
stateless model remembered anything.

Rendered stitch data is capped at 8,192 bytes per coordinate. It contains only
the public declaration fields; source bodies, proofs, transcripts, private
reasoning, and unrelated context are not copied.

## Retained provider-free fixture

The retained fixture contains two stitches, eight hints, four source bindings,
six observations, and four invocation coordinates. Its active-stitch counts
are `2, 2, 1, 0`, for five total projected inclusions. It records two
activations, one fulfillment, one invalidation, zero releases, and zero refused
transitions. Each of the four boundary kinds appears once and all fourteen
effect counters are zero.

Run the exact evidence replay from either PowerShell host:

```powershell
.\scripts\test_cantor_sjs_compiled_lookahead_stitch_evidence.ps1 `
  -OutputDirectory .\experiments\sjs_compiled_lookahead_stitch_p0\artifacts `
  -CargoTargetDirectory D:\CantorBuilds\cantor-lookahead-stitch-p0 `
  -VerifyExisting
```

Add `-Release` for the overflow-checked release lane. The fixture producer and
independent verifier are also available as:

```text
cargo run --locked --offline -p cantor_core --bin cantor-sjs-compiled-lookahead-stitch-fixture
cargo run --locked --offline -p cantor_core --bin cantor-sjs-compiled-lookahead-stitch-verify
```

The verifier reparses retained request bytes, recompiles twice, byte-compares
the packet, receipts, projections, envelope, verification, and reconstructed
manifest, and rehashes the three retained data files.

## What remains separate

This checkpoint does not choose an optimal term set, demonstrate inference
speedup, place text in a prompt, contact a provider, call a model, access hidden
state or K/V cache, persist runtime custody, continue work autonomously, admit a
successor SOP, mutate a workspace, contact a remote machine, use an FPGA, act
on Minecraft, or produce a physical effect. Those require separately sourced,
signed, and measured seams.
