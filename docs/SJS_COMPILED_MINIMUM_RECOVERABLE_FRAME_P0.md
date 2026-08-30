# SJS Compiled Minimum Recoverable Frame P0

MRF-P0 turns the scope-wide inference-hint and controlled-forgetting idea into
an executable provider-free contract. It does not inspect a model context or
compress hidden state. It accepts exact supplied data and tests whether a
strictly smaller active hint basis can still reach one unambiguous exact
OperativeFrame.

The compiler keeps three mandatory classes in every admitted basis:
governing anchors, denials, and open obligations. Stable relations,
recoverable coordinates, and optional trajectory cues may be release-eligible;
expired items are never admitted to the initial basis. Every hint retains its
scope, intended transform, applicability, completion, invalidation, source,
and restoration role.

The candidate generator tries release-eligible hints lexicographically, first
as single removals and then as bounded groups. Recovery sources are supplied
exact checkpoints, event-ledger frames, or source-artifact frames. A candidate
is:

- `anchored` when all reachable routes select one frame byte-identical to the
  baseline;
- `drifted` when they select one unequal frame; or
- `underdetermined` when no frame or more than one distinct frame remains.

Only an anchored candidate is admitted. Every attempt emits an immutable
RestorationWitness and a deterministic public NarrativeProjection event.
Narrative is an audit projection, not hidden chain of thought and not
authority. A basis is `locally_irreducible` only after the declared bounded
generator is exhausted at the final admitted basis. Pass-budget exhaustion
makes no minimum claim.

The retained synthetic fixture has two jobs, eight hints, two recovery
sources, and an 8-to-4 basis reduction. Six witnesses record four admitted
releases, one drift refusal, and one underdetermined refusal. All fourteen
effect counters and execution authority remain zero.

Run the focused test and retained evidence replay with D-drive build output:

```powershell
$env:CARGO_TARGET_DIR = 'D:\CantorBuilds\cantor-mrf-p0'
cargo test -p cantor_core --test sjs_minimum_recoverable_frame

.\scripts\test_cantor_sjs_compiled_minimum_recoverable_frame_evidence.ps1 `
  -OutputDirectory .\experiments\sjs_compiled_minimum_recoverable_frame_p0\artifacts `
  -CargoTargetDirectory D:\CantorBuilds\cantor-mrf-p0 `
  -VerifyExisting
```

The fixture CLI emits one compact evidence bundle. The verifier CLI accepts
that bundle on stdin, reparses every retained file, compiles twice, verifies
again, reconstructs the manifest, and refuses raw-byte or semantic drift.

MRF-P0 proves protocol mechanics only. Prompt projection, live providers,
semantic-model comparison, global minimality, token or speed gains, durable
custody, autonomous continuation, successor-SOP admission, host projection,
remote machines, hardware, and physical effects remain separate contracts and
experiments.
