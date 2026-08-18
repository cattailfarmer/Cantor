# Cantor Needle 2 Attention Runtime

This is a bounded EVO-X2 experiment that connects three distinct roles:

1. Needle 2 proposes one registered attention procedure.
2. The controller verifies the procedure and arguments, requires every selected
   string argument to be literally grounded in the preserved caller stimulus,
   then asks Cantor for a signed, source-bearing SOP projection.
3. The existing loopback llama.cpp server articulates an answer from the compact
   `AttentionFrame` without receiving a tool catalogue on that second pass. Its
   response is constrained to a closed JSON account with one conclusion enum and
   one to six short dimension-tagged findings. The host groups findings into
   preserved, added, removed, conflicting, unsupported, and unresolved dimensions.

Needle is an untrusted learned selector, not an authority or signature verifier.
Cantor is the trust/query boundary. The current registry is deliberately limited
to three read-only procedures and a generated fixture corpus for `cantor`.

The runtime pins the exact Needle package version, copied 14 MB Windows engine,
Cantor executable, fixture environment, query template, SOP procedure sources,
procedure contracts, and catalogue digest. `health` fails if any pinned byte set
changes and also verifies the loopback llama.cpp health endpoint.

Needle selection runs in a separate worker process with a 30-second parent
deadline. The parent terminates an over-time worker and fails shut before Cantor.
Canonical sorted JSON is used for hashes; the learned selector receives a distinct
compact transport encoding that preserves declared schema order. Reusing sorted
canonical JSON for model input lowered the measured positive confidence from
`0.8154` to `0.4665`, even though its logical JSON value was unchanged.

After schema validation, the host independently normalizes caller stimulus and
arguments with Unicode NFKC, case folding, and whitespace collapse. Every
argument must occur as a complete literal phrase with Unicode word boundaries.
This check is independent of Needle confidence and Needle's self-reported
grounding account. It establishes caller-text provenance, not truth or intent.

When a semicolon/newline-delimited record explicitly starts with `subject:`,
`claim:`, `before_frame:`, or `after_frame:`, the controller additionally binds
that field by normalized equality. A learned shortening may be literally present
yet still fails as `needle_argument_binding_mismatch` when it differs from the
declared field. Undeclared fields remain under literal grounding; their roles are
not inferred. A whole-document JSON request is stricter: it must be a closed,
unique-key object containing every required string field and, optionally, a
matching procedure ID or tool name. Declaration faults occur before Cantor and
llama.cpp and disclose field names or bounded structural labels, not values.

After all selection gates and the catalogue recheck pass, the controller emits a
`cantor-attention-admission-account/0.1`. The account identifies the procedure,
catalogue, exact stimulus digest, declaration surface, declared and undeclared
field names, and passed schema/grounding/binding/effect gates. It never contains
argument values or per-value hashes. Its canonical SHA-256 appears beside the
account in route-only and full success results, and the same account is archived
as `01_admission.json`. A rejected selection has no admission account; its typed
fault remains the authoritative negative disposition.

## EVO-X2 layout

The isolated deployment root is `C:\AI\services\cantor-needle-runtime`. It does
not replace or modify `C:\AI\services\sop-agent`, and it uses the existing
llama.cpp endpoint only at `127.0.0.1:8081`.

```powershell
.\run.ps1 health
.\run.ps1 list
.\run.ps1 evaluate
.\run.ps1 run "What is Cantor?"
.\run.ps1 verify "785a888b-dd22-4de1-a95d-e580c6bca7ae"
.\run.ps1 run "Identity boundary review; subject: cantor; claim: unsigned oracle authority."
.\run.ps1 run "Attention transition review for Cantor; before_frame is signed query boundary; after_frame is unsigned semantic authority."
```

Each run creates a UUID-named evidence directory beneath `runs`. Model-private
reasoning fields are removed; the selection, Cantor response, attention frame,
provider response, and final result remain inspectable.

## Current calibration boundary

Needle 2 confidently selects `resolve_sop_subject` for the positive fixture and
rejects an unrelated weather request. Explicit attention-procedure fields select
`inspect_identity_boundary` at `0.8407` and `review_attention_transition` at
`0.7201`; five fresh processes reproduced each route with exact arguments. Broad
natural-language paraphrases remain sensitive and fail shut below the `0.65`
gate or as no-call. Improving those routes requires corpus-driven calibration,
not a weaker trust threshold.

The first post-checkpoint corpus also exposed a host-side fault: prompts naming
another faculty could select a schema-valid call whose single-subject enum forced
`subject: cantor`. Route-only containment prevented semantic execution. The
deterministic caller-stimulus grounding gate now rejects that substitution as
`needle_argument_ungrounded`. The original corpus and results remain immutable
history; they are not retroactively scored as if this gate had existed.

The pinned suite contains twenty-five trials: ten definition, five structured
identity, five structured transition, three off-topic, and two contained
residual cases. This establishes repeatability for those exact fixtures—not
general semantic accuracy. The final 0.8B articulator classified all three full
examples as `unresolved`; its output shape is proved, expert judgment is not.

`evaluate` runs the bounded, versioned and raw-byte-pinned
`evaluation_cases.json` suite in
route-only mode. Its positive, off-topic, and contained-residual trials create
ordinary per-run evidence plus one evaluation summary and manifest beneath
`evaluations`. A mismatched observation returns a nonzero process exit.
Negative expectations may admit a closed set of safe refusal codes when the
contract requires non-execution but does not require one learned failure shape.
The summary counts each observed route or fault and reports finite confidence
minimum, maximum, and mean where Needle supplied calibrated confidence. This is
named `needle_confidence` because it can describe a confident no-call decision,
not only confidence in a selected procedure.

`verify <UUID>` independently reloads one run or evaluation manifest, rehashes
every admitted file, rejects missing or extra files, and checks that the result
identity and status agree with the manifest. It does not rerun inference.

## Security boundary

- Catalogue and SOP procedure sources are content-addressed with SHA-256.
- These local hashes prove consistency against the operator-selected config;
  they do not stop a hostile process from replacing both config and content.
  Production admission still needs a supervisor-pinned or signed catalogue root.
- Unknown, altered, ambiguous, low-confidence, or malformed selections fail shut.
- Schema-valid string arguments absent from the caller stimulus fail shut before
  Cantor or llama.cpp; the fault exposes field names but not argument values.
- Every procedure declares an empty effect set.
- Cantor proof bindings and verified quotes are checked before articulation.
- Needle reports with failed generation, ungrounded fields, or negation are rejected,
  and model self-report cannot waive deterministic host grounding.
- The llama.cpp articulation is not promoted into the signed SOP corpus.
- This experiment does not authorize arbitrary procedures or production SOP data.
