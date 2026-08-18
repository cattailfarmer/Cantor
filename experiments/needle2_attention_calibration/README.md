# Needle 2 attention-language calibration

This directory measures frozen EVO-X2 attention-runtime checkpoints. It is an
observation harness, not a training loop, trusted procedure catalogue, or
production benchmark.

The active profile is an explicitly adaptive regression against admission-account
runtime commit `9980ff353c3792ff9de2bb0471155bab297c31e4`. Its
`runtime_contract_snapshot.json` is deployment-pinned and binds the exact
catalogue digest and closed input schemas. The harness compiles every positive
expected argument object through those schemas before sending any prompt. The
active `declared_binding_cases.json` is a byte-distinct successor corpus containing
the same cases as `in_domain_cases.json`, but with its own identity and exact new
checkpoint lineage. It contains only the admitted subject `cantor` for positive
cases and treats other-faculty requests as negative boundary controls. The prior
corpus remains unchanged as calibration history.

Configuration separates `checkpoint_commit`, the runtime currently under test,
from `corpus_design_commit`, the implementation context in which the corpus was
authored. The active corpus retains design commit
`de4ffd1cef6e019ee7c9db28d78f93228d9c9bd2` while it is reused unchanged against
the newer runtime. Health and new evidence report both identities; archived
evidence remains byte-verifiable without migration.

The completed successor run `36d4aadf-6972-4d9f-8fae-14839d1e48d5` records
thirteen exact positive routes, seventeen safe positive refusals, and six of six
correct negative refusals. The prior frame contraction is now a
`needle_argument_binding_mismatch`, so it no longer counts as an admitted
procedure with mismatched arguments. This is a stricter boundary, not an accuracy
improvement.

The historical `held_out_cases.json` was created after the first runtime
checkpoint and raw-byte hashed before execution. It covers subject resolution, identity
boundary inspection, attention transition review, and negative controls across
natural, imperative, explicit-label, key-value, line-field, JSON-like, terse,
and context-wrapped forms. Because the same project agent designed it after
reading the procedures, `held-out` means unseen by the frozen checkpoint—not
independently authored. After the first run it became calibration history. That
first corpus also contained unsupported positive subject expectations; its raw
results remain preserved under calibration
`1abe028b-ae9c-4446-8bd9-5b6712981f27` and are not rewritten or presented as
general positive accuracy.

## Boundary

Each case launches the frozen controller once with `run --route-only`. The
frozen controller rechecks its own ten-file deployment manifest and runs Needle
in a disposable child process. Route-only mode does not query Cantor and does
not call llama.cpp for articulation. The learned model may propose a procedure;
ordinary host code classifies the observation and never treats confidence as
authorization.

The calibration directory has its own deployment manifest. `config.json` pins
that manifest but is excluded from the manifest to avoid a hash cycle. The
external Git checkpoint remains the review anchor against joint replacement.

## Commands on EVO-X2

```powershell
.\run.ps1 health
.\run.ps1 run
.\run.ps1 verify <calibration-uuid>
```

`run` is intended to be executed once for the active raw-byte-locked corpus. It publishes:

- `00_corpus.json`: parsed corpus, raw digest, checkpoint, and runtime identity;
- `01_observations.json`: ordered selections/refusals and referenced run IDs;
- `02_report.json`: exact counts, ratios, confusion, forms, and confidence;
- `manifest.json`: path, byte, and SHA-256 binding for the three records.

The closed dispositions are:

- `exact_match`;
- `procedure_match_argument_mismatch`;
- `wrong_procedure`;
- `positive_refusal`;
- `correct_negative_refusal`;
- `unexpected_negative_call`;
- `infrastructure_fault`.

Low accuracy does not make a structurally valid calibration run fail. A run is
`incomplete` only when infrastructure prevents the remaining observations.
Results do not authorize lowering the `0.65` gate or editing the frozen runtime.
`needle_argument_ungrounded`, `needle_argument_binding_mismatch`, and
`needle_declaration_invalid` are safe pre-semantic refusals in the grounded
runtime; timeout, dependency, deployment, and malformed protocol faults remain
infrastructure failures.

## Local verification

```powershell
python -m unittest discover -s experiments/needle2_attention_calibration/tests -v
python -m json.tool experiments/needle2_attention_calibration/held_out_cases.json
```

The governing specification is
`specifications/Cantor_Held_Out_Attention_Language_Calibration.sop`.
