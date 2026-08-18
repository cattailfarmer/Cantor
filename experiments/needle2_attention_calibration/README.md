# Needle 2 attention-language calibration

This directory measures the frozen EVO-X2 attention runtime at commit
`b0e27bbff1874e8637cbec619f79e360dac38f14`. It is an observation harness,
not a training loop, trusted procedure catalogue, or production benchmark.

The 36-case corpus was created after the runtime checkpoint and is raw-byte
hashed before its first execution. It covers subject resolution, identity
boundary inspection, attention transition review, and negative controls across
natural, imperative, explicit-label, key-value, line-field, JSON-like, terse,
and context-wrapped forms. Because the same project agent designed it after
reading the procedures, `held-out` means unseen by the frozen checkpoint—not
independently authored. After the first run it is calibration history.

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

`run` is intended to be executed once for the preserved corpus. It publishes:

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

## Local verification

```powershell
python -m unittest discover -s experiments/needle2_attention_calibration/tests -v
python -m json.tool experiments/needle2_attention_calibration/held_out_cases.json
```

The governing specification is
`specifications/Cantor_Held_Out_Attention_Language_Calibration.sop`.
