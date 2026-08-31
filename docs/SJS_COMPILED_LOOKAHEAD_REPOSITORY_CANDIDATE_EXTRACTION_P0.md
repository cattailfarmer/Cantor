# SJS Compiled-Lookahead Repository-Candidate Extraction P0

This provider-free adapter compiles a supplied typed repository slice into the
existing exact-pool compiled-lookahead selector. It does not inspect a
filesystem or Git checkout. The caller supplies every repository coordinate,
content digest, semantic label, metric, token estimate, and coverage relation.

## Governed input

One request binds an exact repository, branch, supplied commit digest, selector
scope, selection policy, 1–16 candidate records, 1–64 obligations, up to 256
coverage relations, and up to 64 evidence references. Each candidate record
retains its element identity, repository-relative locator, lowercase SHA256
content identity, one of fifteen governed element kinds, and the complete
existing `SjsLtoTermCandidate` value.

Locators reject absolute, drive, UNC, backslash, empty, dot, traversal, Windows
device, alternate-stream, NUL, trailing-dot, and trailing-space forms. Candidate
and obligation identities, semantic identities, and relation coordinates are
unique. Every candidate must be explicitly referenced. A mandatory obligation
must have a supplied edge from both a `governing_anchor` source and a governing
element kind. Nonauthority records can cover only optional obligations.

## Deterministic composition

Canonical sealing sorts set-valued records and relations, seals the nested
selector scope, policy, and candidates, and binds the outer request digest. The
compiler then constructs one `supplied_unobserved_candidate_pool` request using
the parent canonical identities, runs the unchanged optimizer and verifier,
and retains the exact downstream request, envelope, verification, count
accounts, and digest lineage.

The fixture maps eight repository records, six obligations, and twelve edges
onto the parent fixture. The exact downstream result admits 92 subsets, selects
three records, rejects five, records one dominated candidate, leaves zero
uncovered, and keeps all fourteen effect counters at zero.

## Evidence replay

The fixture and verification CLIs exchange bounded compact JSON through stdin
and stdout only. The evidence script retains exactly `request.json`,
`envelope.json`, `verification.json`, and `evidence_manifest.json`, each as one
compact LF-terminated UTF-8 line. Independent verification reparses the bytes,
reconstructs both compilation layers twice, compares exact typed results, and
rehashes every manifest-bound data file.

```powershell
.\scripts\test_cantor_sjs_compiled_lookahead_repository_candidate_extraction_evidence.ps1 `
  -OutputDirectory .\experiments\sjs_compiled_lookahead_repository_candidate_extraction_p0\artifacts
```

Repository acquisition, arbitrary SOP interpretation, semantic generation,
global optimality, tokenizer accuracy, prompt placement, live provider/model
A/B, speed or quality claims, learning, autonomy, durable custody, successor
activation, host mutation, remote machines, FPGA, Minecraft, and physical
effects remain separately sourced and signed seams.
