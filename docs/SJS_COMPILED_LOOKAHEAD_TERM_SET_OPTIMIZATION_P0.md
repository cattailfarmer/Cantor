# SJS Compiled Lookahead Term-Set Optimization P0

This provider-free component chooses a compact set of structured terms for a
future `LookaheadStitch`. It consumes one exact supplied candidate pool and an
explicit coverage graph. It does not generate terms, inspect repository text,
infer semantic coverage, call a model, or mutate a prompt.

## Exact meaning of optimal

P0 uses `optimal` only within the supplied pool, scope, model profile, horizon,
budgets, metrics, and policy. With at most 16 candidates and an eight-candidate
selection ceiling, it enumerates every nonempty subset through that ceiling.
A subset is feasible only when it:

- covers every mandatory governing obligation;
- meets the declared weighted-coverage threshold; and
- stays within count, UTF-8 byte, and supplied token-estimate budgets.

Feasible subsets have one complete deterministic order: smallest cardinality,
highest coverage and positive relevance totals, lowest risk, staleness, bytes,
and token estimate, then lexicographically smallest identity vector. Selected
projection order is separate: governing-source precedence, dependency rank,
placement role, then identity.

## Auditable failure

The result is `selected_exact`, `insufficient_budget`, or
`uncoverable_mandatory`. A failed selection authorizes no term set. It retains
the best partial witness, every uncovered obligation, all candidate
dispositions, budget use, and the objective account. A nonauthority source is
never allowed to cover a mandatory obligation.

## Evidence

The synthetic fixture has eight candidates, six obligations, and 12 coverage
edges. A selection ceiling of three admits exactly 92 subsets. The unique
feasible optimum selects three candidates, rejects five, identifies one
dominated candidate, and leaves zero obligations uncovered. A separate
maximum-bound test admits exactly 39,202 subsets for 16 candidates and a
ceiling of eight; a 17th candidate refuses.

The fixture and verifier CLIs emit and independently reconstruct four compact,
LF-terminated evidence files. Debug and overflow-checked release replay the
same retained bytes. Every one of the 14 effect counters remains zero.

```powershell
.\scripts\test_cantor_sjs_compiled_lookahead_term_set_optimization_evidence.ps1 `
  -OutputDirectory .\experiments\sjs_compiled_lookahead_term_set_optimization_p0\artifacts
```

Repository candidate extraction, tokenizer calibration, stitch construction,
host prompt placement, live model A/B testing, speed or quality claims,
adaptive learning, autonomy, remote hardware, and physical effects remain
separate signed seams.
