# Runtime Closure Materialization Plan P0

Cantor can now turn an exact RIS-P0 Revision 0.2 runtime-closure envelope into
an executable *description* of future material work without executing that
work. The compiler first reparses, recompiles, and byte-compares the supplied
upstream envelope. It then derives a deterministic operation DAG across nine
phases:

1. seed validation;
2. prerequisite resolution;
3. material production;
4. target preparation;
5. material staging;
6. material verification;
7. rollback preparation;
8. closure verification; and
9. receipt-candidate emission.

For `N` material nodes and `P` unresolved prerequisites, the plan contains
exactly `4N + P + 3` operations. Each operation has a one-based ordinal,
deterministic UUID-bearing identity, upstream subject references, canonical
dependencies, expected target/digest/byte/verifier/executable declarations,
required-but-denied capabilities, an unresolved reason, and a self-excluding
digest. All operations are `proposed_awaiting_separate_commission`; their
`execution_authorized`, `observed`, and `executed` fields are false.

The retained synthetic fixture has five material nodes and two prerequisites,
so it compiles to 25 unresolved operations. Its receipt candidate asserts zero
observations, executions, materialized nodes, verified nodes, filesystem
results, verifier results, installed state, activated state, rollback readiness,
and successor-recognition authority. All sixteen effect counters remain zero.

The focused verifier refuses unknown, duplicate, noncanonical, trailing, and
overbound JSON; stale raw-byte or semantic digests; synthetic-to-supplied input
relabeling; dependency and identity faults; and fully rehashed phase, kind,
target, denial, authority, operation-state, receipt, verification, manifest,
and raw-file mutations. It double-compiles and double-verifies before comparing
the exact retained four-file evidence bundle.

This checkpoint is not a materializer or installer. It does not observe a host,
resolve a prerequisite, acquire or build material, create a target, stage a
file, run a verifier, prepare a real rollback, emit a completion receipt,
install or activate Cantor, contact a provider or model, access secrets, or
affect a remote machine or hardware. Those require separate source custody,
SJS formation, authority, implementation, and proof.

Provider-free replay:

```powershell
.\scripts\test_cantor_runtime_closure_materialization_plan_evidence.ps1 `
  -OutputDirectory .\experiments\runtime_closure_materialization_plan_p0\artifacts `
  -VerifyExisting
```
