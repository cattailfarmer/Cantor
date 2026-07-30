# Cantor PreparedRuntime decision

Status: implemented, proven, and boundedly activated on 2026-07-29.

Cantor now has a core-owned `PreparedRuntime` for repeated reads against one
immutable signed environment generation. It retains at most one admitted
`SemanticFabric`, and that projection is valid only for a structurally equal
`AuthorityScope`. A different valid scope causes complete replacement rather
than broad, narrow, or approximate reuse.

Every call still supplies and validates its own environment digest, complete
package set, caller, purpose, read-only effect boundary, scope, and operation
bindings before prepared semantic state can be used. Direct and prepared
execution share the same validation, admission, query, inspection, proof, and
response construction functions. `execute_protocol_request` remains the
complete deterministic oracle and rollback path.

The resident `cantor-mcp` adapter now owns the core runtime and does not own
cache or semantic policy. The subprocess CLI remains direct because a
short-lived process has no useful reuse boundary.

## Measured tradeoff

Three release runs used 1, 32, and 256 synthetic signed packages. Each latency
report used 40 direct/preparation samples and 160 prepared-hit samples. Heap
measurements used dhat 0.3.3 in separate baseline and prepared processes.

| Packages | Direct median | Prepared-hit median | Hit speedup | Baseline live heap | Prepared live heap |
|---:|---:|---:|---:|---:|---:|
| 1 | 89.1–89.5 µs | 12.1–12.5 µs | 7.16–7.36× | 18,074 B | 43,283 B |
| 32 | 2,560.8–2,582.2 µs | 22.7–23.0 µs | 111.82–112.81× | 276,703 B | 629,722 B |
| 256 | 20,488.1–20,762.1 µs | 106.3–106.4 µs | 192.74–195.13× | 2,149,466 B | 4,903,129 B |

At 256 packages, first preparation was 19,849.2–20,565.9 µs. Peak allocated
heap increased from 3,195,464 to 5,143,370 bytes. The optimization therefore
earns its cost through reuse; it is not a universally cheaper execution mode.

All measured and fixture-supported comparisons used exact full
`ProtocolResponse` equality. No response mismatch was observed.

## Lifecycle boundary

`PreparedRuntimeSlot` provides compare-and-replace, invalidation, rollback,
and fail-closed demanded security replacement. New acquisitions see a complete
old or complete new generation. An in-flight call that already acquired an
immutable snapshot may finish against that exact generation.

Trust time is still the pinned `now_epoch_seconds` in the signed environment.
A time, revocation, package, trust-store, or publication change requires a new
environment generation. This work does not claim live wall-clock enforcement,
distributed cache coherence, lock-free execution, or production-corpus memory
adequacy.

See the [canonical specification](../specifications/Cantor_Prepared_Runtime.sop),
[solution](../solutions/Cantor_Prepared_Runtime_Solution.sop), [proof](../proofs/Cantor_Prepared_Runtime_Proof.sop),
and [machine-readable evidence summary](../experiments/prepared_runtime_benchmark/artifacts/2026-07-29_three_run_summary.json).
