# Cantor Phase6 persistence decision

Cantor retains its canonical JSON environment snapshot and current
request-scoped admitted `SemanticFabric` reconstruction. SQLite and redb remain
measured candidates, not production dependencies.

This is a positive decision to preserve the simplest adequate boundary—not a
claim that JSON is universally superior or that Cantor will never need an
embedded database.

## Why

Three independent local runs compared 1, 32, and 256 immutable signed packages.
Every candidate reconstructed the exact `EmbeddedRuntimeEnvironment`, matched
its digest, passed normal package admission, and returned the exact direct-core
`ProtocolResponse`.

At 256 packages (1,033,485 canonical JSON bytes):

| Candidate | Median warm reconstruction across runs | Maximum observed p95 | Final bytes |
|---|---:|---:|---:|
| JSON | 2.738–3.012 ms | 3.679 ms | 1,033,485 |
| SQLite | 3.437–3.727 ms | 5.134 ms | 1,220,608 |
| redb | 6.138–6.379 ms | 7.252 ms | 1,118,208 |

Query medians stayed near 20–22 ms for all candidates because the current
protocol re-admits packages and rebuilds the same in-memory core on every
request. A physical backend therefore did not improve the present repeated
query bottleneck.

The complete machine-readable summary is
[`experiments/persistence_benchmark/artifacts/2026-07-29_three_run_summary.json`](../experiments/persistence_benchmark/artifacts/2026-07-29_three_run_summary.json).

## Current storage contract

- The persisted authority surface is the strict serialized
  `EmbeddedRuntimeEnvironment`.
- Compiled packages remain immutable and signed.
- Package order remains digest-significant.
- Files loaded from disk are untrusted until the normal Cantor admission path
  accepts them.
- Persistence never defines identity, relation meaning, scope, or query
  behavior.
- Query execution remains read-only over a request-scoped admitted in-memory
  fabric.

The retained lab tests that contract directly across all three candidates:
exact round trips preserve the environment digest and response; changing
persisted semantic bytes produces a visible `environment_digest_mismatch`
trust failure; malformed physical files do not load; and the SQLite candidate
rejects ordinal, package-identity, or package-digest metadata that differs from
the signed package records. The redb candidate likewise rejects noncontiguous
ordinal keys before reconstructing package order.

The snapshot is not self-authorizing. It contains the trust-store data used by
the engine, so the supervising process must control the file path and bind the
request to an independently trusted environment digest and expected package
set. If an attacker can replace the environment, the request bindings, and the
supervisor's trust decision together, no choice among JSON, SQLite, or redb
repairs that bootstrap failure.

This decision does not create a production environment publisher. The current
writer is a public-key demo fixture generator, not an atomic trust-update
service. A later publisher should prefer immutable, digest-named environment
snapshots and an operator-controlled activation reference rather than rewriting
a loaded authority file in place. A transient environment/request mismatch
must remain a fail-closed trust error.

## Reopen triggers

Repeat the benchmark and reconsider a backend when at least one concrete
requirement appears:

- environments approach the current 64 MiB local input ceiling;
- measured startup/reconstruction violates an agreed latency or memory budget;
- package updates must be atomic and incremental without rewriting a snapshot;
- a production compiler needs governed snapshot publication, activation,
  rollback, retention, or recovery;
- multiple processes require concurrent reads and controlled writes;
- operators need relational inspection or migration tooling over normalized
  records; or
- observed workload shows selective package loading materially reduces cost.

Any adopted backend must still reproduce exact environment digests and
`ProtocolResponse` values and must remain outside semantic authority.

| Observed requirement | Reconsider first | Reason |
|---|---|---|
| Transparent whole-environment interchange | JSON | Already canonical, smallest, and fastest measured reconstruction |
| Atomic incremental package updates, normalized inspection, or multi-process access | SQLite | Transactions, relational constraints, and broad tooling |
| Pure-Rust exact-key incremental package storage | redb | Transactional key/value shape without SQL |
| Repeated resident query latency | Prepared runtime, not a database | Current cost is request-scoped admission and fabric reconstruction |
| Hardware throughput after a stable software hotspot exists | FPGA profile | Separate execution target; never semantic authority |

## Measured next optimization surface

Three independent warm in-process decompositions at 256 packages measured
median ranges of 1.629–1.783 ms for environment digesting, 19.665–19.875 ms for
package admission plus fabric construction, 0.044–0.045 ms for the query
against an already prepared fabric, and 21.943–22.441 ms for the complete
current protocol call. The prepared query result exactly matched the query
result carried by the full protocol response in every run.

That contrast does not predict a 0.047 ms prepared protocol. A correct resident
runtime must still validate the request envelope, caller and purpose, scope,
expected package set, budgets, policy, and proof, and must invalidate prepared
state whenever environment or trust conditions change. It does show that a
separately governed immutable `PreparedRuntime` experiment is more directly
supported by present evidence than changing the physical database.

A naïve resident cache would also duplicate memory: the current environment
owns each compiled package, admission clones each complete package, and the
fabric clones units, relations, labels, and identities into indexes. A future
slice therefore needs an explicit ownership design and retained/peak heap
measurements; serialized JSON size is not a valid heap estimate.

One bounded feasibility test confirms that the existing immutable
`SemanticFabric` is `Send + Sync`: eight threads performed sixteen reads each
against one shared 32-package fabric, and all 128 results matched the full
protocol's query result. This is read-determinism evidence only, not proof of
safe concurrent preparation, invalidation, environment swapping, or service
performance.

## Limitations

The benchmark uses public-key synthetic fixtures with one source and one term
per package. Repeated loads are influenced by the operating-system page cache.
It does not establish cold-disk, multi-writer, crash-recovery, production
corpus, or terabyte-scale performance. The write measurement ends after the
candidate's commit/close or JSON `sync_all`; it does not include crash
injection, power-loss recovery, or proof that a newly created directory entry
survives every supported operating system.
