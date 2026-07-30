# Cantor persistence decision benchmark

This disposable Phase6 lab compares physical reconstruction of the same
immutable signed `EmbeddedRuntimeEnvironment` through:

1. one compact JSON snapshot;
2. SQLite environment metadata plus ordinal package rows; and
3. redb environment metadata plus ordinal package values.

It does not replace `SemanticFabric`, query through SQL, or grant database
records authority. Every reconstructed environment must match the source
digest and return the exact direct-core `ProtocolResponse`.

Current backend report schema is `cantor-persistence-benchmark/0.4`; it includes
the post-measurement ordinal, identity, and digest metadata-integrity checks
under unsafe-forbidden, overflow-checked release compilation.

The lab also contains six persistence evidence tests:

1. exact signed-environment, digest, and response round trip;
2. persisted semantic tampering remains a visible trust failure; and
3. malformed physical artifacts fail closed; and
4. the three tracked raw reports mechanically reproduce every numerical range
   and content digest in the decision summary; and
5. SQLite ordinal, package-identity, and package-digest inspection metadata
   must match the signed package records; and
6. redb ordinal keys must remain contiguous before reconstruction.

Run:

```powershell
cargo run --manifest-path experiments\persistence_benchmark\Cargo.toml --release --bin cantor-persistence-benchmark -- .local\persistence-benchmark
```

The program creates a timestamped run directory under the supplied output
root and prints the path of its machine-readable `report.json`.

The report distinguishes file size immediately after durable write from file
size after the reopen/load cycle because an embedded engine may change its
physical allocation during open or recovery.

The decision artifacts retain the three raw `report.json` files as well as the
aggregate summary. Their hashes and aggregate ranges are checked during tests,
so the evidence can be audited without relying on the ignored local run tree.

The generated packages use public fixture keys. Results are warm local
reopen/reconstruction microbenchmarks over synthetic structural scales, not
cold-disk, production-corpus, concurrent-service, or terabyte claims.

An additional runtime-decomposition probe separates the present per-request
environment digest, package admission plus fabric construction, prepared
query, and full protocol costs:

```powershell
cargo run --manifest-path experiments\persistence_benchmark\Cargo.toml --release --bin runtime_decomposition -- .local\persistence-benchmark\runtime-decomposition.json
```

This probe identifies an optimization surface. It does not claim that a future
prepared protocol can omit request validation, scope gates, expected-package
checks, proof assembly, revocation handling, or other authority work.

The tracked runtime evidence contains three raw profiles and
[`artifacts/2026-07-29_runtime_decomposition_summary.json`](artifacts/2026-07-29_runtime_decomposition_summary.json);
the test suite recomputes their hashes and every aggregate median range and p95
maximum.

[`artifacts/phase6_evidence_manifest.json`](artifacts/phase6_evidence_manifest.json)
content-addresses the preserved source, SJS authority and research lineage,
five benchmark source files, isolated dependency lock, all six raw reports, and
both summaries. The manifest test resolves
all manifest paths inside the repository and recomputes every digest.

Two further candidate/governance tests prove immutable prepared-fabric
read determinism across eight threads and close the Phase6 SJS identity chain.
