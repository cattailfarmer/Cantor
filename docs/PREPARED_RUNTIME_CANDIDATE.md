# Cantor prepared-runtime candidate

Status: superseded by the governed implementation and
[`PREPARED_RUNTIME_DECISION.md`](PREPARED_RUNTIME_DECISION.md). This document
remains the preserved Phase6 research handoff and is not implementation
authority.

## Why this candidate exists

The Phase6 persistence experiment found no present reason to add SQLite or
redb. It also exposed the actual repeated-query cost: the resident MCP adapter
keeps an `EmbeddedRuntimeEnvironment`, but every request recomputes its digest,
re-admits every package, and rebuilds `SemanticFabric`.

Across three warm 256-package profiles:

| Stage | Median range |
|---|---:|
| Environment digest | 1.629–1.783 ms |
| Package admission plus fabric construction | 19.665–19.875 ms |
| Query against an already prepared fabric | 0.044–0.045 ms |
| Complete current protocol request | 21.943–22.441 ms |

The prepared query returned exactly the same query result carried by the full
`ProtocolResponse`. This decomposition locates work; it does not predict the
latency of a correct prepared protocol.

## Candidate contract

A future `PreparedRuntime` would be immutable and bound to exactly one:

- environment version and environment digest;
- trust policy, trust time, and revocation/staleness state;
- complete ordered signed-package set and package digests;
- admitted semantic fabric; and
- protocol-policy version.

Preparation may perform full package verification and fabric construction
once. Every request must still validate protocol version, caller and purpose,
read-only effect boundary, expected environment digest, complete expected
package set, requested scope, operation binding, and budgets. Responses must
retain the same status, exit class, faults, proof, continuation, and normalized
result as `execute_protocol_request`.

Prepared state must never outlive or silently cross an environment, trust,
time, revocation, package, compiler-policy, or protocol-policy change.

## Ownership problem

The obvious implementation is too wasteful:

1. `EmbeddedRuntimeEnvironment` owns every `CompiledSourcePackage`.
2. Admission clones each complete package into `AdmittedPackage`.
3. `SemanticFabric` clones units, relations, labels, and identities into
   indexes.

Keeping both environment and fabric resident therefore duplicates package
content and adds index copies. The design should either share immutable package
ownership explicitly or let the prepared runtime replace the raw environment
after retaining every input needed for request validation, inspection, and
proof.

Serialized JSON bytes are not a heap measurement.

## Evidence already established

- `SemanticFabric` is `Send + Sync`.
- Eight threads performed sixteen reads each against one immutable 32-package
  fabric.
- All 128 results matched each other and the result inside the full protocol
  response.
- This proves bounded immutable-read determinism only. It does not prove
  concurrent preparation, invalidation, swapping, service performance, or
  memory adequacy.

## Required next SJS slice

Before implementation, preserve a new source statement and process it through
SJS. Its minimum acceptance surface should include:

1. exact `ProtocolResponse` equivalence for query and inspect success, partial,
   trust, policy, invalid-request, unresolved, ambiguity, and budget outcomes;
2. no skipped caller, purpose, effect, digest, package-set, scope, policy,
   budget, or proof gate;
3. immutable generation identity and fail-closed invalidation;
4. deterministic concurrent reads and atomic whole-generation replacement;
5. measured retained and peak heap over representative sources, units,
   relations, aliases, quotes, and labels;
6. warm and cold preparation cost separated from repeated-request cost;
7. rollback, revocation, trust-time, and stale-generation tests;
8. no semantic logic in the MCP adapter; and
9. rejection of the optimization if measured gain does not justify its memory
   and lifecycle complexity.

## Explicit non-decisions

- No production `PreparedRuntime` exists yet.
- No cache, database, writer, service-state mutation, or new authority was
  added.
- No 0.044–0.045 ms end-to-end latency claim is made.
- No memory, production-corpus, invalidation, or multi-tenant claim is made.
