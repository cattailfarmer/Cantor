# Cantor embedded CLI protocol

Cantor exposes the same read-only `cantor_core` operations through two commands:

```text
cantor query   --environment <operator-controlled-environment.json> [--input <request.json>]
cantor inspect --environment <operator-controlled-environment.json> [--input <request.json>]
```

When `--input` is omitted, the versioned protocol request is read from standard input. Standard output contains exactly one compact JSON `ProtocolResponse` and one terminating newline. Diagnostics go only to standard error.

## Authority separation

The request cannot supply trust roots, recognized packages, or current trust time. Those values live in a separate `EmbeddedRuntimeEnvironment` file selected by the supervising process. The request binds:

- the SHA-256 digest of the complete expected environment;
- every expected package identity and signed package digest;
- the caller identity, purpose, read-only effect boundary, and semantic scope; and
- the operation-specific query or inspection.

Cantor rejects an environment or package substitution before semantic lookup. The response repeats the observed environment digest and admitted package identities as protocol proof.

The environment file is a local trust-root asset. Keep it operator-controlled and pass a pinned absolute path from Codex or another supervisor. Do not let model-generated text choose or rewrite that file.

The embedded timestamp is also operator authority. Digest binding detects a
substituted environment, but it cannot by itself detect coordinated replay of
an older request and older once-valid environment. A production supervisor
must supply trusted current time, enforce anti-rollback/freshness policy, and
retain revocation state.

Caller identity and allowed scope in the request are declarations, not an
authentication mechanism. Cantor proves that query scope stays within the
envelope and signed package authority; a production supervisor must
authenticate the caller and construct or constrain those declarations from
its own ACL policy.

## Exit classes

| Code | Class | Meaning |
|---:|---|---|
| 0 | `success` | Complete successful result |
| 2 | `invalid_request` | Invalid arguments, JSON, protocol, schema, or request budget |
| 3 | `trust_failure` | Environment, package, certificate, signature, freshness, or expected-digest failure |
| 4 | `unresolved` | Unknown, ambiguous, absent, or unsupported semantic dependency |
| 5 | `policy_denial` | Caller, purpose, scope, or read-only policy mismatch |
| 6 | `semantic_fault` | Contradiction, proof gap, or exhausted execution budget |
| 70 | `internal_fault` | CLI serialization or internal invariant failure |

Nonzero results still emit a structured response. A caller must inspect both the process exit code and response envelope. Failure never licenses fabricated SOP guidance.

## Generate and run the fixture-only demonstration

The generator contains public fixed test keys. It is for protocol exploration only.

```powershell
cargo run -p cantor_cli --example generate_demo -- .local\cantor-demo
cargo build -p cantor_cli --release
.\target\release\cantor.exe query `
  --environment .local\cantor-demo\environment.json `
  --input .local\cantor-demo\query.json
.\target\release\cantor.exe inspect `
  --environment .local\cantor-demo\environment.json `
  --input .local\cantor-demo\inspect.json
```

The explicit files avoid Windows PowerShell's legacy native-pipeline text encoding. A Codex subprocess should instead write UTF-8 JSON bytes directly to standard input.

The first command compiles and signs one fixture SOP unit, then writes:

- `environment.json`: local trust store plus the signed compiled package;
- `query.json`: an environment- and package-bound semantic query; and
- `inspect.json`: an environment- and package-bound fabric inspection.

Never promote the demo keys or generated environment into real semantic authority.

## Codex subprocess rule

A Codex integration should:

1. use an absolute, supervisor-pinned environment path;
2. send request JSON through standard input;
3. set process timeout and output limits;
4. require a valid response protocol version and matching request identity;
5. require the expected environment, package, and result digests;
6. preserve nonzero exit classes and faults in the surrounding task record; and
7. inject only verified result and proof fields as Cantor reflection context.

The Rust caller helper `verify_protocol_response(request, response)` checks the
request and operation identities, protocol version, environment digest,
complete admitted-package set, expected package digests, status/exit/outcome
consistency, protocol-to-core digest binding, recomputed core result digest,
exact partial-fault projection, typed continuation consistency, and package
provenance before the response is used. Semantic-unit inspection also carries
the signed source-document digest alongside its byte-exact quote. Query and
inspection results are both independently digest-bound.

`verify_protocol_response` proves schema, binding, and digest consistency. A
digest is not a response signature: an attacker who can replace both the
result and its digest is outside that helper's guarantee. For a stronger local
check, `verify_protocol_response_against_environment` repeats the request
against the supervisor-pinned signed environment and requires exact response
equality. The supervising process must still trust the Cantor executable and
its local OS channel. Near-expired elapsed-time budgets can make exact
re-execution intentionally conservative; use a sufficient time budget for
verified complete results.

MCP, a resident daemon, write operations, and effect execution are not active in this CLI profile.
