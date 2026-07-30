# Cantor

Cantor is an emerging SOP semantic coprocessor: a local,
provider-independent control layer that supplies verified Subject-Oriented
Programming definitions and operations to a neural inference model.

Cantor is designed to:

- compile governed SOP source into signed semantic packages;
- resolve subjects and perspectives through a typed semantic fabric;
- demand-load the smallest applicable SOP operation through `sop_query`;
- direct a replaceable inference provider such as Ollama;
- validate proposed judgments against meaning, evidence, constraints, and
  authority;
- preserve pertinent history, reflective review, provenance, and reentry
  state; and
- prevent unsigned or uncompiled content from acquiring semantic or
  executable authority.

## Current status

Cantor now has an executable safe-Rust trust, query, CLI, and read-only MCP
baseline:

- `cantor_core` defines versioned semantic machine forms and the original
  deterministic evaluator;
- the trusted-package compiler binds canonical package, semantic, source,
  dependency, proof, authority, compiler, validity, and exact-quote records
  with SHA-256 and distinct Ed25519 attestations;
- admission rejects unsigned, changed, corrupt, stale, revoked, expired,
  downgraded, mixed, scope-invalid, dependency-drifted, and structurally
  invalid packages;
- the in-memory semantic fabric serves the admission-verified signed exact
  index and performs contextual,
  typed-relation, and opt-in deterministic lexical lookup with visible
  ambiguity, exclusion, authority, absence, contradiction, and budget faults;
- query results carry verified quotes, package-bound typed paths, structured
  package/root proof, detail accounts, omissions, and a recomputable result
  digest; and
- the `cantor` executable exposes the same core through environment-bound
  `query` and `inspect` JSON operations with stable exit classes; and
- the `cantor-mcp` executable exposes exactly one local STDIO `query_sop`
  tool whose structured result is the same protocol response, with no
  transport-specific semantic authority; and
- `cantor_core::PreparedRuntime` retains at most one immutable exact-scope
  projection for repeated resident reads, with atomic generation replacement,
  invalidation, rollback, and the direct request path preserved; and
- `cantor-corpus` parses the bounded fail-closed
  `cantor-sop-source/0.1` profile, lowers exact source anchors and typed
  containment, compiles distinct-Ed25519 signed packages, and generates
  verified runtime/query artifacts from three reviewed Cantor specifications;
  and
- `cantord` keeps one fully admitted immutable generation resident behind an
  authenticated loopback-only protocol, while `cantorctl` provides strict
  status, query, inspect, compare-and-refresh, and exact-generation shutdown
  operations without acquiring semantic authority; and
- `cantor-mcp` may alternatively use `--service-config` to project its
  unchanged one-tool contract through that shared refreshable generation,
  while embedded `--environment` mode remains the rollback path; and
- the Windows supervised lifecycle scripts start `cantord` hidden, require
  authenticated readiness before atomic secret-free state publication,
  provide fresh authenticated health, and stop only a PID/start-time/executable
  match through exact-generation graceful shutdown; and
- `cantor_ecosystem` proves one commissioned, effect-free seven-message
  principal–manager–Codex–Cantor–Observer cycle with exact addressing,
  causal response contracts, authority containment, replay and budget gates,
  deterministic review, immutable failure prefixes, and a replay-verifiable
  transported outcome over a real signed `cantor_core` response.

Phase6 also measured canonical JSON snapshots against SQLite and redb at 1,
32, and 256 signed-package scales. JSON plus request-scoped admitted in-memory fabric is
retained because it remained the smallest and fastest current reconstruction
surface and neither embedded backend improved semantic query execution. See
[`docs/PERSISTENCE_DECISION.md`](docs/PERSISTENCE_DECISION.md).
The governed resident optimization, allocation cost, latency evidence, scope
boundary, and rollback decision are recorded in
[`docs/PREPARED_RUNTIME_DECISION.md`](docs/PREPARED_RUNTIME_DECISION.md).
The first real SOP self-hosting loop, operator commands, grammar boundary,
identity rules, key handling, generated artifacts, measurements, and
limitations are documented in
[`docs/SELF_HOSTED_CORPUS.md`](docs/SELF_HOSTED_CORPUS.md).
The resident service security boundary, operator publication sequence,
rollback path, and client contract are documented in
[`docs/RESIDENT_SERVICE.md`](docs/RESIDENT_SERVICE.md).
The first executable ecosystem protocol, exact route, authority boundary,
Observer checks, outcome verifier, and nonclaims are documented in
[`docs/SUPERVISED_MOCK_LOOP.md`](docs/SUPERVISED_MOCK_LOOP.md).

Protocol digests prove binding and internal consistency, not authenticity
against a hostile process that can replace both content and digest. The
stronger verifier re-executes against the supervisor-pinned signed
environment; the supervisor remains responsible for the executable and local
OS channel.

The original eight SOP CoreAcceptance fixtures remain passing:

1. aliases and contextual meanings remain distinguishable;
2. inference derivations expose premises and rules;
3. unknown knowledge remains distinct from invalid state;
4. pure transformations remain separate from effects;
5. effects are denied or authorized but never silently committed;
6. yielded state serializes, restores, and reenters exactly;
7. verbose and condensed forms compile to equivalent semantic IR; and
8. a SKOS relation imports with declared fidelity and lineage.

The earlier `llama.cpp` experiment proves a usable external tool-call
checkpoint seam. A physical database, remote or general-purpose service,
learned neural routing, FPGA execution, faculty runtime, provider inference,
and distributed execution remain deliberately inactive behind their evidence
gates.

Run the proof and fixture-only CLI demonstration locally:

```powershell
cargo test --workspace
cargo build --workspace --release
cargo run -p cantor_cli --example generate_demo -- .local\cantor-demo
.\target\release\cantor.exe query --environment .local\cantor-demo\environment.json --input .local\cantor-demo\query.json
.\target\release\cantor.exe inspect --environment .local\cantor-demo\environment.json --input .local\cantor-demo\inspect.json
.\target\release\cantor-mcp.exe --environment .local\cantor-demo\environment.json
```

Compile the reviewed self-hosted corpus with operator-supplied distinct keys:

```powershell
.\target\release\cantor-corpus.exe compile --manifest .\corpus\self_hosted\corpus.json --authority-key C:\secure\cantor-authority.key --compiler-key C:\secure\cantor-compiler.key --output .\.local\cantor-self-hosted
.\target\release\cantor.exe query --environment .\.local\cantor-self-hosted\environment.json --input .\.local\cantor-self-hosted\query-semantic-unit.json
```

Initialize and run the bounded resident service over a compiled environment:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\initialize_cantor_service.ps1 -EnvironmentPath C:\Project\Cantor\.local\cantor-self-hosted\environment.json -RuntimeDirectory C:\Project\Cantor\.local\cantor-service
.\target\release\cantord.exe --config C:\Project\Cantor\.local\cantor-service\service.json
.\target\release\cantorctl.exe status --config C:\Project\Cantor\.local\cantor-service\service.json --request-id request:operator_status_1
.\target\release\cantor-mcp.exe --service-config C:\Project\Cantor\.local\cantor-service\service.json
```

For a durable operator state record, replace the manual `cantord` launch with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_cantor_service.ps1 -ServerPath C:\Project\Cantor\target\release\cantord.exe -ClientPath C:\Project\Cantor\target\release\cantorctl.exe -ConfigPath C:\Project\Cantor\.local\cantor-service\service.json -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\get_cantor_service_health.ps1 -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop_cantor_service.ps1 -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json
```

The generated demo uses public fixture keys and must never become real
authority. See [`docs/CLI_PROTOCOL.md`](docs/CLI_PROTOCOL.md) for the trust
boundary, protocol verifier, Codex subprocess rules, and exit classes. See
[`docs/MCP_PROTOCOL.md`](docs/MCP_PROTOCOL.md) for the one-tool MCP contract,
Codex registration example, limits, and proof surface.

## Read first

Current build authority:
[`specifications/Cantor_Engine_Neural_Fabric_CLI_Build.sop`](specifications/Cantor_Engine_Neural_Fabric_CLI_Build.sop).

Current executable proofs:

- [`proofs/CEB_Slice_01_Core_IR_Proof.sop`](proofs/CEB_Slice_01_Core_IR_Proof.sop)
- [`proofs/CEB_Slice_02_Trusted_Package_Proof.sop`](proofs/CEB_Slice_02_Trusted_Package_Proof.sop)
- [`proofs/CEB_Slice_03_Deterministic_Query_Proof.sop`](proofs/CEB_Slice_03_Deterministic_Query_Proof.sop)
- [`proofs/CEB_Slice_04_CLI_Only_Proof.sop`](proofs/CEB_Slice_04_CLI_Only_Proof.sop)
- [`proofs/CEB_Slice_04_Codex_MCP_Proof.sop`](proofs/CEB_Slice_04_Codex_MCP_Proof.sop)
- [`proofs/Phase6_Persistence_Decision_Proof.sop`](proofs/Phase6_Persistence_Decision_Proof.sop)
- [`proofs/Cantor_Prepared_Runtime_Proof.sop`](proofs/Cantor_Prepared_Runtime_Proof.sop)
- [`proofs/Cantor_Self_Hosting_Ingestion_Proof.sop`](proofs/Cantor_Self_Hosting_Ingestion_Proof.sop)
- [`proofs/Cantor_Resident_Service_Proof.sop`](proofs/Cantor_Resident_Service_Proof.sop)
- [`proofs/Cantor_Service_Backed_MCP_Proof.sop`](proofs/Cantor_Service_Backed_MCP_Proof.sop)
- [`proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop`](proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop)
- [`proofs/Cantor_Supervised_Mock_Loop_Proof.sop`](proofs/Cantor_Supervised_Mock_Loop_Proof.sop)
- [`proofs/CEB_Deterministic_Baseline_Release_Audit.sop`](proofs/CEB_Deterministic_Baseline_Release_Audit.sop)

1. [`SOP_CORE_MAP.sop`](SOP_CORE_MAP.sop) — authority and project map
2. [`specifications/SOP_Core.sop`](specifications/SOP_Core.sop) — compact
   semantic programming core
3. [`specifications/Cantor_Semantic_Coprocessor_Identity.sop`](specifications/Cantor_Semantic_Coprocessor_Identity.sop)
   — converged component identity
4. [`specifications/Cantor_SOP_Query_Microkernel.sop`](specifications/Cantor_SOP_Query_Microkernel.sop)
   — lightest demand-loaded runtime
5. [`specifications/Cantor_Trusted_Compilation_Profile.sop`](specifications/Cantor_Trusted_Compilation_Profile.sop)
   — mandatory source authority boundary
6. [`specifications/Cantor_Llama_CPP_Tool_Reflection_Probe.sop`](specifications/Cantor_Llama_CPP_Tool_Reflection_Probe.sop)
   — first live provider contract
7. [`experiments/llama_tool_reflection/README.md`](experiments/llama_tool_reflection/README.md)
   — reproducible harness and run instructions

## Provenance

The project matured from the Large Language Model-Walker formation under
`C:\Project\Pinky\LargeLanguageModelWalker`. Those artifacts were copied
without rewriting signed specifications, so historical absolute paths remain
as provenance. New work is rooted in this repository.

Official repository: <https://github.com/cattailfarmer/Cantor>
