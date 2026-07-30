# Read-only live Codex adapter

Cantor can now replace the mock worker boundary with one real Codex App Server turn while retaining the existing deterministic seven-message ecosystem protocol and Observer review.

This is a narrow inference-coprocessor seam. It is not a persistent manager, shared hidden state, automatic retry loop, effect broker, or multi-agent deliberation runtime.

## What the adapter does

1. Validates absolute, non-symlink paths and lowercase SHA-256 pins for the Codex executable, `cantor-mcp`, and signed environment.
2. verifies the exact bounded `codex --version` result.
3. starts the pinned executable as an App Server over stdio JSONL.
4. creates one ephemeral thread with approval policy `never` and a read-only sandbox.
5. starts one turn with `readOnly`, `networkAccess: false`, one assignment, and a closed output schema.
6. admits only one exact `cantor.query_sop` call whose argument is the supervisor-issued `ProtocolRequest`.
7. decodes authoritative MCP `structuredContent` as `ProtocolResponse` and runs the core verifier.
8. strictly parses one final candidate, rejects duplicate set members, requires all criteria, requires no effects, and requires proof references to equal the supervisor-admitted set.
9. binds request, response, and exact final-message bytes to independent SHA-256 evidence.
10. replays the observed exchange through the logical `cantor_query`, `cantor_return`, and `candidate` stages and lets the deterministic Observer decide.

The process boundary uses a synchronous two-line stdout queue, bounds each
line before allocation, continues draining stderr after its retention limit,
terminates partially initialized children, validates the authority returned by
`thread/start`, and requires graceful successful App Server exit.

The physical model turn finishes before the buffered exchange is translated into those three logical messages. This preserves the ecosystem contract for review and evidence; it does not claim to alter causal order inside model inference.

## Operator probe

Build the production MCP server and examples:

```powershell
cargo build --release -p cantor_mcp --bin cantor-mcp
cargo build --release -p cantor_ecosystem --examples
```

Prepare a probe input from explicit local artifacts:

```powershell
target\release\examples\prepare_live_codex_probe.exe `
  C:\absolute\path\to\codex.exe `
  C:\absolute\path\to\cantor-mcp.exe `
  C:\absolute\path\to\environment.json `
  C:\absolute\path\to\protocol-request.json `
  C:\absolute\working\directory `
  C:\absolute\probe-input.json
```

Run one separately authorized live turn:

```powershell
target\release\examples\live_codex_probe.exe C:\absolute\probe-input.json
```

Successful stdout is one JSON object containing `LiveTurnEvidence` and the complete validated `CycleOutcome`. Diagnostics and typed failures go to stderr. The operator should redirect stdout and stderr separately.

The preparation utility writes no credential. The adapter delegates provider authentication to Codex and never reads, copies, serializes, or logs the credential.

## Fail-closed behavior

The cycle stops before candidate admission on any of these conditions:

- executable, version, environment, path, digest, route, or budget mismatch;
- malformed, oversized, uncorrelated, unknown, duplicate, premature, or failed JSON-RPC traffic;
- any server request requiring approval, input, permission, elicitation, attestation, or dynamic callback;
- any started item other than passive reasoning/message/plan items or the exact Cantor MCP call;
- a second tool call, altered arguments, different completed call identity, failed tool, missing structured response, or protocol verification failure;
- a final answer before Cantor, multiple final answers, missing final answer, unknown or missing criterion, invented proof identity, requested effect, or candidate/evidence digest mismatch;
- interrupted or failed terminal turn, timeout, early EOF, or process cleanup failure.

A model can still attempt a forbidden read-only built-in action before the App Server reports its started item. The adapter rejects and terminates at the first observable event; the current profile does not claim pre-inference tool masking beyond the read-only/no-network sandbox and exact MCP configuration.

## Live proof recorded on 2026-07-30

The finalized adapter completed an explicit probe with:

- `codex-cli 0.146.0`;
- exact Codex executable SHA-256 `bc343ba420dc2e2e9f59e6fc5e5bf0aae1cd8c771fc319665241fc9c0271fddb`;
- exact `cantor-mcp` SHA-256 `fa81784fd9c6f40a23074d822048a1a441a5764dc9af4c676180feaa64fd26b3`;
- exact environment SHA-256 `5e81ac0151353c19e6be3fd3975fa315e6cdd2c90944aa83c1ee91d6a9a338c3`;
- one `cantor.query_sop` call;
- 89 admitted App Server events and 44,831 received bytes;
- zero advisories and zero requested effects;
- a verified response digest `801558450a76dee795d3abd9e453a92088b8a2a45b375e71ebf57aa8358768d4`;
- Observer `accept` and manager `accept`.

The fault ledger also preserves real rejected attempts: an outdated Codex version, an unsupported schema keyword, and final answers produced before the required tool. None entered a candidate into the ecosystem.

## Authority that remains locked

This slice does not authorize workspace writes, provider selection, automatic retry, steering, persistent threads, notification-driven continuation, approval forwarding, dynamic tools, autonomous Shaliach management, multiple workers, effect execution, KV-cache or hidden-state access, FPGA compilation, or learned neural routing.
