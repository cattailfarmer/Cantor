# Semantic inspection consumer handoff

Cantor now supplies a one-shot semantic-inspection executable, an exact wire
library, and an effect-free consumer contract/transcript verifier. The consumer
crate is `cantor_sop_inspect_consumer`; the executable remains the previously
published `cantor-sop-inspect-stdio`.

This is an engine handoff, not an installed Scribe/Eclipse integration. The
application owns discovery, trusted executable selection, launch policy,
timeouts, packaging, presentation, and acceptance. A verified transcript proves
correspondence of supplied bytes, not that a particular executable ran.

## Portable contract

`contract()` returns the supported
`cantor-semantic-inspection-consumer-contract/0.1` value. `parse_contract()`
accepts only that exact supported value and seal; future or altered coordinates
are refused even when somebody recomputes a hash.

The host invocation has zero arguments. Write the complete UTF-8 request bytes
to stdin, then close stdin to deliver EOF. The host does not dispatch before EOF.
It emits one exact wire JSON value without a newline, prefix, or suffix and then
exits. This is **not MCP JSONL**, a resident service, or a multi-request session.

The contract inherits the existing wire limits: request at most 80 MiB + 64 KiB,
response at most 128 MiB + 64 KiB. The pure transcript verifier accepts at most
one extra request byte to witness the deterministic overflow refusal; stderr is
bounded at 128 bytes. These are machine safety ceilings, not recommended model
context sizes. Applications should normally choose much smaller task packets.

| Observed outcome | Exit | stdout | stderr |
| --- | --- | --- | --- |
| Inspection succeeded | 0 | Exact sealed wire response, `succeeded` | Empty |
| Semantic request refused | 0 | Exact sealed wire response, `refused` | Empty |
| Invalid outer request | 2 | Empty | Exactly `cantor_stdio_host_refused\n` |
| Partial output, timeout, signal, unexplained failure | Failure | Do not accept | Do not turn into a success receipt |

Exit 0 means completed transport, not necessarily a successful semantic query.
A valid outer request receiving a host fault is an incomplete/unexplained
execution; the consumer does not reclassify it as deterministic input refusal.

## Acceptance API

```rust
use cantor_sop_inspect_consumer::{Transcript, verify, validate_receipt};

let transcript = Transcript { exit_code, stdout: &stdout, stderr: &stderr };
let receipt = verify(&exact_request_bytes, transcript)?;
validate_receipt(&exact_request_bytes, transcript, &receipt)?;
```

`verify` reconstructs the published wire result and compares stdout byte for
byte. It returns `inspection_succeeded`, `semantic_refused`, or `host_refused`.
Receipts bind raw request/stdout/stderr SHA256, byte counts, exit, outcome,
contract digest, wire coordinates, non-authority, and a canonical receipt seal.
Raw request padding changes its receipt even if semantic parsing is unchanged.

`parse_receipt` checks bounded strict shape and seal only. Always use
`validate_receipt` with the actual retained request and transcript for acceptance.
Self-consistent hashes alone are not evidence of correct execution. No receipt
grants operator approval, model authority, application acceptance, or effects.

## Golden fixtures and replay

`fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json` includes the
portable contract and eight cases: Unicode success, empty page, page one, page
two, nested refusal, malformed outer input, unknown outer field, and empty
outer input. Each case retains exact request/stdout/stderr strings, exit code,
and the expected receipt. Encode these strings directly as UTF-8 without a BOM;
do not parse and reserialize their nested request strings before byte replay.

The test exporter regenerates the entire bundle byte-identically. Development
tests run each case in a fresh host process, concurrently drain bounded outputs,
close stdin, enforce a ten-second whole-exchange deadline, and kill on abandoned
exchange. A separate stalled-EOF adversary verifies timeout/kill/reap behavior.
This harness is test-only, not a production launcher.

From the repository, the scoped verification commands are:

```powershell
./scripts/test_cantor_semantic_inspection_consumer_handoff_p0.ps1 -Profile debug
./scripts/test_cantor_semantic_inspection_consumer_handoff_p0.ps1 -Profile release
```

Both use the existing `D:\CantorBuilds\target`, one Cargo build job, no
incremental compilation, locked offline dependencies, and serialized tests.
Build output and logs are replaceable development material, not the runtime SOP
seed and not committed fixture knowledge.

## Provenance and application frontier

The unchanged stdio implementation was published at
`075eeb7f02e5dfc816dba5aae93be72ee24174c3`. Consumer formation is
`5d4842c9f2e4bf58b38da3c859f29c01e5724ad8`, immediately bookended by
`ceee406e6ff4f5f4a34c6b56f8116a3fc4778b86`. Its procedural SJS signature is
`3a2306de-7074-4e99-b72d-37f2e911302d`, canonical specification
`6abf0365-921b-4d9c-a794-a65ae187ffae`.

The separately owned Scribe/Eclipse application may consume the verified
published contract under its own source/authority gates. Cantor does not edit
its board, launch another agent, message another conversation, merge branches,
install an extension, load a model, or contact EVO-X2 through this handoff.
Official MCP requires a separately signed adapter; stdin/stdout transport alone
does not make this executable an MCP server.
