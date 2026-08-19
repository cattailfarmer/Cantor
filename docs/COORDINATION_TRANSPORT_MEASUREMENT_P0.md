# Coordination Transport Measurement P0

This experiment measures the exact compact JSON surface of Cantor's stateless
procedure-coordination tool. It uses the production public forms, serializer,
dispatcher, MCP metadata, and checked two-process candidate fixture.

It measures structured bytes only. It does not measure tokens, inference
context, latency, allocations, RSS, throughput, network framing, or model
quality.

## Result

The admitted context is 18,653 bytes. The genesis checkpoint is 4,628 bytes,
while the terminal outcome is 47,386 bytes. Complete tool metadata is 56,243
bytes: 34,666 bytes of input schema and 21,106 bytes of output schema.

| Step quota | Calls | Request bytes | Response bytes | Total bytes | Impossible zero-handle ceiling |
|---:|---:|---:|---:|---:|---:|
| 1 | 15 | 640,285 | 415,835 | 1,056,120 | 261,142 |
| 2 | 8 | 319,399 | 221,726 | 541,125 | 130,571 |
| 4 | 5 | 190,374 | 147,034 | 337,408 | 74,612 |
| 8 | 3 | 91,737 | 84,619 | 176,356 | 37,306 |
| 64 | 2 | 42,057 | 53,050 | 95,107 | 18,653 |

The “zero-handle ceiling” removes every repeated context after the first and
charges zero bytes for its replacement. No real registry can attain that
number because it needs at least an operation, handle, lineage, sequence, and
fault surface.

Quota eight reduces total structured transfer by about 83% relative to quota
one. Quota sixty-four reduces it by about 91%. In contrast, the impossible
context-only replacement ceiling is about 20–25% of total transfer across the
measured schedules. Dynamic checkpoints and the terminal result remain the
larger surface.

## Decision

A context-only registry is deferred. It would introduce custody, concurrency,
restart, and authentication obligations while attacking a secondary cost.
Coarser bounded stepping is the first optimization because it retains the
stateless proof and removes substantially more transfer.

If a stateful session layer is later governed, it should retain both the exact
admitted context and the current checkpoint and expose a small compare-and-set
continuation handle. Hashing only the static context is insufficient. A host
should also consider whether the model needs the full 56 KB tool schema at
all; deterministic host policy can call the typed tool while presenting a much
smaller semantic control surface to the model.

This is an architectural direction, not authority to implement the session
layer.

## Source correction

The preserved source expected fifteen terminal steps because the preceding
checkpoint fixture had that count. The independently admitted measurement lane
uses the same checked candidate but its exact successful outcome contains
fourteen steps. SJS therefore replaced the hard-coded count with a recorded
fixture value and requires every schedule to equal it. The raw source remains
unchanged so the correction is traceable rather than silently rewritten.

All schedules produced terminal outcome SHA-256
`cf7f8a3dabc33480f5eefd02e382eed716ab8a36a9166a7455a147a8225590b1`.

## Reproduction

Generate the deterministic report:

```powershell
cargo run -p cantor_coordination_measurement --locked
```

Verify generation, arithmetic, corruption refusal, scope refusal, and exact
tracked artifact equality:

```powershell
cargo test -p cantor_coordination_measurement --locked
```

The checked artifact is
[`experiments/coordination_transport_measurement/artifacts/coordination_transport_measurement_v1.json`](../experiments/coordination_transport_measurement/artifacts/coordination_transport_measurement_v1.json).
Canonical authority is
[`specifications/Cantor_Coordination_Transport_Measurement_P0.sop`](../specifications/Cantor_Coordination_Transport_Measurement_P0.sop),
with preserved source under
[`source_documents/2026-08-19_coordination_transport_measurement`](../source_documents/2026-08-19_coordination_transport_measurement/).

