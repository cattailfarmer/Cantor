# Cantor reflection loop P0 evidence

This directory preserves sanitized live evidence from the bounded EVO-X2
reflection-loop prototype. Failed predecessors remain visible because they are
falsification evidence, not disposable build noise.

Provider-private reasoning fields are removed by the Rust host before a report
is written. The reports contain model requests and public responses, exact MCP
structured results, ordered externalized states, typed faults, and deployment
hashes. They do not authorize the learned routes or any external effect.

The current accepted report is `script_acceptance_verified_v10.json` under
report profile 0.2. Its verifier reconstructs the complete request/import/output
path rather than trusting recorded headline fields. `script_acceptance_verified_v8.json`
is the preserved predecessor in which the tiny model repeated refusal prose
until its output budget was exhausted. Profile 0.2 closes that non-semantic
summary field to a case-specific constant; the successor v9 campaign passes.
The v10 successor additionally closes provider choice cardinality, mixed
answer-plus-tool output, verified-refusal status, and exact four-operator frame
shape while preserving the same report profile.

Earlier profile-0.1 reports remain historical observations tied to their
recorded runner binaries. The current crate integration fixture is the v10
profile-0.2 report.
