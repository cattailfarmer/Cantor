# Cantor coordination MCP

`cantor-coordination-mcp` exposes one local STDIO tool,
`step_procedure_coordination`. It is a stateless transport over Cantor's pure
resumable procedure coordinator.

Use `begin` with a complete `CoordinationToolContext` to receive a genesis
checkpoint. Use `advance` with that same exact context, one checkpoint, and a
positive `maximum_steps` quota. A successful advance returns either a paused
successor checkpoint or the existing terminal coordination outcome.

The authoritative result is `structuredContent`. The server retains no
context, checkpoint, or model state, invokes no provider, performs no external
effect, and does not modify a live inference pass. A host can present the tool
result to a model in a later ordinary tool-loop pass.
