# Cantor compact coordination MCP

`cantor-compact-coordination-mcp` exposes one volatile local STDIO tool,
`continue_procedure_session`.

`open` imports an exact `CoordinationToolContext` as a bounded JSON string and
returns a digest-bound handle. `advance` uses only the current registry digest,
session identity, sequence, record digest, and positive step quota. `inspect`
returns the current handle. `read` returns exact retained record JSON so
process custody does not become invisible authority.

Every mutation uses compare-and-set lineage and is serialized inside the
process. Restart loses all sessions. The server has no durable persistence,
authentication, provider access, model access, network listener, or external
effect authority.
