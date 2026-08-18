# EVO-X2 route-attention MCP experiment

This isolated deployment projects the verified Needle route-only runtime through
the separate `cantor-attention-mcp` server. It neither changes nor registers the
trusted `cantor-mcp` / `query_sop` surface.

Remote root: `C:\AI\services\cantor-attention-mcp`

The deployment contains the release executable, an operator-selected config,
and a descriptive deployment manifest. The adapter itself pins and rechecks the
Needle controller and runtime config, and the Needle runtime independently
checks its own deployment manifest on every operation.

The repository does not automatically add the server to Codex. Registration is
an explicit operator action after reviewing the binary, config, and tool
instructions.

Selected routes and archived refusals are symmetric evidence surfaces. A
selected route requires verified admission; an archived refusal requires the
same run identity to verify with recorded status `fault` and admission
`not_applicable`. Infrastructure faults without a run identity remain visibly
unverified. Every refusal remains an MCP tool error.
