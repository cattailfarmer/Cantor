# Cantor route-attention MCP adapter

`cantor-attention-mcp` is a separate experimental STDIO MCP server for the
verified Needle route-only runtime. It does not replace or extend the trusted
`cantor-mcp` / `query_sop` server.

It publishes exactly one tool, `route_attention`, accepting
`{"stimulus":"..."}`. A selected route is returned only after the runtime's
independent evidence verifier confirms the run and its admission account.
Learned selection remains a proposal; it is not signed meaning, truth,
authorization, or permission to call another tool.

The operator supplies an absolute closed configuration and explicitly registers
the built executable. Repository code does not edit Codex configuration.

```powershell
cargo build -p cantor_attention_mcp --release
codex.cmd mcp add cantor-attention -- C:\absolute\cantor-attention-mcp.exe --config C:\absolute\attention-mcp.json
```

The adapter invokes the pinned Python controller by direct argument vector,
always with `--route-only`, then invokes `verify --id <run-id>`. It opens no
listener, uses no shell, calls no llama endpoint, mutates no trust store, and
contains no signing material.
