# Cantor attention reentry ledger MCP

`cantor-attention-ledger-mcp` hosts one volatile, process-local,
content-addressed attention ledger and exposes one STDIO tool:
`continue_attention_session`.

The first `open` request carries a complete validated frame. Later `apply`
requests carry only the session operation and exact compare-and-set bindings:
ledger digest, session sequence, and head frame digest. `inspect`, `read_frame`,
and `read_event` make all retained state explicit.

```powershell
cargo build -p cantor_attention_ledger_mcp --release
.\target\release\cantor-attention-ledger-mcp.exe --ledger-id ledger:local-session
```

This P0 process is not durable. Restart loses every session. It has no network
listener, authentication, signing authority, model provider, or effect broker.
Host registration and persistence are separate governed steps.

The command lifecycle, compare-and-set contract, fault boundary, and proof
commands are documented in
[`docs/ATTENTION_REENTRY_LEDGER_P0.md`](../../docs/ATTENTION_REENTRY_LEDGER_P0.md).
