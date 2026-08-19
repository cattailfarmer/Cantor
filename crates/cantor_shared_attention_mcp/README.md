# Cantor shared-attention MCP adapter

`cantor-shared-attention-mcp` exposes the pure shared-attention state machine
through one stateless STDIO MCP tool named `coordinate_attention`.

Each call carries a complete `SharedAttentionToolRequest` under the `request`
property. The server returns the complete `SharedAttentionToolResponse` as
`structuredContent`. It stores no current frame and invokes no model, network,
signed SOP query, route-selection runtime, or external effect.

The intended host loop is:

```text
model pass -> proposed typed request -> coordinate_attention
           -> exact successor/backpressure/refusal -> later model pass
```

This is shared semantic state between passes, not shared hidden state or
mid-token insertion. Settlement is a coordination checkpoint, not proof of
external truth; DreamFrame content remains hypothetical.

Build and run with:

```powershell
cargo build -p cantor_shared_attention_mcp --release
target\release\cantor-shared-attention-mcp.exe
```

Host registration is deliberately outside this P0 adapter slice.
