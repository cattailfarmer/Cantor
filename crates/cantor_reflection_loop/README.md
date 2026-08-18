# Cantor reflection loop P0

This experimental executable joins two existing seams without modifying either:

1. an unmodified llama.cpp server emits one structured `route_attention` call;
2. the host validates it and invokes the pinned Cantor attention MCP process;
3. a second llama.cpp pass reflects over the exact structured result; and
4. the host validates and stores a sanitized, ordered execution trace.

The `positive`, `refusal`, and `control` cases are deliberately closed. A pass
proves only this bounded externalized tool/reflection loop. It does not make a
route signed SOP authority, authorize an effect, expose hidden model state, or
establish a general agent runtime.

Run `cantor-reflection-loop --help` for the live CLI contract.

Use `verify --report <path>` to replay deterministic acceptance over a preserved
full report. Use `inspect --report <path>` to emit a compact, verified projection
of the walked states, tool status, procedure, evidence reference, timing, and
token counts. Neither command reruns model inference or upgrades authority.

Use `contract` to print the machine-readable report and trace profiles, exact
case set, pass and call limits, state paths, authority boundary, and excluded
private fields without contacting llama.cpp or launching the MCP adapter.

From the repository root,
`scripts/test_cantor_reflection_loop_p0.ps1` runs the complete effect-free
offline acceptance surface against the pinned current evidence.
