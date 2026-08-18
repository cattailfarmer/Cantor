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

One server process admits one route job at a time. Overlap receives immediate
`runtime_busy`; the adapter creates no hidden queue or retry. This is a
process-local resource permit, not a distributed singleton, fair scheduler, or
token-ring negotiation protocol.

Positive routes carry a verified `cantor-attention-frame/0.1` sequence:
`FOCUS`, `BOUND`, `ADMIT`, then `RETURN`. Omitted `response_mode` retains the
full proof-rich result. `response_mode: "frame"` returns the compact frame under
its distinct profile only after the same routing, digest, admission, archive,
verification, and single-flight work. Faults remain proof-rich and never carry
a positive frame.

Reproduce all three current full/frame measurements with:

```powershell
.\scripts\measure_attention_frame_response_modes.ps1
```

The observed reduction is bounded to the current catalogue and argument sizes;
it is not a future-procedure guarantee and does not reduce inference compute.
Deployment fingerprints, current results, and the operator-owned registration
boundary are consolidated in
[`../../docs/EVOX2_ATTENTION_RUNTIME_STATUS_2026-08-18.md`](../../docs/EVOX2_ATTENTION_RUNTIME_STATUS_2026-08-18.md).
