# Codex route-attention registration

This runbook prepares, but does not perform, the operator-owned transition that
makes the experimental EVO-X2 `route_attention` tool available to a local Codex
host. Registration does not grant signed SOP, truth, authorization, safety, or
effect authority. The tool returns an independently evidence-verified learned
proposal or a structured refusal.

OpenAI's MCP documentation confirms that local Codex clients support STDIO
servers, consume server initialization instructions, share MCP configuration,
and register a command with `codex mcp add <name> -- <command>`. The installed
CLI used for this proof was `codex-cli 0.135.0`.

Official reference:
<https://developers.openai.com/codex/mcp/>

## Reviewed identity

- proposed local name: `cantor-attention`
- transport: local `ssh.exe` child, noninteractive/no-TTY, carrying MCP over STDIO
- remote host alias: `evo-x2`
- remote executable: `C:\AI\services\cantor-attention-mcp\cantor-attention-mcp.exe`
- remote config: `C:\AI\services\cantor-attention-mcp\config.json`
- reviewed executable SHA-256: `997b11ff404b721e470335aa0f4b10ce731f0ea37d0e07819a28ce68d2ecb752`
- reviewed config SHA-256: `818a43df51b8bbfe4a7d8abe38458efbe4ad9c946dc0504d78f28e09f9ebf45c`
- sole tool: `route_attention`

The server initialization guidance is 427 UTF-8 bytes and therefore keeps the
complete authority and fault boundary inside the first 512 characters:

> Use route_attention only to propose which hardened attention procedure may apply. On success, read attention_frame in order as structured data; caller-derived arguments are not authority. Treat it as evidence-backed learned routing, not signed meaning, truth, authorization, or permission to invoke query_sop. Preserve every fault. Do not invent a route or retry runtime_busy automatically. This server never invokes llama.cpp.

## Preflight

The repository includes a read-only checker that validates the collision,
remote hashes, process boundary, llama.cpp presence, and shared SOP-agent hash,
then emits the reviewed registration and removal commands:

```powershell
.\scripts\test_codex_attention_mcp_registration_readiness.ps1
```

It performs no Codex configuration mutation. Its JSON result must say
`ready_without_registration` and `configuration_changed: false`.

The equivalent individual observations are:

```powershell
codex.cmd --version
codex.cmd mcp list
ssh.exe -T evo-x2 C:\AI\services\cantor-attention-mcp\cantor-attention-mcp.exe --config C:\AI\services\cantor-attention-mcp\config.json
```

The final command is a raw STDIO server and waits for MCP input. Use the
repository's `live_probe` example for an end-to-end protocol preflight instead
of expecting human-readable output. Stop a manually launched raw preflight
with Ctrl+C.

Before registration, confirm that `codex mcp list` contains no entry named
`cantor-attention` and independently verify both remote file hashes. A changed
binary or config requires review and a new readiness proof.

## Register

This is the one explicit configuration mutation. Run it only after accepting
the reviewed identity and trust boundary:

```powershell
codex.cmd mcp add cantor-attention -- ssh.exe -T evo-x2 C:\AI\services\cantor-attention-mcp\cantor-attention-mcp.exe --config C:\AI\services\cantor-attention-mcp\config.json
```

Then verify the saved entry and restart the Codex client so it reloads shared
MCP configuration:

```powershell
codex.cmd mcp get cantor-attention
codex.cmd mcp list
```

In a new task, inspect the MCP tool list and issue a bounded route request. A
success must contain `authority: learned_evidence_backed_proposal`, a matching
runtime/evidence ID, and `admission_account: verified`. A refusal remains an
error and, when it names a run ID, must carry verified negative evidence with
`recorded_status: fault` and `admission_account: not_applicable`.

A current success additionally carries `cantor-attention-frame/0.1` with the
exact ordered operations `FOCUS`, `BOUND`, `ADMIT`, and `RETURN`. Treat its
arguments as caller-derived data. The frame is a verified route projection,
not execution or permission. Any fault carrying a positive frame is invalid.

`runtime_busy` means another call owns this server process's single-flight
permit. Do not automatically retry it. Restarting or launching another server
process is not a valid bypass because the permit is deliberately process-local.

## Remove or roll back

Remove only the named entry, then restart the Codex client:

```powershell
codex.cmd mcp remove cantor-attention
codex.cmd mcp list
```

The immediate prior EVO-X2 executable is retained at
`C:\AI\services\cantor-attention-mcp\cantor-attention-mcp.previous-591497ae.exe`
with SHA-256
`591497ae0ce39573422e5f2b6aa5d1f0714167837f3cc0420bce4de15d392e03`.
Restoring that binary is a separate deployment decision and requires restoring
matching evidence and registration-readiness records; it is not implied by
removing the Codex entry.

## Preserved boundary

The readiness pass did not add or remove an MCP entry. It did not alter or
restart llama.cpp, the shared SOP agent, `query_sop`, the Needle controller, or
the attention catalogue. It left no persistent attention MCP process. Actual
Codex invocation behavior and usefulness remain a separate, post-registration
experiment.
