# Cantor MCP adapter

`cantor-mcp` is a local STDIO Model Context Protocol server. It is a transport
projection of `cantor_core`, not a second inference engine or authority layer.

## Contract

The server publishes exactly one tool:

- name: `query_sop`
- input: `{ "request": <ProtocolRequest> }`
- structured output: the existing `ProtocolResponse`
- annotations: read-only, non-destructive, idempotent, closed-world

The nested `ProtocolRequest` is the same strict request accepted by the
`cantor query` and `cantor inspect` CLI operations. It pins the caller,
purpose, read-only effect boundary, environment digest, expected signed
packages, requested authority scope, operation, and query budget.

The adapter does not infer omitted authority. Unknown fields and malformed
identities are rejected. Trust, scope, ambiguity, absence, contradiction, and
budget outcomes remain visible in the structured response. A non-successful
Cantor protocol response is also marked as an MCP tool error so the model
cannot mistake it for successful authority.

## Invocation prerequisite

Registration is not sufficient by itself. Before the first call, a trusted
supervisor must give the model a valid `ProtocolRequest` template containing
the caller identity, purpose/effect policy, pinned environment digest,
expected signed package set, and allowed scope. The model may specialize the
authorized query fields and request ID only as that supervisor permits.

Cantor deliberately does not mint or guess these bindings from model prose.
The fixture generator writes usable `query.json` and `inspect.json` examples.
A later convenience/bootstrap surface would need its own governed authority
contract; it is not smuggled into this one-tool slice.

## Startup

Build the workspace and generate the public-key fixture environment:

```powershell
cargo build --workspace --release
cargo run -p cantor_cli --example generate_demo -- .local\cantor-demo
```

Run the server directly:

```powershell
.\target\release\cantor-mcp.exe --environment .local\cantor-demo\environment.json
```

STDOUT is reserved for MCP JSON-RPC frames. Startup and operational diagnostics
go to STDERR. The process validates the environment version, byte limit,
recognition certificates, trust policy, signatures, validity windows, scope,
and global fabric identities before opening the server.

The generated demo uses public fixture signing keys. It proves the protocol,
but it is not production authority.

## Prepared runtime

The server owns one core `PreparedRuntime` for the lifetime of the process.
After a request passes its independent environment-digest, package-set,
caller, purpose, effect, and protocol gates, the runtime may reuse one
immutable `SemanticFabric` prepared for the structurally exact requested
`AuthorityScope`. A different valid scope builds and atomically replaces the
complete projection. It never treats a broader, narrower, overlapping, or
similar scope as equivalent.

This is a physical execution optimization in `cantor_core`; the adapter has no
cache or semantic policy of its own. The direct request-scoped protocol path
remains the deterministic oracle and rollback. Trust time is still the pinned
environment `now_epoch_seconds`, so a time or security-state change requires a
new environment generation rather than mutation of the active runtime.

## Codex registration

The operator may register the local subprocess with Codex:

```powershell
codex.cmd mcp add cantor -- .\target\release\cantor-mcp.exe --environment C:\absolute\path\to\environment.json
codex.cmd mcp list
```

This repository does not alter user or workspace Codex configuration
automatically. Registration is an operator-owned trust decision. Use an
absolute environment path so the server does not depend on the client's
working directory. The `.cmd` launcher avoids a PowerShell script-execution
policy blocking the npm-installed `codex.ps1`; shells where `codex` resolves
directly to an executable may use `codex` instead.

Suggested server instruction:

> Use `query_sop` only when the current subject may be governed by the loaded
> signed SOP environment and a trusted supervisor supplied a request template.
> Treat `structuredContent` as the authoritative `ProtocolResponse`. Preserve
> faults, proof, and continuation. Do not invent caller, package, digest, or
> scope bindings.

The adapter also supplies equivalent instructions during MCP initialization.
Its text content is only a short status summary; the complete authoritative
result remains in `structuredContent`.

## Trust boundary

Cantor verifies signed packages inside the pinned environment and binds each
request to that environment's digest. The process supervisor remains
responsible for:

- the integrity of the `cantor-mcp` executable;
- the environment file path and OS access controls;
- deciding which signing authorities enter the trust store; and
- launching the process without an untrusted wrapper.

The adapter has no network transport, write tool, package compiler, signing
key, trust-store mutation, model inference, persistent database, mutable or
cross-process shared state, unbounded cache, learned router, or FPGA path.

## Limits

- environment file: 64 MiB
- tool argument object: 1 MiB
- semantic query result: bounded again by the request's `QueryBudget`

The outer limits protect the adapter. The inner Cantor budget remains part of
the signed, replayable protocol response.

## Verification

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release
```

The test suite proves:

- the server publishes exactly one tool with the declared annotations;
- malformed arguments produce visible structured tool faults;
- trust failures remain exact `ProtocolResponse` values;
- direct core, CLI, and MCP adapter results are equivalent; and
- repeated equal calls prepare once and then use the same exact-scope core
  projection; and
- an official Rust MCP client can initialize, list, and call the real STDIO
  subprocess without contaminating its framing channel.
