# Cantor MCP adapter

`cantor-mcp` is a local STDIO Model Context Protocol server. It is a transport
projection of `cantor_core`, not a second inference engine or authority layer.

## Contracts

Embedded `--environment` mode publishes two tools:

- name: `query_sop`
- input: `{ "request": <ProtocolRequest> }`
- structured output: the existing `ProtocolResponse`
- annotations: read-only, non-destructive, idempotent, closed-world
- name: `lookup_sop_anchors`
- input: `{ "text": <string>, "include_source"?: <boolean>,
  "maximum_postings"?: <integer>, "maximum_matches"?: <integer> }`
- structured output: the existing `LexicalAnchorLookupResult`, the pinned
  environment digest, and by default an exact `SourceProjectionResult`
- annotations: read-only, non-destructive, idempotent, closed-world

Resident `--service-config` mode publishes only `query_sop`. The resident
service protocol does not yet carry the derived lexical sidecar; the adapter
does not silently rebuild it from a mutable filesystem or substitute a
different generation.

The nested `ProtocolRequest` is the same strict request accepted by the
`cantor query` and `cantor inspect` CLI operations. It pins the caller,
purpose, read-only effect boundary, environment digest, expected signed
packages, requested authority scope, operation, and query budget.

The `lookup_sop_anchors` tool tokenizes ordinary input, searches the immutable
lexical index prepared from the admitted signed generation at startup, orders
the bounded matches deterministically, and projects exact admitted paths,
line spans, quotations, document and certificate identities, and proof
digests. `include_source` defaults to `true`. The result states lexical
correspondence and signed-snapshot provenance; it does not state that a record
is true, applicable, permitted, safe, or authoritative for the caller's
purpose. Those decisions remain separate protocol work.

The adapter does not infer omitted authority. Unknown fields and malformed
identities are rejected. Trust, scope, ambiguity, absence, contradiction, and
budget outcomes remain visible in structured results. A non-successful Cantor
result is also marked as an MCP tool error so the model cannot mistake it for
successful authority.

## Invocation prerequisite

Registration is not sufficient to call `query_sop`. Before that call, a
trusted supervisor must give the model a valid `ProtocolRequest` template containing
the caller identity, purpose/effect policy, pinned environment digest,
expected signed package set, and allowed scope. The model may specialize the
authorized query fields and request ID only as that supervisor permits.

Cantor deliberately does not mint or guess these bindings from model prose.
The fixture generator writes usable `query.json` and `inspect.json` examples.
A later convenience/bootstrap surface would need its own governed authority
contract; it is not smuggled into either discovery or query.

`lookup_sop_anchors` is the bounded bootstrap/discovery surface. A model may
call it with subject text without inventing a `ProtocolRequest`, but it must
retain the result's explicit non-authority boundary and must not reinterpret
lexical proximity as permission or applicability.

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

Or delegate through an already running bounded resident service:

```powershell
.\target\release\cantor-mcp.exe --service-config C:\Project\Cantor\.local\cantor-service\service.json
```

The two startup modes are mutually exclusive. Resident mode loads and pins the
validated loopback endpoint, frame and timeout limits, and capability once,
then performs an authenticated status exchange before opening MCP STDIO. A
later edit to the configuration file cannot silently retarget the running MCP
process. `cantord` may still activate a new complete generation through its
separate operator protocol.

STDOUT is reserved for MCP JSON-RPC frames. Startup and operational diagnostics
go to STDERR. The process validates the environment version, byte limit,
recognition certificates, trust policy, signatures, validity windows, scope,
and global fabric identities before opening the server.

The generated demo uses public fixture signing keys. It proves the protocol,
but it is not production authority.

## Prepared runtime

In embedded mode, the server owns one core `PreparedRuntime` and one immutable
anchor lookup runtime for the lifetime of the process. The lookup runtime
admits every configured signed package and derives its semantic fabric,
anchor catalogue, and lexical association index before MCP STDIO opens.
Consequently, an edited source or environment file cannot alter a running
process; it must be recompiled, re-signed, admitted, and loaded by a new
process.

After a `query_sop` request passes its independent environment-digest,
package-set, caller, purpose, effect, and protocol gates, the prepared runtime
may reuse one immutable `SemanticFabric` for the structurally exact requested
`AuthorityScope`. A different valid scope builds and atomically replaces the
complete projection. It never treats a broader, narrower, overlapping, or
similar scope as equivalent.

This is a physical execution optimization in `cantor_core`; the adapter has no
cache or semantic policy of its own. The direct request-scoped protocol path
remains the deterministic oracle and rollback. Trust time is still the pinned
environment `now_epoch_seconds`, so a time or security-state change requires a
new environment generation rather than mutation of the active runtime.

In resident mode, the adapter owns no `PreparedRuntime`. Each valid tool call
passes its unchanged `ProtocolRequest` to the pinned `cantord` client and
projects only the exact nested `ProtocolResponse`. If the service refreshes,
an old supervisor-issued request remains bound to its old environment and
fails through the normal core protocol; the adapter never repairs it. A new
supervisor-issued request with the new digest and package bindings can succeed
without restarting MCP.

## Codex registration

The operator may register the local subprocess with Codex:

```powershell
codex.cmd mcp add cantor -- .\target\release\cantor-mcp.exe --environment C:\absolute\path\to\environment.json
codex.cmd mcp list
```

Resident registration uses:

```powershell
codex.cmd mcp add cantor -- .\target\release\cantor-mcp.exe --service-config C:\absolute\path\to\service.json
```

This repository does not alter user or workspace Codex configuration
automatically. Registration is an operator-owned trust decision. Use an
absolute environment path so the server does not depend on the client's
working directory. The `.cmd` launcher avoids a PowerShell script-execution
policy blocking the npm-installed `codex.ps1`; shells where `codex` resolves
directly to an executable may use `codex` instead.

Suggested server instruction:

> Use `lookup_sop_anchors` to discover exact signed SOP records and quotations
> from ordinary text when that tool is advertised. Preserve its proof and its
> lexical/snapshot-only boundary. Use `query_sop` only when the subject may be
> governed by the loaded signed SOP environment and a trusted supervisor
> supplied a request template.
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

The adapter has no write tool, package compiler, signing key, trust-store
mutation, model inference, persistent database, unbounded cache, learned
router, or FPGA path. Embedded mode has no network transport. Resident mode
uses only the authenticated loopback protocol declared by
`Cantor_Resident_Service.sop`; it exposes no lifecycle operation to the model.

## Limits

- environment file: 64 MiB
- tool argument object: 1 MiB
- anchor input text: 16 KiB
- anchor postings inspected: 16,384 by default, caller-reducible or boundedly
  caller-increasable under the core limit
- anchor matches returned: 256 by default, caller-reducible or boundedly
  caller-increasable under the core limit
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

- embedded mode publishes exactly the two declared tools while resident mode
  preserves its one-tool contract;
- anchor lookup is repeatable, bounded, rejects unknown arguments, and returns
  exact admitted quotations by default;
- each source-projection proof is bound to the lexical lookup proof;
- malformed arguments produce visible structured tool faults;
- trust failures remain exact `ProtocolResponse` values;
- direct core, CLI, and MCP adapter results are equivalent; and
- repeated equal calls prepare once and then use the same exact-scope core
  projection; and
- an official Rust MCP client can initialize, list, and call the real STDIO
  subprocess without contaminating its framing channel.
