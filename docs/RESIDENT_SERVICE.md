# Cantor resident service

`cantord` keeps one completely verified, immutable Cantor environment resident
for multiple local callers. `cantorctl` is a thin client. Semantic query,
inspection, trust, and proof behavior remain in `cantor_core`.

This is a bounded local read-only service profile. It is not an HTTP service,
remote API, package compiler, trust editor, autonomous agent, or effect broker.

## Security boundary

- `cantord` starts only with `--config <absolute-path>`.
- The configured listener must be an IPv4 or IPv6 loopback address.
- Every request requires the 256-bit capability from `auth_token_path`.
- The token is read from a file, never a command-line argument, and is omitted
  from responses and diagnostics.
- The activation descriptor may select environments only beneath
  `allowed_environment_root`.
- Refresh rereads the one activation path pinned at startup. A request cannot
  select an environment file.
- Environment bytes must match the activation SHA-256 and then pass complete
  Cantor package admission, fabric construction, and PreparedRuntime checks.
- One connection carries one bounded JSON frame and receives one bounded JSON
  response. Frames are 1024 through 1048576 bytes; connections and read/write
  timeouts are bounded.
- Excess connections are bounded-drained briefly before a structured rejection
  is attempted, avoiding unread-request TCP reset behavior without claiming
  denial-of-service resistance.
- Status exposes rejected-connection and worker-panic counters without caller
  content.

Protect the runtime directory with the operating system account permissions
appropriate for the callers. Loopback plus a bearer capability does not
provide hostile multi-user isolation or transport encryption.

## Build

```powershell
cargo build --workspace --release --locked --offline
```

The binaries are:

```text
target\release\cantord.exe
target\release\cantorctl.exe
```

## Initialize operator artifacts

First compile an admitted environment. The self-hosted corpus workflow in
`docs/SELF_HOSTED_CORPUS.md` produces
`.local/cantor-self-hosted/build/environment.json`.

Create ignored local service artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\initialize_cantor_service.ps1 `
  -EnvironmentPath C:\Project\Cantor\.local\cantor-self-hosted\build\environment.json `
  -RuntimeDirectory C:\Project\Cantor\.local\cantor-service `
  -AllowedEnvironmentRoot C:\Project\Cantor\.local `
  -ListenAddress 127.0.0.1:39841
```

The initializer refuses to overwrite existing artifacts unless `-Replace` is
explicit. Review the runtime directory before using that option.

Publication order is:

1. write a new immutable environment file beneath `allowed_environment_root`;
2. verify its digest and contents;
3. atomically publish a higher-sequence activation descriptor;
4. request refresh with the exact current generation and sequence.

## Start and inspect

```powershell
target\release\cantord.exe `
  --config C:\Project\Cantor\.local\cantor-service\service.json
```

In another terminal:

```powershell
target\release\cantorctl.exe status `
  --config C:\Project\Cantor\.local\cantor-service\service.json `
  --request-id request:operator_status_1
```

Machine JSON is written only to standard output. Operational diagnostics use
standard error.

## Supervised local lifecycle

The Windows operator profile can launch `cantord` hidden, prove authenticated
readiness, publish a secret-free state record atomically, report health, and
perform graceful exact-generation shutdown:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\start_cantor_service.ps1 `
  -ServerPath C:\Project\Cantor\target\release\cantord.exe `
  -ClientPath C:\Project\Cantor\target\release\cantorctl.exe `
  -ConfigPath C:\Project\Cantor\.local\cantor-service\service.json `
  -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\get_cantor_service_health.ps1 `
  -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\stop_cantor_service.ps1 `
  -StatePath C:\Project\Cantor\.local\cantor-service-supervisor\state.json
```

The state binds the PID to the canonical server executable and exact UTC
process start time, preventing a reused PID from authorizing health or
shutdown. It records the start generation, activation sequence, configuration,
client, and separate log paths, but contains no token, token path, request
content, or semantic content. Health always performs a fresh authenticated
status call, so a legitimate refresh appears as a changed current generation.
The state is exact compact UTF-8 machine output: do not hand-edit, reorder, or
reformat it. BOMs, duplicate members, unknown members, and any noncanonical
round trip are rejected before the record can identify a process.

An existing state file is refused by default. `-ReplaceStale` is accepted only
after the record is structurally valid and its complete process identity is
proved not live. A live matching process is never replaced. Startup failure
may terminate only the exact process created by that start attempt. Stop never
force-kills: rejected shutdown or an exit timeout preserves the state for
operator review.

Starts for the same state path are serialized by a state-path-derived local
Windows kernel mutex. Concurrent attempts have exactly one admitted winner;
the mutex is process-lifetime state and contains no capability material.

This is a Windows process-lifecycle prerequisite, not a general service
manager, automatic restart policy, OS-service installer, Codex controller, or
Shaliach agent runtime.

## Query or inspect

Use an existing complete `cantor-protocol/0.1` request:

```powershell
target\release\cantorctl.exe query `
  --config C:\Project\Cantor\.local\cantor-service\service.json `
  --request-id request:operator_query_1 `
  --input C:\Project\Cantor\.local\cantor-self-hosted\build\query-cantor.json
```

`ServiceResult.kind=protocol` contains the unchanged `ProtocolResponse`.
The outer response binds it to the service generation and activation digest
that executed it.

## Refresh

Publish a new activation descriptor:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\publish_cantor_activation.ps1 `
  -ActivationPath C:\Project\Cantor\.local\cantor-service\activation.json `
  -EnvironmentPath C:\Project\Cantor\.local\cantor-self-hosted-v2\environment.json `
  -Sequence 2
```

Read the current generation from `cantorctl status`, then request the exact
compare-and-swap:

```powershell
target\release\cantorctl.exe refresh `
  --config C:\Project\Cantor\.local\cantor-service\service.json `
  --request-id request:operator_refresh_2 `
  --expected-generation <64-hex-generation-value> `
  --expected-sequence 1
```

Candidate loading occurs before the active-state write lock. Invalid, tampered,
stale, equal-sequence, or unchanged-generation candidates leave the previous
generation active.

Rollback uses the same process: publish a previously valid environment through
a new, higher activation sequence and refresh with current preconditions.

## Shutdown and fallback

```powershell
target\release\cantorctl.exe shutdown `
  --config C:\Project\Cantor\.local\cantor-service\service.json `
  --request-id request:operator_shutdown_1 `
  --expected-generation <64-hex-generation-value>
```

The embedded `cantor` CLI and standalone `cantor-mcp` remain complete rollback
paths. Service failure never authorizes fabricated SOP guidance.

## Codex through the shared generation

The existing one-tool MCP adapter can use this service without changing its
model-callable surface:

```powershell
target\release\cantor-mcp.exe `
  --service-config C:\Project\Cantor\.local\cantor-service\service.json
```

It authenticates and checks status before opening MCP STDIO, then delegates
each unchanged `ProtocolRequest` through the pinned service client. Refresh
remains operator-only. Stale request bindings fail closed; the MCP adapter
does not guess a new environment digest or package set.
