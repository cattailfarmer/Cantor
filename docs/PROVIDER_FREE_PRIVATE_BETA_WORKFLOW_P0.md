# Provider-free private-beta workflow P0

Cantor now has one release-bound disposable Windows workflow across the
existing self-hosted corpus and resident service. It builds or verifies four
local release binaries, stages exact copies, generates ephemeral fixture
signing seeds, compiles the tracked corpus, initializes and starts the
loopback-only service, proves authenticated health, runs the generated
`query-cantor` request, gracefully stops, proves the direct CLI returns the
exact same `ProtocolResponse`, and removes the complete disposable run root.

This is the provider-free mechanical private-beta boundary. It is not an OS
installer, supported distribution, upgrade policy, production key or secret
lifecycle, live-provider qualification, operator product, or production
product.

## Execute

Build and run from the published `codex/self-hosted-corpus` HEAD. Choose an
unused IPv4 loopback port and an absent run-root name with exactly the required
closed identity:

```powershell
$runRoot = Join-Path ([IO.Path]::GetTempPath()) `
  ("cantor-private-beta-" + [guid]::NewGuid().ToString("N"))

.\scripts\invoke_cantor_provider_free_private_beta_workflow.ps1 `
  -RunRoot $runRoot `
  -OutputPath .\private-beta-report.json `
  -ListenAddress 127.0.0.1:39851
```

The default performs this exact build before staging:

```powershell
cargo build -p cantor_cli -p cantor_service --bins --release --locked --offline
```

`-UsePrebuilt` skips compilation but still requires and hashes those exact four
workspace release binaries. `-ReplaceOutput` is required to replace an
existing report; the run root itself must always be absent.

Verify the checked report after the same release binaries have been built:

```powershell
.\scripts\verify_cantor_provider_free_private_beta_workflow.ps1
.\scripts\test_cantor_provider_free_private_beta_workflow.ps1
```

## Safety and rollback

The run root must be absolute, outside the repository, absent, not a drive or
user-profile root, not a reparse point, and named
`cantor-private-beta-` plus 32 lowercase hexadecimal characters. A preexisting
root is refused without mutation. The output report must be outside the run
root and is atomically published only after cleanup.

The existing supervisor owns process identity and graceful shutdown. On a
fault, the workflow stops only through an admitted exact supervisor state. If
that stop cannot be proved, it retains the run root and reports the residual;
it never force-kills and never deletes through an uncertain identity.

On success, the supervisor state is removed after process exit. The direct CLI
fallback runs after stop. Only then are the fixture seeds, local token,
generated environment and queries, logs, staged binaries, configuration, and
run root removed. The checked report retains hashes, counts, step states,
PID/generation identity, response equality digests, rollback flags, and
capability denials—never key bytes, token material, source quotations, or
semantic response content.

## Remaining gaps

The exact pinned llama.cpp provider remains unavailable and no synthetic live
trial is introduced. Production trust provisioning, installation packaging,
distribution and upgrade support, configuration migration, durable custody,
effects, remote execution, FPGA execution, and Minecraft remain separately
governed or denied.
