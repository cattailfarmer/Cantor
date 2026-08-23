# Local product developer-alpha acceptance

Cantor's current provider-free product boundary can be replayed with one
repository command:

```powershell
.\scripts\audit_cantor_local_product_acceptance.ps1 -VerifyOnly
```

The checked report is
`experiments/local_product_acceptance/artifacts/local_product_developer_alpha_acceptance_v1.json`.
It binds one published ancestor commit, eight immutable component artifacts,
the exact semantic, Iterative P1, lifecycle, corpus, and service evidence
profiles, and the recursive zero-stale evidence state. Verification reconstructs
the report from the current tree and requires byte-equivalent JSON structure;
unknown or changed fields are refused.

Generate the report after an intentional evidence change with:

```powershell
.\scripts\audit_cantor_local_product_acceptance.ps1
```

Run the bounded provider-free component verifiers and focused tests before
generating or verifying with:

```powershell
.\scripts\audit_cantor_local_product_acceptance.ps1 -ExecuteFocused
```

On a Windows host that refuses freshly linked unsigned executables under
Application Control, retain that refusal and run the lifecycle portion through
the existing bounded local WSL toolchain without changing host policy:

```powershell
.\scripts\audit_cantor_local_product_acceptance.ps1 -ExecuteFocused -UseWslFocusedLane
```

That option uses locked/offline dependencies, one local stable Cargo target,
and a fresh temporary `python` shim to the already installed `python3`; the shim
and generated probe outputs are removed by the command.

Default and verify-only modes do not compile, install, launch a service,
contact a provider or network, create durable custody, or execute external
effects. Focused mode may use the existing local Cargo cache and runs only
tracked provider-free verifiers and tests.

## Accepted boundary

The exact accepted status is
`provider_free_developer_alpha_verified_with_declared_gaps`. It proves that:

- the self-hosted corpus evidence still reports 3 sources, 417 units, and 360
  relations;
- the supervised service evidence profile exists, without claiming a current
  service process;
- Semantic Anchor evidence reaches the governed Slice 5F selection protocol,
  all three real correction targets remain null, and the only selection
  receipt is explicitly synthetic;
- Iterative Attention P1 retains its provider-free Slice 8B release identity
  and denies provider, persistence, effect, remote, FPGA, and Minecraft
  capabilities;
- the lifecycle bridge retains its exact 124,144-byte stateless versus
  1,200-byte volatile-custody comparison and visible restart loss; and
- the unavailable pinned provider retains zero live trials and zero custody
  registrations.

## Deliberate gaps

This report is not private-beta, operator, or production acceptance. It does
not prove a one-command install-to-rollback workflow, a currently running
service, representative live-provider task outcomes, distribution and upgrade
support, production authentication, trust-root or secret lifecycle, durable or
distributed custody, external effects, threat-model closure, recovery,
observability, SLOs, security review, or deployment fitness.

Live compatibility remains contingent on the exact pinned local provider. The
audit never downloads a model, substitutes a provider, or uses a remote
fallback. A real Semantic Anchor target remains independently
curator-authority-gated and is not fabricated by this acceptance surface.
