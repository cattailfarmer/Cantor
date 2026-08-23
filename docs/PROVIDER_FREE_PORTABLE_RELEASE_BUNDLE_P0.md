# Provider-free portable release bundle P0

Cantor now publishes one deterministic Windows x86_64 portable release-bundle
candidate containing the four binaries already proven by the provider-free
private-beta workflow. The checked archive is
`experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip`.
Its companion evidence JSON binds the archive, exact published source commit,
`Cargo.lock`, target, six-entry allowlist, entry bytes and SHA-256 identities,
and explicit capability denials.

This is a real handoff artifact and a portable package identity. It is not an
installer, supported delivery channel, publisher-authenticity signature,
production trust root, configuration system, upgrade promise, operator
product, or production product.

## Generate

From the published `codex/self-hosted-corpus` HEAD:

```powershell
.\scripts\build_cantor_provider_free_portable_release_bundle.ps1
```

The default performs the exact locked/offline release build for `cantor`,
`cantor-corpus`, `cantord`, and `cantorctl`, then constructs the archive twice.
Both generated archives must be byte-identical before publication. Use
`-UsePrebuilt` only when the current workspace release binaries have already
been built. Existing checked outputs are refused unless `-ReplaceOutputs` is
explicit.

The ZIP contains exactly these ordinal paths:

```text
BUNDLE_README.txt
bin/cantor-corpus.exe
bin/cantor.exe
bin/cantorctl.exe
bin/cantord.exe
bundle-manifest.json
```

Entries use the ZIP store method, zero external attributes, normalized slash
paths, and fixed DOS timestamp fields `1980-01-01 00:00:00`. The embedded
manifest identifies the target, source commit, `Cargo.lock`, payload entries,
bounds, and nonclaims. No key, token, configuration, corpus, state, log, or
provider result enters the archive.

## Verify

```powershell
.\scripts\verify_cantor_provider_free_portable_release_bundle.ps1
.\scripts\test_cantor_provider_free_portable_release_bundle.ps1
```

The verifier reads the ZIP without extracting or executing it. It closes the
report shape, rehashes the archive, validates exact ZIP entry order and
metadata, rederives the README and embedded manifest, and byte-compares each
archived executable with the current release binary. The adversarial suite
also proves cross-directory deterministic generation, explicit deterministic
replacement, three producer refusals, and fifteen verifier refusals.

## Handoff and remaining work

A recipient can hash the ZIP and compare it with the governed companion
evidence, but SHA-256 reproducibility alone is not publisher authenticity.
The separately governed no-listener configuration diagnostic is now available
and documented in `docs/OPERATOR_CONFIGURATION_DIAGNOSTIC_P0.md`. Supported
delivery, publisher signing and trust provisioning, production secret and
configuration creation/repair lifecycle, compatibility, migration, upgrade
and rollback across releases, operator acceptance, and support policy remain
separate operator-product work. Live-provider compatibility remains contingent
on the exact pinned local provider; no download, substitution, remote fallback,
or synthetic live trial is authorized here.
