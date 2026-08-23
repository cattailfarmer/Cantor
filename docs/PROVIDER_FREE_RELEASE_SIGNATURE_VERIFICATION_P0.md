# Cantor provider-free release signature verification P0

`cantor-release-verify` verifies one detached Ed25519 envelope over the exact
current portable bundle and its checked evidence. The caller supplies a strict
publisher policy containing the public key, publisher and policy identities,
allowed evidence profile, and target.

```powershell
.\target\release\cantor-release-verify.exe `
  --bundle .\experiments\provider_free_portable_release_bundle\artifacts\cantor-provider-free-windows-x86_64-p0.zip `
  --bundle-evidence .\experiments\provider_free_portable_release_bundle\artifacts\cantor-provider-free-windows-x86_64-p0-evidence.json `
  --policy C:\operator-owned\release-policy.json `
  --envelope C:\operator-owned\release-envelope.json
```

The verifier requires four distinct bounded physical non-symlink files. It
rehashes the bundle and evidence, checks the complete top-level portable
evidence shape, requires source/target/archive agreement, canonicalizes the
strict payload as compact JSON, and verifies the signature against the policy
key. Exit `0` is verified, `2` is invocation or input transport refusal, `3`
is verification refusal, and `70` is receipt serialization failure.

The compact receipt contains public identities and exhaustive false safety
claims. It never contains paths, the public key, signature, raw policy,
envelope, bundle, or evidence. A verified receipt proves only payload integrity
and possession of a key pinned by the supplied policy. It does not establish
that the policy is governed, that the publisher identity is true, or that the
release is supported, installable, trusted for production, or accepted.

The product binary has no signing, key generation, key storage, policy
mutation, trust onboarding, installation, extraction, execution, or service
command. The separate fixture example uses one fixed publicly disclosed test
seed and labels its policy and envelope `synthetic_fixture_only`.

Windows Application Control may refuse a newly emitted local binary. Do not
weaken host policy. The governed proof lane uses the existing isolated Ubuntu
24.04 WSL environment when this occurs.

Focused commands are:

```powershell
cargo test -p cantor_release_signature --all-targets --locked --offline
cargo test -p cantor_release_signature --all-targets --release --locked --offline
cargo clippy -p cantor_release_signature --all-targets --locked --offline -- -D warnings
.\scripts\build_cantor_provider_free_release_signature_evidence.ps1 -ReplaceOutput
.\scripts\verify_cantor_provider_free_release_signature_evidence.ps1
.\scripts\test_cantor_provider_free_release_signature_evidence.ps1
```

The checked synthetic report is 5243 bytes with SHA256
`5F70A754963A34CDDD7E3F62354800C8F156B567D7F806DA130C6BBA94F9517A`
and binds published source commit
`dbe73a379832756c562c671d049a552b7c42ba70`. Two locked-offline WSL
executions emitted byte-identical receipts, all five retained artifacts were
byte-identical across a second same-mode generation, and the independent suite
passed three producer plus thirteen tamper refusals without invoking the Rust
verifier or signing.

The evidence producer refuses an existing artifact directory unless
`-ReplaceOutput` is explicit and its complete five-file physical inventory is
exact. Replacement uses a same-parent directory swap with an exact rollback
identity; it is evidence publication, not product installation.

The final acceptance gate exposed expected portable-evidence `Cargo.lock`
drift from adding this workspace crate. The portable bundle and private-beta
workflow were refreshed from published `e23bf27d`; the signature evidence above
was then regenerated from published `dbe73a37` and reproduced from the same
source in a separate short-path local clone.
