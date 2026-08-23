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
.\scripts\build_cantor_provider_free_release_signature_evidence.ps1
.\scripts\verify_cantor_provider_free_release_signature_evidence.ps1
.\scripts\test_cantor_provider_free_release_signature_evidence.ps1
```

The checked synthetic report is 5243 bytes with SHA256
`703852DFDBFA105BC10F04FBE3AE3D944F8D6711A8402DC9BC4DED525A96E63A`
and binds published source commit
`cc520563f031c3a9da2dfcc3d7991990bf5b9ec5`. Two locked-offline WSL
executions emitted byte-identical receipts, all five retained artifacts were
byte-identical across a second same-mode generation, and the independent suite
passed three producer plus thirteen tamper refusals without invoking the Rust
verifier or signing.

The evidence producer refuses an existing artifact directory unless
`-ReplaceOutput` is explicit and its complete five-file physical inventory is
exact. Replacement uses a same-parent directory swap with an exact rollback
identity; it is evidence publication, not product installation.

The identities above describe the checked `cc520563` pre-closure run. The final
acceptance gate subsequently exposed expected portable-evidence `Cargo.lock`
drift from adding this workspace crate. They remain historical until the
portable bundle and dependent signature evidence are refreshed and replayed
from clean published identities.
