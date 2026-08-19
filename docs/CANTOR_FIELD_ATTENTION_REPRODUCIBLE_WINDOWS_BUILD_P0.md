# Cantor field-attention reproducible Windows build P0

This profile answers one narrow question: can one exact committed `cantor_field_cycle` source revision produce byte-identical Windows release executables from two clean source and target roots on the current host and toolchain?

Run the fresh proof from the Cantor repository root:

```powershell
.\scripts\test_cantor_field_attention_reproducible_windows_build.ps1 -SourceRevision HEAD
```

The command resolves `HEAD` to a commit, archives it, extracts two isolated copies, performs two locked offline release builds, compares the executables exactly, and runs effect-free `contract`, `field-digest`, and `verify` checks. It emits one JSON receipt to standard output and removes its temporary campaign directory by default.

Use `-KeepArtifacts` only for diagnosis. The receipt declares retention but intentionally omits the random local path. Cleanup of retained diagnostic artifacts remains an operator action under the host's file-operation policy.

Run the fast repository-and-receipt audit without rebuilding:

```powershell
.\scripts\audit_cantor_field_attention_reproducible_windows_build.ps1
```

The audit also refuses the pinned proof when the tracked Cargo configuration, workspace manifests, field-cycle package, or proof tool differs from the tested commit. It resolves all five historical tested-input, receipt, and anchor commit/tree pairs, requires each tested → receipt → anchor ancestry edge and each anchor → next-tested successor edge, requires the configured upstream to contain every anchor, and requires the current anchor bytes to equal their committed forms. This fast audit therefore requires a Git checkout with its upstream configured; the fresh two-root build command itself does not depend on an upstream.

The pinned v1 receipt proves local repetition for commit `b4532cff5876d94b116bf7ab44ee5017d70ce5ea` on one Windows MSVC toolchain. Each extracted source root independently selects and reports the same Rust and Cargo identities. It does not prove cross-host reproducibility, package signing, deployment trust, semantic correctness, or that the historical h8 executable was built reproducibly.

## Prerequisites

- Run from inside the Cantor Git repository on Windows.
- Use PowerShell 7 or later; Windows PowerShell 5.1 is rejected before campaign state is created.
- `git.exe`, `tar.exe`, `cargo.exe`, and `rustc.exe` must be available.
- The selected revision must contain `Cargo.lock`, the `cantor_field_cycle` package, and all three governed reports.
- Locked dependencies must already exist in the local Cargo cache because the build is offline.
- The MSVC linker must accept `/Brepro` through `RUSTFLAGS`.

The tool records the toolchain it actually observes. Matching the pinned toolchain is not assumed merely because the command runs.

## Reading the receipt

- `source` binds the commit, tree, commit epoch, archive, lockfile, and two-root isolation.
- `toolchain` exposes the readable Rust release and commit plus Cargo, host, LLVM, and the full `rustc -vV` digest.
- `build` states every controlled environment value and exact Cargo command.
- `artifact` is the byte length, SHA-256, and direct byte-comparison result.
- `behavior` binds the exact contract output, governed field digest, report file and verifier-computed identities, exchange counts, expected dispositions, and zero provider requests.
- `cleanup` says whether diagnostic artifacts were retained without disclosing a random local path.
- `claim` is the maximum conclusion the receipt supports.

Success requires all three layers simultaneously: two clean builds agree, the output equals the governed P0 behavior reference, and local temporary-state policy completes. An older executable may reproduce itself and still be correctly rejected.

## Failure interpretation

- A Git-resolution failure means no immutable source identity was available; it is not a compiler result.
- An offline Cargo failure means the local dependency cache cannot satisfy the locked graph; the tool does not download or repair it.
- An artifact mismatch means the controlled local build was not byte reproducible.
- A contract, field, report-byte, verifier-property, or disposition mismatch means the equal binaries do not preserve the governed P0 reference.
- A cleanup-boundary failure means the tool refused to recursively remove a path it could not prove was one physical target child.

Every failure exits nonzero and withholds a `passed` receipt. Ordinary failed campaigns clean their validated temporary root in `finally`.

## Git identity and proof freshness

The receipt follows the commit it tests, and Git anchors follow the receipt. This successor ordering is intentional: a receipt cannot truthfully include itself. The fast audit additionally checks that the current tracked Cargo configuration, workspace manifests, field-cycle package, and proof tool still equal the tested commit.

The Minecraft handoff file is a separate workstream and is intentionally absent from every Cantor campaign commit.
