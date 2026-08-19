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

The pinned v1 receipt proves local repetition for commit `bd9403e1385e4e4a8cbd54bcb109c08d444b45f5` on one Windows MSVC toolchain. It does not prove cross-host reproducibility, package signing, deployment trust, semantic correctness, or that the historical h8 executable was built reproducibly.
