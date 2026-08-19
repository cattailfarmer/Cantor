# Bounded workspace verification P0

This local development wrapper prevents one class of false product failure:
unbounded accumulation of isolated Cargo targets until the Windows system
volume is full and WSL becomes unreliable.

The default is plan-only and invokes neither WSL nor Cargo:

```powershell
.\scripts\invoke_bounded_workspace_verification.ps1
```

Execute one complete serialized regression with the reusable target:

```powershell
.\scripts\invoke_bounded_workspace_verification.ps1 -Action test -Execute
```

Or run warnings-denied Clippy through the same target:

```powershell
.\scripts\invoke_bounded_workspace_verification.ps1 -Action clippy -Execute
```

Before an executable lane starts, the wrapper verifies a declared minimum free
space on the Windows volume containing the repository. The default threshold is
20 GiB. It emits the exact plan as JSON, uses one build job and one Rust test
thread, and propagates the child exit status.

The wrapper never deletes a cache, creates a per-run target, accesses OneDrive,
or contacts EVO-X2 or any other remote host. Cleanup remains a separate,
explicitly inspected operation.

Run the offline command-contract proof with:

```powershell
.\scripts\test_bounded_workspace_verification.ps1
```
