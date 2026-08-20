# Bounded workspace verification P1

P1 separates three states that P0 treated as one: observing capacity, admitting
an expensive verification lane, and preserving a reserve while that lane runs.

The default remains read-only plan mode and now succeeds even when capacity is
insufficient:

```powershell
.\scripts\invoke_bounded_workspace_verification.ps1
```

The JSON reports `free_bytes`, the 40 GiB startup minimum, the 8 GiB runtime
reserve, `capacity_sufficient`, the exact `/mnt/<drive>` observation mount, and
the complete command. It invokes neither WSL nor Cargo.

Explicit execution remains:

```powershell
.\scripts\invoke_bounded_workspace_verification.ps1 -Action test -Execute
.\scripts\invoke_bounded_workspace_verification.ps1 -Action clippy -Execute
```

Execution refuses before WSL discovery unless the startup minimum is met. Once
Cargo starts, a Bash guard samples the Windows volume every two seconds. It
interrupts the Cargo parent with status 73 if available bytes cross below the
reserve, or status 74 if the sample is not numeric. Ordinary Cargo status is
otherwise preserved.

The Bash program crosses the Windows-to-WSL boundary as an exposed UTF-8 base64
payload. The outer command contains no shell variables, decodes under pipeline
failure checking, and feeds the program to an inner Bash exactly once. The JSON
plan exposes the decoded program, encoding, payload, and exact transport command.

The lane sets one build job and one test thread, disables incremental output,
and disables test and development debug information. Test, feature, lockfile,
target, and warnings selections are unchanged from P0. The settings reduce
artifact demand; they do not reduce semantic test coverage.

The guard does not claim a process-group hard kill. It signals the Cargo parent,
waits for it, and reports the operational disposition. Inspect the machine for
surviving compiler processes after any capacity interruption.

The wrapper still performs no cleanup, VHD compaction, WSL configuration,
remote access, OneDrive operation, or Cantor product action.

Run the offline contract proof with:

```powershell
.\scripts\test_bounded_workspace_verification.ps1
```

The offline suite uses isolated PowerShell processes and an impossible startup
threshold to prove pre-WSL refusal. The emitted Bash program can be syntax
checked with local Git Bash without executing its body.

The first corrected capacity-admitted acceptance on 2026-08-20 completed 154
workspace result groups with 792 passed, zero failed, and one governed ignored
test. A separate workspace/all-targets/all-features warnings-denied Clippy run
also returned zero. These observations prove the selected repository bytes and
guarded lane; they do not guarantee that future runs will have enough capacity.
