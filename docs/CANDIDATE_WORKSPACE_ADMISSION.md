# Candidate workspace admission

`cantor_ecosystem::admit_candidate_workspace` is the Phase3A gate in front of any future workspace-write Codex turn. It proves that an operator-prepared Git linked worktree is the exact disposable candidate named by a work packet. It does not prepare or modify that worktree.

## What is bound

The strict request pins:

- the Git executable by canonical path, SHA-256, and exact version;
- separate canonical principal and candidate workspace roots;
- the repository common directory;
- one full base object ID and one full local candidate branch ref;
- a sorted protected-branch set and sorted, nonoverlapping relative-path policy;
- candidate, correlation, and single-use nonce identities; and
- per-command, aggregate-byte, process, and monotonic-time budgets.

The engine runs twelve fixed, direct Git observations with no shell: version, both top levels, both common directories, candidate Git directory, candidate HEAD, candidate and principal symbolic refs, porcelain-v2 status, worktree inventory, and recursive submodule inventory. Git-sensitive environment overrides are removed and prompts and pagers are disabled.

Admission requires a linked worktree, exact shared repository identity, exact branch and base, a single matching worktree-inventory entry, empty status, no submodules, and a nonprotected branch distinct from the principal branch.

## Receipt and freshness

The receipt binds canonical request JSON, ordered command arguments and raw results, normalized repository facts, path policy, deterministic process and byte counts, and the configured deadline. Measured elapsed time is intentionally excluded from receipt identity.

A receipt reports an observation; it does not grant write authority or prove that the filesystem is still unchanged. A future Phase3B consumer must call `revalidate_candidate_workspace` immediately before launching its separately authorized writer and consume the nonce only once.

## Probe

Build and invoke the operator probe with an absolute strict request:

```powershell
cargo run -p cantor_ecosystem --example candidate_workspace_probe --locked --offline -- C:\absolute\candidate-admission-request.json
```

On Windows, `std::fs::canonicalize` commonly yields the extended `\\?\C:\...` path form. Requests must use the exact canonical paths that the runtime will compare; the receipt returns those observed paths.

The probe writes only its JSON result to stdout. It never creates, cleans, resets, stages, commits, merges, pushes, signs, activates, deletes, or promotes a worktree.

## Authority boundary

Phase3A authorizes only read-only admission. Phase3B candidate mutation, Phase3C immutable sealing and independent review, and Phase3D governed promotion each require a new source-preserved SJS authority and proof.
