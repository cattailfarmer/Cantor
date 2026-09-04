# B1 A5 operator-decision chain verification

A5 is a provider-free, non-authorizing Rust verifier. It connects the existing signed operator-decision format to the verified A1 policy, A2 custody statement, A3 revocation statement and A4 supplied time witness. It does not execute the decision.

## What it verifies

The verifier replays A4 (and therefore A1–A3) without modifying those implementations. Only the packet's fifth descriptor may change. Exact A5 envelope bytes must match the descriptor before envelope parsing. The legacy policy must match the A1 identity and decoded public key, and bind the exact raw A1 policy envelope and A3 snapshot. The unchanged legacy verifier checks its policy, fixed proposal, request, payload digest and Ed25519 signature.

An explicit A5 request supplies the expected policy revision, decision UUID, decision kind and external decision identity. A5 associates these with the replayed chain; it does not invent signed fields in the old format.

For either Authorize or Reject, the supplied A4 observation is classified against the half-open interval `[issued, expires)`: before, within or after. Issuance equality is within; expiry equality is after. Direct integer comparison supports the u64 endpoints without arithmetic overflow.

## What it does not prove

A legacy decision signature does **not** sign the later A4 witness or receipt. A passing chain and a within-interval comparison do not prove current time, freshness, signer authority, operative revocation, private-key custody or authorization to execute. All 33 authority/context claims remain false; all 22 effect-account fields remain zero/false. Revoked and unknown supplied A3 assertions remain visible.

The production core has no signer, clock, reference resolver, process runner, network client or workspace writer. Evidence readers accept only explicit bounded supplied files. These checks require stable files; they are not an atomic filesystem snapshot or an operating-system sandbox. CLI startup/stdout and test-harness processes are not product execution authority.

## Reproduce

From the native D: worktree, with the locked offline toolchain and external-to-Git D: temporary directory:

```powershell
$env:CARGO_TARGET_DIR='D:\crf\target'
$env:CARGO_BUILD_JOBS='1'
$env:CARGO_INCREMENTAL='0'
$env:RUST_MIN_STACK='33554432'
$env:TEMP='D:\CantorBuilds\B1A4TestTemp'
$env:TMP=$env:TEMP
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/test_b1_operator_decision_chain_verification.ps1
```

Process-scoped RemoteSigned is covered by the user's specific approval for reviewed scripts. No persistent policy change is needed. The same reviewed script is also gated on PowerShell 7.

The focused script runs debug and overflow-checked release tests, generates the deterministic test-only fixture only when its directory is absent, and compares retained output with two fresh evidence-verifier processes and the explicit-input CLI in each profile. The fixture producer is intentionally ignored in ordinary test runs and refuses to overwrite an existing evidence directory.

The directory CLI accepts exactly one directory:

```text
cantor-b1-operator-decision-chain-evidence-verify <evidence-directory>
```

The explicit-input CLI accepts exactly 19 paths in the order declared by `ODCV_EVIDENCE_FILES[0..19]`. Both CLIs emit only the reconstructed receipt on stdout, or a refusal on stderr with exit code 2. Neither writes an output file.

## Evidence and limits

`implementation_provider_free_evidence/` contains exactly 21 regular nonlink files: 19 supplied inputs, the retained receipt, and the manifest. The manifest binds the 20 payload files in fixed order; every retained file ends with exactly one LF. Raw candidate hashes exclude the transport LF; manifest artifact hashes include it.

Limits are 1 MiB per machine form, 16 MiB aggregate retained input, JSON depth 32, 4096 aggregate object fields, general text 8192 bytes, and 1–48 unique nonempty opaque references. Stricter legacy bounds remain in force. References are compared as data, never opened.

The declaration contracts are 47 request fields, 113 receipt fields and 18 manifest fields. The tests cover both input classes, both decisions, all interval outcomes, u64 endpoints, adverse A3 assertions, key-domain distinctions, validly signed mismatched policies, unsigned A4 rebinding, every receipt truth/effect field, noncanonical framing, bounds, junctions, evidence tampering and fresh-process refusals.

## Governance and completion

Immutable source snapshot: `dc4d390b-953b-415f-9fd9-2bd6f4838e19`.
Canonical specification: `ee06ff6d-ba10-4a02-a157-9533d734912e`.
Formation signature: `b40dd6f3-9adc-4bd4-b87d-154e92668106`.
Formation publication: `cf757a4a73ca274722ec62b6953b7aee29d15422`, bookended by `4d814e1c72b3b0a44b159986e08e3d3f509dea18`.

The separate implementation requirement matrix, closure proof and publication bookend record actual gate outcomes; the frozen formation artifacts are not rewritten to describe later work. Provider status remains `provider_unavailable` with zero live or synthetic provider trials. Deterministic test fixtures are not provider trials.
