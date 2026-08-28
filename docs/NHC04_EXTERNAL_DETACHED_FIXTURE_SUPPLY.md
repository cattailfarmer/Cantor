# NHC-04 external detached fixture supply

NHC-04 is ready to compile and independently verify an effectless inner-model launch plan once an authorized party supplies one valid detached Ed25519 request fixture. Cantor does not create, import, retain, or infer a private signing key.

## What crosses the boundary

The only artifact supplied to Cantor is `request.json`: canonical compact JSON for `NestedInnerLaunchPlanRequest`, optionally followed by one line terminator. It must be at most 1,048,576 JSON bytes and must already contain a valid signature and final request digest.

Do not place a private key, seed phrase, signing command, key-store export, or signer credential anywhere in this repository. A signer may retain its own custody receipt outside Cantor. That receipt is not NHC-04 execution authority.

## External signer sequence

1. Start from the exact governed NHC-03 request, envelope, and verification triplet. Construct the intended `InnerLaunchPlan`, then call `seal_inner_launch_plan`.
2. Construct `NestedInnerLaunchPlanRequest`. Set its `upstream_bundle_digest` with `nested_inner_launch_plan_upstream_digest`. Set the authorization tuple, the public `verifying_key_hex`, a 128-hex-character placeholder `signature_hex`, and an empty `request_digest`.
3. Call `nested_inner_launch_plan_authorization_payload_bytes`. This emits the ASCII domain `cantor.nested-inner-launch-plan.authorization.v1`, one NUL byte, and canonical JSON for the full signed tuple. The payload binds the NHC-03 bundle digest, complete sealed plan, authorization and subject identities, policy and nonce digests, sequence range, one-attempt/zero-retry limits, disposition, consumption state, and public verifying key. It excludes the signature and request digest.
4. Sign those exact payload bytes with Ed25519 outside Cantor. The signing key must correspond to `verifying_key_hex`.
5. Insert the 64-byte signature as 128 hexadecimal characters. Call `seal_nested_inner_launch_plan_request`; this replays the complete NHC-03 bundle, validates the plan and signature, recomputes the upstream digest, and seals the request digest.
6. Call `to_nested_inner_launch_plan_request_machine_form` and deliver only those canonical compact bytes as `request.json`.

Changing any bound plan, upstream, authorization, public-key, policy, nonce, sequence, attempt, retry, disposition, or consumption value after signing invalidates the signature. Changing any other request field after sealing invalidates the request digest.

## Cantor-side production and verification

Use the one governed focused runner. The output directory must not already exist; the runner refuses overwrite and writes through a temporary sibling directory before one final rename.

```powershell
pwsh -NoProfile -File .\scripts\test_cantor_nested_inner_launch_plan_evidence.ps1 `
  -RequestPath C:\authorized-input\request.json `
  -OutputDirectory C:\authorized-output\nhc04-evidence
```

The runner uses locked, offline Cargo with one build job, UTF-8-pinned process streams, and the D-drive target `D:\CantorBuilds\cantor-nhlp-p0-focused-script` by default. `-Release` selects the optimized binaries, and `-CargoTargetDirectory` may select another explicit build target.

It invokes exactly the two signed-formation CLIs:

- `cantor-nested-inner-launch-plan-fixture` parses and validates the supplied request, compiles the envelope, verifies it twice, and constructs the evidence bundle.
- `cantor-nested-inner-launch-plan-evidence-verify` independently parses and replays that bundle. Its output must equal the retained verification bytes exactly.

Only after both commands agree does the runner publish exactly four LF-terminated files: `request.json`, `envelope.json`, `verification.json`, and `evidence_manifest.json`. It never invokes a signer, model, provider, shell launch plan, workspace mutation, network, remote host, cancellation, or cleanup operation.

## What success does not mean

A passing NHC-04 fixture proves supplied-key cryptographic correspondence and deterministic provider-free compilation of a proposed effectless plan. It does not prove executable or working-directory presence, executable bytes, key custody, revocation, freshness, current sequence, process creation, model loading, provider availability, inference, stream custody, cancellation execution, cleanup, persistence, remote access, or any physical effect. Those remain later governed stages.
