# B1 A7 Private Execution Permit Reference Correspondence P0

This provider-free verifier answers one deliberately narrow question: does caller-supplied, public, opaque reference metadata correspond to the ordinal-seven private-execution-permit candidate described by the fully replayed A6 receipt and signed plan?

It does not open or resolve the reference. It does not authenticate permit material, establish issuer authority, prove scope or freshness, consume anything, contact a broker, prepare execution, or authorize an effect.

## Executables

`cantor-b1-private-execution-permit-reference-verify` accepts exactly 27 explicit file arguments in the canonical order selected by the formation.

`cantor-b1-private-execution-permit-reference-evidence-verify` accepts exactly one evidence-directory argument. The directory must contain exactly 30 direct regular nonlink files: a 29-payload manifest plus the 29 named payloads. The retained A6 evidence manifest is custody material, not a trusted semantic shortcut.

Both programs write one canonical receipt to stdout on success. Refusals use stderr and exit code 2. The programs do not write evidence or mutate caller inputs.

The checked-in deterministic fixture is at `experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence`.

## Verification order

1. Bound raw carrier sizes and filesystem shape before expensive predecessor replay.
2. Parse and validate the evidence manifest, exact membership, canonical framing, and all 29 payload hashes.
3. Replay the complete unchanged A6 chain from its 24 explicit semantic inputs and compare the complete supplied A6 receipt.
4. Reconstruct the authority packet twice and require byte identity, with only the ordinal-seven descriptor changed from A6.
5. Admit the exact raw 16-field reference envelope and 34-field verification request.
6. Reconstruct all 17 primitive correspondence comparisons, their conjunction, and ordered mismatch reasons.
7. Reconstruct and validate the complete 63-field receipt, including 18 false A7 authority fields and the unchanged 22-field zero-effect account.

The envelope, request, receipt, and evidence manifest use different fixed SHA-256 domains over a NUL delimiter and exact canonical typed bytes. Each self-digest is cleared only in its own domain computation.

## Deterministic retained result

The retained fixture has 30 files, 29 payloads, 168804 payload bytes, and 174374 total bytes. Its 5570-byte evidence manifest has raw SHA-256 `F5973900F9213FA7679C9D0EDB926BD6E10606F0E3D620DEF5C36B53630E4678`.

The raw retained receipt is 17675 bytes with SHA-256 `B24AFC882037F13EB09CF9ACE0F45E5FB5552904E6AB5AC146BFAB090F99A103`. Windows stdout adds one transport newline, producing 17676 bytes with SHA-256 `A15452544D8F0D1BE8D83AAD3E799FB4F63EDA26A175FB06DE0D2A9A0B79D31E`.

The result remains `supplied_private_permit_reference_correspondence_matched_execution_unresolved`, with `private_execution_permit_present=false`, `execution_authorized=false`, and zero effects.

## Verified boundaries

The suite changes or refuses every envelope, request, receipt, and manifest field; all 28 semantic payloads; every one of the 131072 comparison subsets; raw framing and resource hazards; missing, extra, linked, junction, and reparse inputs; rehashed false retained identity; reference smuggling and echo hazards; and a deliberately broken expensive predecessor behind the early raw-size preflight.

The production module has no resolver, secret store, environment, clock, signer, key, process, network, provider, MCP, Git, broker, writer, persistence, activation, cleanup, remote, or physical-effect capability. Stable-file checks are conservative and bounded but are not an atomic-snapshot claim against every concurrent replacement.

## Scope

All checked-in data is synthetic. The pinned local model provider remains unavailable and no live or synthetic provider trials are part of A7. A later private-permit verifier, broker, or execution phase requires a new source-governed specification and satisfaction signature.
