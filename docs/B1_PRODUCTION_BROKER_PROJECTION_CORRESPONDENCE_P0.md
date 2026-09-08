# B1 A8 Production Broker Projection Correspondence P0

This provider-free verifier answers one narrow question: does a caller-supplied public logical broker-projection declaration correspond to ordinal eight of the authority packet after a complete, unchanged A7 replay?

It does not resolve an endpoint, contact a broker, read permit material, authenticate a session, activate a projection, prepare a filesystem, execute work, or grant effects. A matched receipt still says `execution_unresolved` and keeps all 15 A8 authority fields false.

## Executables

`cantor-b1-production-broker-projection-verify` accepts exactly 30 explicit file arguments in the formation-selected order.

`cantor-b1-production-broker-projection-evidence-verify` accepts exactly one evidence directory. That directory contains exactly 34 direct regular nonlink files: 33 manifest-bound payloads plus the manifest. The embedded A6 and A7 manifests are custody bytes, never trusted semantic shortcuts.

Both programs write one canonical receipt plus one transport LF to stdout on success. Refusals use bounded nonsecret stderr and exit code 2. Neither program writes evidence or mutates caller inputs.

The checked-in deterministic fixture is `experiments/b1_production_broker_projection_correspondence_p0/implementation_provider_free_evidence`.

## Verification order

1. Bound filesystem membership, direct/nonlink shape, individual files, aggregate bytes, and raw declaration bytes.
2. Hash all 33 retained payloads before semantic parsing.
3. Replay the complete unchanged A1 through A7 chain and compare the complete retained A7 receipt.
4. Reconstruct A7's packet request locally, replace only ordinal eight, and compile the A8 packet twice byte-identically.
5. Admit the exact 24-field declaration and 44-field request under distinct self-digest domains.
6. Reconstruct all 26 primitive comparisons, their conjunction, and duplicate-free ordered mismatch reasons.
7. Reconstruct and validate the 68-field receipt, nested A7 receipt, 15 false A8 authority fields, and unchanged 22-field zero-effect account.
8. Replay the entire payload a second time and require exact agreement with the retained receipt bytes.

Matching and well-formed mismatching declarations produce distinct descriptive receipts. Malformed shapes, raw substitutions, forged summaries, retained-identity changes, endpoint/capability smuggling, and authority promotion refuse.

## Deterministic retained result

The retained fixture has 34 files, 33 payloads, 202015 payload bytes, and 208214 total bytes. Its 6199-byte evidence manifest has raw SHA-256 `64E98F47FD01E28D339B1B73FD5EFC85032A0AE559FBCDB2AE98594BA97CBD7E`.

The 23018-byte retained receipt has raw SHA-256 `763FD0992498528BDB278554349F5A6AA5A4D3C5172F9D2C7DF9FDDBE841EAD6`.

The result is `supplied_production_broker_projection_correspondence_matched_execution_unresolved`, with correspondence proved, all 15 A8 authority fields false, 22 effect fields zero/false, one attempt, no retry, and no cleanup.

## Adversarial and workspace verification

The verifier refuses independently rehashed mutation of every 24-field declaration coordinate, every 44-field request coordinate, every 68-field receipt coordinate, all 28 comparison fields, all 22 effect fields, all 16 manifest fields, and each three-field artifact record. It also refuses mutation of every one of the 28 explicit retained A7 semantic payloads, every 63-field nested A7 receipt coordinate, all 19 nested A7 comparison fields, and all 22 nested effects. All 26 single A8 comparison mismatches, the complete mismatch set, and 4096 bounded comparison subsets preserve exact ordered truth.

Constructive replay covers both valid A7 statuses: an internally consistent A7 mismatch is preserved as adverse nested evidence while A8 proves only its own projection correspondence and promotes no authority. Canonical BOM, CRLF, whitespace, escaping, ordering, duplicate/unknown field, concatenation, raw-byte, restart, endpoint/capability, path, membership, per-file, aggregate, and Windows junction adversaries refuse.

PowerShell 7 and Windows PowerShell 5.1 each pass 14 focused unit tests and 12 full-chain integration tests in debug and overflow-checked release, with the test-owned fixture producer as the only governed ignore. Locked offline serialized whole-workspace debug and overflow-checked release each pass 305 result groups, 1881 tests, zero failures, and 21 governed ignores. Workspace and five standalone experiment Clippy surfaces pass all targets and features with warnings denied; debug and release documentation and formatting pass.

The three nested canonical self-digested manifests are excluded from the generic transitive JSON rewriter. They may be changed only by the typed fixture producer; this prevents formatting or partial-rehash laundering of retained evidence.

## Scope

All checked-in coordinates are deterministic and synthetic. The pinned local provider remains unavailable; A8 performs zero live and synthetic provider trials. Private-permit verification, endpoint resolution, broker connectivity/authentication, activation, physical preparation, execution, and autonomous operation require later separately governed phases.
