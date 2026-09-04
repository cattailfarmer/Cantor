# A6 expected-observation correspondence

Implementation status: the full-chain core and independent evidence reader are
verified; exact attributed publication and its immediate bookend remain pending.
This is a supplied-data verifier, not a host-observation collector.

A6 replays the complete existing A5 operator-decision chain and the original
preparation plan already bound by its signed proposal. It then admits one exact
observation bundle and compares ten supplied facts: carrier commit, branch,
remote, project, supplied observation time, capacity floor, two build junctions,
four upstream identities, five proposed-role absence assertions, and reserved-ref
absence. A valid mismatch produces a descriptive mismatch receipt. Malformed
coordinates, substituted plans, inconsistent raw bytes, or forged receipts refuse.

The receipt contains the entire A5 receipt. Rejection, adverse revocation
assertions, and supplied-time interval outcomes remain visible. Matching A6
observations do not make any of those outcomes authoritative.

## Invocation

Run from the governed checkout with the existing locked offline toolchain.
Keep build output and temporary test files on D: in this development lane.

```powershell
$env:CARGO_TARGET_DIR = 'D:\crf\target'
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_INCREMENTAL = '0'
$env:RUST_MIN_STACK = '33554432'
$env:TEMP = 'D:\CantorBuilds\B1A4TestTemp'
$env:TMP = $env:TEMP
pwsh -NoProfile -ExecutionPolicy RemoteSigned -File scripts/test_b1_expected_observation_correspondence.ps1
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts/test_b1_expected_observation_correspondence.ps1
```

These child-process policy settings are the reviewed, explicitly approved
process-scoped settings. They are not persistent policy changes or permission
to run arbitrary scripts. The focused script creates deterministic public
fixture files only through the ignored test producer, and only if the requested
evidence directory does not already exist.

The directory verifier accepts exactly one stable supplied directory:

```powershell
cargo run --locked --offline -p cantor_ecosystem --bin cantor-b1-expected-observation-evidence-verify -- experiments/b1_expected_observation_correspondence_p0/implementation_provider_free_evidence
```

The explicit-input binary is `cantor-b1-expected-observation-verify`. Supply the
first 24 paths, in the exact order declared by `EOCV_EVIDENCE_FILES` in
`crates/cantor_ecosystem/src/b1_expected_observation_correspondence_evidence.rs`.
The directory form has those 24 inputs, `receipt.json`, and
`evidence_manifest.json`: 26 direct regular nonlink files, no extras.

Successful binaries print only a compact canonical receipt plus LF. Refusals
print an error on stderr and exit 2 without a successful receipt. Paths and
references inside supplied forms are compared as data, never followed.

## Preserved distinctions

- The legacy decision pins `98683316ff8735026dded1838c88e84edf7288f5`.
- The original preparation plan pins `49af9aa11db6696a95a13fead653c5edc1253f0d`.
- A6's `expected_carrier_commit` is a separate caller-supplied comparison value,
  not latest HEAD or signed operator consent.
- The original plan's observed capacity stays 43,004,325,888 bytes.
  New supplied capacity is compared to its 15,032,385,536-byte minimum.
- The four A6 profiles and the unchanged nested A5 profile retain their own
  ordered schemas. No signature grammar or model provider was added.

The comparison-only helper remains narrower than full verification. Use
`verify_eocv_expected_observation` or the independent evidence APIs when claiming
full supplied correspondence; `compare_eocv_supplied_values` alone does not
authenticate an upstream chain or issue an A6 receipt.

Neither form proves current host truth, collector identity, freshness, atomicity,
signer authority, a private permit, broker permission, or physical readiness.
All 14 A6 authority flags remain false; the nested A5 receipt preserves its
33 false authority flags. Both 22-field effect accounts remain zero.

## Recovery and proof

The published partial checkpoint `bedccc9349d656f255d65b70116ab175c6b79590`
and its nine-test evidence remain immutable historical records.
Current progress and final proof pointers belong in
`narrative/reentry/Cantor_B1_Expected_Observation_Correspondence_P0_Reentry.sop`
and the separate implementation requirement matrix, not the 21 frozen
formation artifacts.

## Verified implementation snapshot

The prepublication snapshot passes exact locked-offline serialized workspace
debug and overflow-checked release with 299 result groups, 1,824 reported
passes, zero failures, and 19 intentional ignores per profile. Both approved
PowerShell hosts pass 32 focused active tests per profile with one ignored
fixture producer. Two additional fresh debug and two release processes emit
the exact retained 13,096-byte receipt with SHA-256
`7790CD5CCCD15A8F69A25633FFACCEF33AA41A734B2B1ACE4E023283F60C3BFC`
and empty stderr.

The retained directory contains exactly 26 files: 25 manifest-accounted
payloads totaling 142,789 bytes plus the manifest. Its independent verifier
replays A5, the signed proposal-bound plan, and A6 twice. Workspace and five
standalone experiment Clippy gates pass with warnings denied; format,
20-library documentation in both profiles, the 21-artifact formation, both
host parsers, and 111 current manifests with 2,927 references and zero stale
bindings also pass.

These measurements authorize only exact provider-free implementation
publication. They do not turn the fixture into a current host observation,
resolve a private permit, or authorize execution. The pinned provider remains
unavailable; live and synthetic provider trial counts remain zero.
