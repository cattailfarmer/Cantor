# A4 supplied time-witness correspondence

This provider-free verifier connects an explicitly supplied signed witness to the
existing A1 policy, A2 custody and A3 revocation-snapshot correspondence chain.
It compares the supplied observation with the supplied A3 interval. It does not
read a clock, contact a time service, establish witness trust or authorize work.

The formation is frozen at `e06d2f31362a881455883126a3060c6b6e7705c3`,
bookended by `73de513e0ad2a8c98f166015728fb391f19db091`.
Implementation completion requires the independent gates; existence of these
files is not a completion claim.

## Interfaces

`cantor-b1-trusted-time-witness-verify` takes exactly fourteen explicit
retained input filenames, in this order:

1. predecessor_request.json
2. predecessor_packet.json
3. predecessor_verification.json
4. a1_policy_envelope.json
5. a1_verification_request.json
6. a1_receipt.json
7. custody_attestation.json
8. a2_verification_request.json
9. a2_receipt.json
10. revocation_snapshot.json
11. a3_verification_request.json
12. a3_receipt.json
13. time_witness_receipt.json
14. verification_request.json

`cantor-b1-trusted-time-witness-evidence-verify` takes one directory containing
those files plus `receipt.json` and `evidence_manifest.json`. It checks the
exact file set, ordered raw-byte manifest, upstream replay, and reconstructed
receipt twice. Both commands emit the canonical receipt plus one LF to stdout;
refusal emits no receipt, reports stderr and exits 2. They never write output
files, resolve evidence references or load private keys.

Files use typed declaration-order compact UTF-8 JSON and exactly one LF.
Candidate raw hashes exclude that LF; artifact hashes include it.
Limits are 1 MiB per form plus the transport LF, 16 MiB per evidence set,
JSON depth 32, total fields 4096, text 8192 bytes, and 1–48 opaque references.

Readers bound bytes before and during reads and reject nonregular/link/reparse
entries and linked directory ancestry. The caller supplies a stable local
directory. These checks do not constitute an atomic filesystem snapshot or an
OS access sandbox against concurrent ancestor replacement.

## Meaning of a successful receipt

The request explicitly pins witness UUID, supplied authority label, key,
fingerprint and positive sequence. A changed witness signed by another key
fails against the unchanged request. Replacing both the witness and the entire
request creates a different correspondence event, not an authenticated trust
decision. The signature input binds the prior A3 packet, avoiding a circular
digest through the resulting A4 packet.

Structural bounds are `issued <= observed <= expires`. A3 interval comparison
uses `observed < this_update`, `this_update <= observed <= next_update`, or
`observed > next_update`; both endpoints are within. Zero and u64 maximum
require no subtraction. Sequence is not replay protection.

All twelve correspondence fields are true, all twenty-nine authority fields
remain false and all twenty-two effect fields remain zero/false. The five
downstream authorities remain unresolved. Neither an external candidate nor a
within-interval outcome establishes current time, time-source authority,
accuracy, freshness, operative revocation truth or execution permission.
No RFC 3161, OCSP or NTS interoperability is claimed.

## Verification

Run the reviewed focused script from the repository root, with Cargo output and
temporary test directories configured on D:

```powershell
$env:CARGO_TARGET_DIR = 'D:\crf\target'
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_INCREMENTAL = '0'
$env:RUST_MIN_STACK = '33554432'
$env:TEMP = 'D:\CantorBuilds\B1A4TestTemp'
$env:TMP = $env:TEMP
pwsh -NoProfile -File scripts/test_b1_trusted_time_witness_receipt_verification.ps1
```

The example uses this development worktree's D-drive target directory and an
existing, direct non-repository D-drive temporary directory. Create the latter
if absent. Keep temporary fixtures outside every Git checkout: the full
workspace includes refusal tests that require a genuinely non-repository path.
Choose corresponding D-drive locations for a different checkout.

The same gate is required under Windows PowerShell 5.1 using only the explicitly
approved process-scoped RemoteSigned invocation; no persistent policy changes.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/test_b1_trusted_time_witness_receipt_verification.ps1
```

The script exercises debug and overflow-checked release, two fresh independent
process replays per profile, exact retained receipt correspondence and conserved
authority/effect fields.

If the retained directory is absent, only the ignored test-owned
`produce_retained_twv_fixture_evidence` producer can create it. It requires
`CANTOR_TWV_EVIDENCE_OUTPUT`, refuses an existing directory, and signs only
synthetic deterministic fixture material. It is not a production witness
issuer. External-shape test cases are synthetic tests of admission shape, not
live external trust evidence.

The verification manifest's required fresh-process count is an obligation
discharged by the script/tests; an in-process replay does not spawn processes.
Full exact workspace, formation, evidence, attribution and publication gates
are recorded separately in implementation closure records.
