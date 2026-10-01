# Windows inspection runtime seed P0

This is a small, rebuildable **inspection seed**, not an installer, model host, or
autonomous Cantor agent. The completed consumer handoff and official-rmcp adapter
are its unchanged foundation. Current authority is Pinky's live .sop root; the
ReasoningFramework history is provenance, not runtime authority.

## Build and verify

Use the reviewed tooling in PowerShell 7.6 on this Windows x86-64 host, with the
existing Rust 1.96.0 MSVC toolchain and offline dependencies. Compatible Windows
and MSVC/UCRT runtime libraries are prerequisites; portability to a different
machine and full distribution/dependency licensing have not been proved.

The producer requires a fresh, absent leaf named seed- followed by 32 lowercase
hexadecimal characters directly below D:\CantorBuilds\cantor-inspection-seed.
It always runs the locked, offline, single-job, overflow-checked release build of
cantor-sop-inspect-stdio and cantor-sop-inspect-mcp in D:\CantorBuilds\target.
Inherited Cargo target, encoded Rust flags, and compiler wrappers are cleared
only for that recipe, then restored. The host/version check refuses another
toolchain. A separately signed local metadata refinement binds the exact scoped
flags -C overflow-checks=on -C link-arg=/Brepro. This prevents the observed MSVC
timestamp/PDB nonce drift without editing or comparing away executable bytes;
only actual local retained-byte proof is claimed, not cross-host reproducibility.
There is no prebuilt-binary selector, target override, overwrite,
cleanup, extraction, or installation switch.

Run scripts/build_cantor_inspection_runtime_seed_p0.ps1 with -OutputLeaf set to
that fresh leaf. It creates exactly:

- cantor-inspection-runtime-seed-windows-x86_64-p0.zip
- seed-report.json

Run scripts/verify_cantor_inspection_runtime_seed_p0.ps1 with -PackageLeaf to
replay the read-only archive checks. The independent verifier never calls the
producer, extracts files, or starts a packaged runtime. It reads at most 16 MiB
for the ZIP and 128 KiB for the report, checks exact raw ZIP framing and all
seven ordinal entries, recomputes actual CRC32/SHA256, compares executable bytes
with the current recipe's targets, and rederives the SOP, examples, guide and
manifest from source. All metadata must match exact canonical raw JSON bytes;
duplicates, unknown fields, different types/order and trailing JSON refuse.

## Contents and endpoint ownership

The seven entries, in ordinal order, are GUIDE.md, the two named bin executables,
examples/inspect-seed-request.json, examples/mcp-tool-arguments.json,
seed-manifest.json and sop/seed.sop. ZIP uses store-only data, fixed DOS1980 time,
UTF-8 names, exact local/central/end records, and no extras, comments, descriptors,
encryption, split disks, ZIP64, attributes, padding or trailing bytes.

The real kind/context/term SOP declares five descriptive Seed units. It is not
an installation commission. The stdio endpoint receives one sealed supplied-value
inspection request and observed EOF, then returns one wire JSON value without a
newline. The MCP endpoint uses inherited stdin/stdout, protocol initialization,
then the sole inspect_sop_semantics tool with a single wire_request_json string.
The caller awaits each response, retains structuredContent and exact nested wire
bytes, owns the process/deadline/captures, and closes input on completion.
The session is ephemeral; restart belongs to the caller. Protocol stdout cannot
carry logging.

The separate developer-only native test creates exactly two fresh executable
copies and starts the stdio and MCP endpoints. It bounds aggregate stdout at
1 MiB, uses 4096-byte asynchronous reads and a 30-second whole-exchange deadline,
requires empty stderr and exit zero, and kills/reaps only a failed child.
It verifies five unique complete source excerpts against exact UTF-8 spans,
MCP tool/schema/non-authority metadata, two byte-identical wire responses, one
unknown-tool refusal, one malformed-argument refusal and subsequent recovery.
There is no runtime invocation in package production or archive verification.

## Evidence and rebuild limits

The adversarial script compares two fresh mandatory-recipe ZIP/report generations
byte-for-byte and exercises output scope, file/entry bounds, raw metadata,
container fields, ordering, duplicate names, actual CRC and payload identity.
Internally repaired binary/seed mutants also update manifest/report hashes and
ZIP CRCs; they still cannot replace source or target identity. Refusals are
counted only when the verifier emits its explicit seed_ contract fault, not when
the harness crashes.

All executable source is unchanged. Complete locked/offline serialized workspace
debug/release, warnings-denied Clippy, format, PowerShell parsing, physical evidence
and exact owned Git attribution remain required closure gates. All-feature
workspace builds can change target binaries through dependency feature unification;
therefore the mandatory production recipe is repeated afterwards and the retained
candidate must still match. Hashes describe this local build, not publisher trust,
cross-compiler reproducibility, application acceptance or another host.

ZIPs, executable copies, logs and adversarial scratch remain outside Git on D:.
Only small source fixtures, tooling, identities, measured reports and SJS/narrative
closure are published. No installer, model/provider, remote machine, Windows
policy change, WSL build, autonomous SOP job or full Cantor distribution is
authorized by this seed. Those are separate governed frontiers.
