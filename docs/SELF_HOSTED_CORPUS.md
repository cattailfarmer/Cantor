# Cantor self-hosted SOP corpus

Cantor now has a complete local source-to-query loop for a deliberately
bounded SOP profile:

```text
reviewed .sop bytes
  -> strict parser
  -> deterministic SemanticUnit and Narrower records
  -> exact byte anchors and quotes
  -> SHA-256 + distinct Ed25519 package attestations
  -> generated trust store and environment
  -> verified query/inspect requests
  -> cantor CLI or read-only MCP response
```

This is the first self-hosting product slice, not a claim that every imagined
SOP construct is executable. Unsupported syntax is rejected; it is never
silently ignored or interpreted by a language model.

## Build the tracked corpus

Create two distinct Ed25519 seed files. Each file must contain either exactly
32 raw bytes or 64 ASCII hexadecimal digits with at most one final LF or CRLF.
Key generation and production key custody are intentionally outside this
slice.

```powershell
cargo build --workspace --release --locked --offline

.\target\release\cantor-corpus.exe compile `
  --manifest .\corpus\self_hosted\corpus.json `
  --authority-key C:\secure\cantor-authority.key `
  --compiler-key C:\secure\cantor-compiler.key `
  --output .\.local\cantor-self-hosted
```

Existing artifact names are refused. Supply `--replace` only when replacing a
previously verified local build.

The compiler preflights parsing, lowering, collision detection, signing,
trust admission, every generated request, and exact protocol verification in
memory before publishing. Individual files are written through same-directory
temporary files and atomic rename. `build-manifest.json` is published last; a
missing manifest or artifact-hash mismatch means the set is not ready.

The tracked manifest compiles:

- `specifications/SOP_Core.sop`
- `specifications/Cantor_Semantic_Coprocessor_Identity.sop`
- `specifications/Cantor_Prepared_Runtime.sop`

The current reviewed corpus contains 3 sources, 417 semantic units, and 360
typed containment relations.

## Query it

```powershell
.\target\release\cantor.exe query `
  --environment .\.local\cantor-self-hosted\environment.json `
  --input .\.local\cantor-self-hosted\query-semantic-unit.json

.\target\release\cantor.exe query `
  --environment .\.local\cantor-self-hosted\environment.json `
  --input .\.local\cantor-self-hosted\query-cantor.json

.\target\release\cantor.exe query `
  --environment .\.local\cantor-self-hosted\environment.json `
  --input .\.local\cantor-self-hosted\query-prepared-runtime.json

.\target\release\cantor.exe inspect `
  --environment .\.local\cantor-self-hosted\environment.json `
  --input .\.local\cantor-self-hosted\inspect-fabric.json
```

Each successful query returns the semantic record, exact governing source
line, byte and display-line anchors, source and span digests, package and
certificate identities, signers, relationship paths, decision trace, detail
accounts, and a recomputable result digest.

The same environment can be served through the embedded MCP process:

```powershell
.\target\release\cantor-mcp.exe `
  --environment .\.local\cantor-self-hosted\environment.json
```

Embedded mode advertises `query_sop` and `lookup_sop_anchors`. The former
returns exactly the core `ProtocolResponse`; the latter maps ordinary text to
the derived lexical catalogue and, by default, returns the exact admitted SOP
source quotations and source-projection proof. The MCP adapter owns no parser,
trust, ranking, source-projection, or proof policy: it invokes the corresponding
core operations over the immutable admitted generation prepared at startup.

## Bounded source profile

`cantor-sop-source/0.1` recognizes:

- one unindented `Subject:` metadata line;
- an optional unindented `Description:` line;
- `& [name] body` as `Term`;
- `+ [name] body` as `Declaration`;
- `@ [name] body` as a queryable `Relation` record;
- `! [name] body` as `Judgment`;
- `= body` as `Operation`;
- `- body` as `Contract`;
- blank lines and `#` comments; and
- exact two-space indentation levels.

Every other nonblank line faults with document identity, path, line, byte
range, kind, bounded preview, and deterministic message. Tabs, invalid UTF-8,
orphan indentation, malformed brackets, empty bodies, resource-limit
violations, and identical sibling declarations are rejected.

The parser does not infer a target endpoint from `@` prose. The only relation
it synthesizes is directly observed syntax containment:
`parent Narrower child`.

## Stable identity and recompilation

File identity derives from project, namespace, and explicit `document_id`.
Unit identity derives from document identity, marker family, parent key, local
name when present, and normalized body digest. File paths and line numbers are
not semantic identity.

Moving a file, changing LF to CRLF, or inserting unrelated display lines
preserves semantic identity. Changing asserted content changes its content
identity. In either case, changed source bytes require recompilation because
the signed document, root, quote, and anchor digests change.

Repeated field names such as `+ [edge]` are valid when their bodies differ.
No encounter ordinal is used, so reordering siblings preserves identity.

## Key and artifact boundary

Private seeds are read only from explicit command-line paths. Cantor emits
public verifying keys and SHA-256 fingerprints, never private seed bytes or
paths. The compiler requires distinct signer identities and seed bytes.

`corpus/self_hosted/corpus.json`, source, code, tests, and evidence are tracked.
Keys and generated runtime artifacts belong under ignored `.local/` storage.
The deterministic seeds used by automated tests are public test material and
grant no production authority.

## Measured local profile

Three 30-iteration overflow-checked release runs on the current Windows host
reported:

- parse and lower median: 1.46–1.54 ms;
- signed package compile median: 6.64–6.75 ms;
- complete build and request preflight median: 67.92–68.26 ms;
- environment JSON load median: 2.25–2.27 ms;
- direct request-scoped exact query median: 6.13–6.29 ms; and
- prepared exact query hit median: 47.0–47.5 µs.

All measured responses matched. These results cover three reviewed files, not
a terabyte-scale database, network service, production key system, learned
router, or hardware implementation. Raw reports and the content-addressed
summary are under `experiments/self_hosted_corpus_benchmark/artifacts`.

## Authority

The governed contract is
`specifications/Cantor_Self_Hosting_Ingestion.sop`. Its separate source,
explosion, justification, feature slice, matrix, solution, and proof records
preserve the SJS chain.
