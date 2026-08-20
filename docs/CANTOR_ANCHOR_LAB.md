# Cantor Anchor Lab

`cantor-anchor-lab` is the first direct lexical lookup over Cantor's compiled
semantic-anchor sidecar. It accepts ordinary text, admits one signed local
runtime environment, derives the catalogue and lexical index in memory, and
returns ordered exact semantic addresses with source-bearing evidence.

Build it:

```powershell
cargo build -p cantor_cli --bin cantor-anchor-lab
```

Query an existing environment:

```powershell
.\target\debug\cantor-anchor-lab.exe query `
  --environment .\.local\cantor-demo\environment.json `
  --text "Cantor"
```

To inspect the exact signed SOP snapshot behind every returned address:

```powershell
.\target\debug\cantor-anchor-lab.exe query `
  --environment .\.local\cantor-demo\environment.json `
  --text "Cantor" `
  --include-source
```

Or query an operator-built self-hosted corpus:

```powershell
.\target\debug\cantor-anchor-lab.exe query `
  --environment .\.local\cantor-self-hosted\environment.json `
  --text "PreparedRuntime"
```

The optional `--maximum-postings` and `--maximum-matches` flags set strict
complete-result limits. Cantor refuses when either complete set exceeds its
limit; it does not return a potentially misleading partial lexical result.

The success JSON binds:

- the admitted environment digest;
- catalogue, fabric, lexical-index, compiler, and tokenizer identities;
- original input and deterministic token occurrence accounts;
- unmatched tokens;
- complete posting count;
- matches ordered by unique-token coverage, then exact address identity;
- preferred-expression, alias, and meaning-surface evidence;
- exact unit, package, context, file, clause, span, and line identities; and
- a replayable proof digest.

With `--include-source`, the success envelope also contains a separately
proof-bearing `source_projection`:

- the package-relative path recorded in the admitted snapshot;
- exact UTF-8 quote text and its `SourceAnchor` byte and display-line span;
- the signed document digest and recognition-certificate identity;
- one digest per projection and one digest for the ordered projection result;
- an explicit warning that the quote proves the admitted snapshot, not the
  current mutable filesystem or external truth.

Cantor never opens the projected path. The bytes come from the package that was
already signature-checked and admitted in memory. If any lexical match lacks an
exact package, quote, source snapshot, certificate, or anchor correspondence,
the entire projection refuses instead of silently omitting that match.

This laboratory performs lexical correspondence only. It does not run purpose,
use-case, boundary, lifecycle, applicability, authority, safety, or truth
gates, and its output says so explicitly. It writes no artifact, invokes no
model or service, and changes neither the existing `cantor query` protocol nor
the exact semantic-anchor scanner.
