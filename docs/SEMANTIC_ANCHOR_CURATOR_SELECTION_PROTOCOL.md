# Semantic Anchor curator-selection protocol

Slice 5F provides a provider-free verifier for an externally governed curator
policy and Ed25519-signed exact candidate selection. Cantor does not ship a
governed curator policy, real curator private key, or selected target.

The verifier checks:

- exact raw Slice 5A evidence SHA-256 and report digest;
- one unique curator grant, Ed25519 public key, allowed query, authority scope,
  and source requirement;
- exact query, ambiguous candidate identity, and source-anchor membership;
- canonical selection-payload signature; and
- strict status separation between `GovernedSelection` and
  `SyntheticFixtureOnly`.

Signature verification proves payload integrity and possession of the
policy-pinned key. It does not prove that the policy itself was governed.
Downstream activation must independently admit policy provenance before a
`GovernedSelection` receipt can support Semantic Anchor Slice 6.

## Operator flow

Prepare strict policy and payload JSON outside the repository. Export the exact
bytes to sign:

```powershell
cargo run -p cantor_core --bin cantor-semantic-anchor-curation -- `
  --canonicalize-payload selection-payload.json selection-payload.bin
```

Sign `selection-payload.bin` with the policy-pinned Ed25519 key, encode the
64-byte signature as hexadecimal, and form the signed selection JSON. Verify
the policy and selection against the checked baseline:

```powershell
cargo run -p cantor_core --bin cantor-semantic-anchor-curation -- `
  --verify `
  experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json `
  curator-policy.json signed-selection.json verified-receipt.json
```

The repository’s checked evidence is deliberately synthetic:

```powershell
cargo run -p cantor_core --bin cantor-semantic-anchor-curation -- `
  --verify-synthetic-fixture `
  experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json `
  experiments/semantic_anchor_catalogue_slice5f/synthetic_curator_selection_fixture.json
```

It proves protocol mechanics only. The correction catalogue retains null real
targets, and the synthetic key and receipt must never be treated as governance
authority.
