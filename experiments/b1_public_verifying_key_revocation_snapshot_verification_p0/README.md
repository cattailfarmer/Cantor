# B1 A3 revocation snapshot verification P0

This provider-free experiment verifies exact supplied A3 snapshot bytes against the published A0 packet, A1 policy-envelope correspondence receipt, and A2 public-key possession-correspondence receipt. It checks target-key lineage, one of three declared status assertions, internal interval structure, and a detached Ed25519 responder signature.

It does not authenticate or authorize the responder, establish registry completeness or a monotonic authoritative head, prevent rollback, read a current clock, establish freshness, decide operative revocation, or grant any downstream execution authority. The retained material is deterministic fixture evidence only.

Run the complete focused debug, overflow-checked release, core-CLI, evidence-CLI, and fresh-process replay surface from the repository root:

```powershell
./scripts/test_b1_public_verifying_key_revocation_snapshot_verification.ps1
```

The retained directory contains exactly thirteen direct regular nonlink files. Twelve payload artifacts are bound by `evidence_manifest.json`; the independent reader hashes the LF-terminated retained bytes before parsing and reconstructs the entire A0/A1/A2/A3 chain twice.

The evidence CLI accepts exactly one explicit directory and writes one nonauthorizing receipt plus LF to stdout:

```powershell
cargo run --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-evidence-verify -- experiments/b1_public_verifying_key_revocation_snapshot_verification_p0/implementation_provider_free_evidence
```
