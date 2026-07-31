# Phase 3 topology forms

`cantor_ecosystem::topology_forms` is the effect-free M2A vocabulary for the
future Windows candidate-topology scanner.

The public form vocabulary is `cantor-phase3-topology-forms/0.3`. Topology
receipts identify their serialized contract separately as
`cantor-phase3-topology-receipt/0.3`, while the future physical scanner policy
remains `cantor-windows-candidate-topology/0.1`.

It validates:

- hard scan limits;
- 128-bit scan-local file identities;
- root, directory, regular-file, and stream observation structure;
- caller-constructible topology-receipt forms with separate receipt and scanner
  profiles and a required `consistency_evidence` label;
- required root identity and canonical volume-GUID final-path syntax;
- half-open receipt-consumption intervals; and
- honest deny-launch versus quarantine consequences.

Former receipt shapes are intentionally rejected. The 0.1 shape used one
overloaded `profile` field and carried neither `root_identity` nor
`root_volume_guid_path`. The 0.2 shape used `consistency` and
`quiescent_double_inventory`, which overstated equal non-atomic repeated
acquisition evidence. Missing observations and changed meaning are never
reconstructed through aliases or migration.

Receipt 0.3 admits only `non_atomic_repeated_inventory_equal`.
`os_snapshot_proven` remains a structural enum value but is rejected by receipt
validation until a later authority defines and proves its snapshot provenance.

A valid form is not acquisition evidence or proof that the observation is true,
and public construction is not receipt issuance. The module cannot read
a filesystem, call Win32, prove that the candidate address, identity, and final
path correspond, enforce topology policy, generate time or randomness, or
ensure a receipt is consumed globally only once. Those responsibilities remain
in separately governed M2B through M2E slices.
