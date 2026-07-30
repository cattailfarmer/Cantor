# Phase 3 topology forms

`cantor_ecosystem::topology_forms` is the effect-free M2A vocabulary for the
future Windows candidate-topology scanner.

The public form vocabulary is `cantor-phase3-topology-forms/0.2`. Topology
receipts identify their serialized contract separately as
`cantor-phase3-topology-receipt/0.2`, while the future physical scanner policy
remains `cantor-windows-candidate-topology/0.1`.

It validates:

- hard scan limits;
- 128-bit scan-local file identities;
- root, directory, regular-file, and stream observation structure;
- fresh, content-addressed topology receipts with separate receipt and scanner
  profiles;
- required root identity and canonical volume-GUID final-path syntax;
- half-open receipt-consumption intervals; and
- honest deny-launch versus quarantine consequences.

The former receipt shape is intentionally rejected. It used one overloaded
`profile` field and carried neither `root_identity` nor
`root_volume_guid_path`; those missing observations cannot be reconstructed
honestly.

A valid form is not proof that the observation is true. The module cannot read
a filesystem, call Win32, prove that the candidate address, identity, and final
path correspond, enforce topology policy, generate time or randomness, or
ensure a receipt is consumed globally only once. Those responsibilities remain
in separately governed M2B through M2E slices.
