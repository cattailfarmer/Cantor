# Phase 3 topology forms

`cantor_ecosystem::topology_forms` is the effect-free M2A vocabulary for the
future Windows candidate-topology scanner.

It validates:

- hard scan limits;
- 128-bit scan-local file identities;
- root, directory, regular-file, and stream observation structure;
- fresh, content-addressed topology receipts;
- half-open receipt-consumption intervals; and
- honest deny-launch versus quarantine consequences.

A valid form is not proof that the observation is true. The module cannot read
a filesystem, call Win32, enforce topology policy, generate time or randomness,
or ensure a receipt is consumed globally only once. Those responsibilities
remain in separately governed M2B through M2E slices.
