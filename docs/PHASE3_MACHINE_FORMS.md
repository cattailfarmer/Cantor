# Phase 3 pure machine forms

`cantor_ecosystem::phase3_evidence` is the effect-free common vocabulary for
future candidate mutation, sealing, testing, and review slices. It provides:

- typed SHA-256 artifact references;
- exhaustive Phase 3B and Phase 3C lifecycle edges;
- honest pre-turn and post-turn fault consequences;
- explicit capture-consistency and storage-immutability strength;
- coherent regular-file add, modify, delete, and mode-change records;
- independent review checks that preserve `unknown`; and
- four non-promotional review dispositions.

Call `decode_phase3_json` when admitting JSON. Serde rejects unknown fields and
enum variants, then semantic validation rejects malformed digests, unsafe
relative paths, invalid lifecycle edges, false clean-state claims, incoherent
path records, and unordered or duplicate evidence.

The module performs no I/O. It cannot inspect a path, launch Codex, mutate a
workspace, publish a seal, reconstruct a candidate, run tests, call a model,
clean state, or promote code. The physical fixtures and all later milestones
remain locked by
[`Cantor_Phase3B_3C_Physical_Proof_Plan.sop`](../plans/Cantor_Phase3B_3C_Physical_Proof_Plan.sop).
