//! Effectless deterministic runtime for the CTPR machine forms.
//!
//! The runtime owns immutable value transitions only. It performs no clock
//! reads, persistence, filesystem access, provider calls, threads, or effects.

mod evaluator;
mod planner;
mod repository;
mod types;

pub use evaluator::{
    digest_material_event, digest_repository_generation, digest_semantic_snapshot,
    evaluate_runtime, from_normalized_runtime_snapshot, replay_runtime,
    to_normalized_runtime_snapshot,
};
pub use types::*;
