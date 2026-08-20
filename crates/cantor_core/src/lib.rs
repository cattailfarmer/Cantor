//! Cantor Core v0.1.
//!
//! This crate implements the deterministic semantic IR, trusted package
//! boundary, and proof-carrying in-memory query core. It does not implement
//! neural, FPGA, provider, database, or distributed-runtime behavior.

pub mod environment;
pub mod evaluator;
pub mod faculty;
pub mod fixtures;
pub mod machine;
pub mod model;
pub mod prepared;
pub mod procedure;
pub mod procedure_authorship;
pub mod procedure_compiler;
pub mod procedure_coordination;
pub mod procedure_runtime;
pub mod procedure_tool;
pub mod procedure_validation;
pub mod procedure_verifier;
pub mod protocol;
pub mod query;
pub mod review;
pub mod semantic_anchor_catalogue;
pub mod semantic_anchor_scan;
pub mod shared_attention;
pub mod sop;
pub mod temporal;
pub mod temporal_runtime;
pub mod trust;

pub use environment::*;
pub use evaluator::evaluate;
pub use faculty::*;
pub use fixtures::{FixtureId, FixtureReport, all_fixture_ids, run_fixture};
pub use machine::{content_digest, from_machine_form, to_machine_form};
pub use model::*;
pub use prepared::*;
pub use procedure::*;
pub use procedure_authorship::*;
pub use procedure_compiler::*;
pub use procedure_coordination::*;
pub use procedure_runtime::*;
pub use procedure_tool::*;
pub use procedure_validation::*;
pub use procedure_verifier::*;
pub use protocol::*;
pub use query::*;
pub use review::{build_capsule, review_capsule};
pub use semantic_anchor_catalogue::*;
pub use semantic_anchor_scan::*;
pub use shared_attention::*;
pub use sop::*;
pub use temporal::*;
pub use temporal_runtime::*;
pub use trust::*;

/// Version of the semantic intermediate representation implemented here.
pub const IR_VERSION: &str = "cantor-ir/0.1";
