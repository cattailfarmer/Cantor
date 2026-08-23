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
pub mod nested_host_identity;
pub mod objective_work_plan;
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
pub mod self_hosted_anchor_evidence;
pub mod semantic_anchor_catalogue;
pub mod semantic_anchor_curation;
pub mod semantic_anchor_scan;
pub mod semantic_compiler;
pub mod shared_attention;
pub mod sop;
pub mod sop_boot_session;
pub mod temporal;
pub mod temporal_runtime;
pub mod trust;

pub use environment::*;
pub use evaluator::evaluate;
pub use faculty::*;
pub use fixtures::{FixtureId, FixtureReport, all_fixture_ids, run_fixture};
pub use machine::{content_digest, from_machine_form, to_machine_form};
pub use model::*;
pub use nested_host_identity::*;
pub use objective_work_plan::*;
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
pub use self_hosted_anchor_evidence::*;
pub use semantic_anchor_catalogue::*;
pub use semantic_anchor_curation::*;
pub use semantic_anchor_scan::*;
pub use semantic_compiler::*;
pub use shared_attention::*;
pub use sop::*;
pub use sop_boot_session::*;
pub use temporal::*;
pub use temporal_runtime::*;
pub use trust::*;

/// Version of the semantic intermediate representation implemented here.
pub const IR_VERSION: &str = "cantor-ir/0.1";
