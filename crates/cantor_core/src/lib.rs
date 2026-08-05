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
pub mod protocol;
pub mod query;
pub mod review;
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
pub use protocol::*;
pub use query::*;
pub use review::{build_capsule, review_capsule};
pub use sop::*;
pub use temporal::*;
pub use temporal_runtime::*;
pub use trust::*;

/// Version of the semantic intermediate representation implemented here.
pub const IR_VERSION: &str = "cantor-ir/0.1";
