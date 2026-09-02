//! Pure shared semantic-frame governance for independent inference passes.
//!
//! This module owns transportable frame state, atomic typed deltas,
//! backpressure, same-digest settlement, and bounded hypothetical branches.
//! It never reads a clock, performs IO, invokes a model, executes an effect,
//! or shares provider hidden state.

mod accounting;
mod accounting_manifest;
mod accounting_host;
mod admission;
mod compaction;
mod dream;
mod forms;
mod ledger;
mod runtime;
mod tool;

pub use accounting::*;
pub use accounting_manifest::*;
pub use accounting_host::*;
pub use admission::*;
pub use compaction::*;
pub use dream::*;
pub use forms::*;
pub use ledger::*;
pub use runtime::*;
pub use tool::*;

pub const SHARED_ATTENTION_PROFILE: &str = "cantor-shared-attention-frame/0.1";
pub const ATTENTION_DELTA_PROFILE: &str = "cantor-shared-attention-delta/0.1";
pub const FRAME_ATTESTATION_PROFILE: &str = "cantor-frame-attestation/0.1";
pub const DREAM_FRAME_PROFILE: &str = "cantor-dream-frame/0.1";
pub const DREAM_REVIEW_PROFILE: &str = "cantor-dream-review/0.1";
pub const ATTENTION_COMPACTION_PROFILE: &str = "cantor-attention-compaction/0.1";
pub const ATTENTION_BYTE_PROXY_PROFILE: &str = "canonical-json-utf8-bytes/0.1";
