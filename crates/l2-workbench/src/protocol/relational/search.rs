//! Bounded search and frozen rule replay for relational transforms

mod discovery;
mod input;
mod locator;
mod replay;

pub use discovery::{
    infer_relational_transform_candidates, infer_relational_transform_candidates_with_job,
};
pub use replay::apply_relational_transform_rule;
