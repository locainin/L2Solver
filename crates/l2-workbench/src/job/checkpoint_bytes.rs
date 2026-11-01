//! Serde codec for checkpoint byte fields
//!
//! Admit the complete encoded document, parser scratch, and decoded state before deserializing.
//! Bound the input separately and keep the resulting memory allowance while decoded bytes live.
//! This codec does not perform memory admission by itself.

pub use crate::serialization::base64::{deserialize, serialize};
