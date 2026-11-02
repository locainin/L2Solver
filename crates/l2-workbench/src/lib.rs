//! Bounded passive reconstruction, artifact evidence, and explicit byte derivations

#![forbid(unsafe_code)]

pub mod application;
pub mod artifact;
pub mod behavior;
pub mod capture_collection;
pub mod carrier;
pub mod derivation;
pub mod endpoint;
pub mod evidence;
pub mod experiment;
pub mod hypothesis;
pub mod identity;
pub mod investigation;
pub mod job;
pub mod journal;
pub mod measurement;
pub mod protocol;
pub mod query;
pub mod reconstruction;
pub mod recovery;
pub mod store;
pub mod tcp_range;
pub mod tshark;
pub mod validation;

mod allocation;
mod hashing;
mod hex;
mod integer;
mod serialization;

pub use allocation::btree_node_bytes;
pub use hashing::{parse_sha256_digest, sha256};

#[cfg(test)]
#[path = "../tests/hashing/format.rs"]
mod hashing_tests;
