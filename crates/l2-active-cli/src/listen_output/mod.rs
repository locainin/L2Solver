//! Present received discovery and spanning-tree evidence

pub mod collection;
mod discovery;
pub mod isl;
mod stp;
pub mod switching;

pub use discovery::write as write_discovery;
pub use stp::write as write_stp;
