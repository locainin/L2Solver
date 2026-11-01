//! Present received discovery and spanning-tree evidence

pub(crate) mod collection;
mod discovery;
pub(crate) mod isl;
mod stp;
pub(crate) mod switching;

pub use discovery::write as write_discovery;
pub use stp::write as write_stp;
