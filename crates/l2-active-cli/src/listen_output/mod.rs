//! Present received discovery and spanning-tree evidence

mod collection;
mod discovery;
mod stp;

pub use discovery::write as write_discovery;
pub use stp::write as write_stp;
