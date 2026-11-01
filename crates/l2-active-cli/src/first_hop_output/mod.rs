//! Present first-hop claims without exposing sensitive frames by default

mod hsrp;
mod vrrp;

pub use crate::listen_output::collection::Context;
#[cfg(test)]
pub use crate::listen_output::collection::Disclosure;
pub use hsrp::write as write_hsrp;
pub use vrrp::write as write_vrrp;
