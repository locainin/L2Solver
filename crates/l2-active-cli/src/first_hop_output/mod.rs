//! Present first-hop claims without exposing sensitive frames by default

mod hsrp;
mod vrrp;

pub(crate) use crate::listen_output::collection::Context;
#[cfg(test)]
pub(crate) use crate::listen_output::collection::Disclosure;
pub(crate) use hsrp::write as write_hsrp;
pub(crate) use vrrp::write as write_vrrp;
