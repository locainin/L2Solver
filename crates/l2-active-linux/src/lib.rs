//! Checked Linux interface selection and bounded active packet I/O

mod admission;
mod discovery;
mod selector;

/// Checked IPv6 source discovery and NDP preparation
#[cfg(target_os = "linux")]
pub mod ndp;

#[cfg(target_os = "linux")]
mod pin;

#[cfg(target_os = "linux")]
mod packet;

#[cfg(target_os = "linux")]
mod direct;

#[cfg(target_os = "linux")]
mod filter;

#[cfg(target_os = "linux")]
mod listen;

#[cfg(target_os = "linux")]
mod wire;

#[cfg(target_os = "linux")]
mod channel;

#[cfg(target_os = "linux")]
mod buffer;

#[cfg(target_os = "linux")]
mod deadline;

#[cfg(target_os = "linux")]
mod intent;

#[cfg(target_os = "linux")]
mod privileges;

#[cfg(target_os = "linux")]
mod reaper;

#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
mod client;

#[cfg(target_os = "linux")]
pub use client::HelperLink;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use worker::run_helper;

pub use admission::select_arp_source;
pub use discovery::{InterfaceInfo, Ipv4Assignment, discover};
pub use selector::InterfaceSelector;
