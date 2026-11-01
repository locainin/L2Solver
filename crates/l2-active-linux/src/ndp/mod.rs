//! Read Linux IPv6 assignments and prepare a checked on-link solicitation

mod admission;
mod discovery;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/ndp/internal.rs"]
mod tests;

pub use admission::prepare;
pub use discovery::{Ipv6Assignment, NdpInterfaceInfo, discover, discover_until};
