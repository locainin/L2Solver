//! Bounded IEEE 802.11 management and security element codecs

#![forbid(unsafe_code)]

mod element;
mod error;
mod management;
mod model;
mod security;

pub use error::{ManagementError, SecurityError};
pub use management::parse_management;
pub use model::{
    ActionBody, AkmSuite, AssociationRequestBody, AssociationResponseBody, AuthenticationBody,
    BeaconBody, CipherSuite, ElementKind, ElementsBody, InformationElement, ManagementBody,
    ManagementFrame, PmfMode, ReasonBody, ReassociationRequestBody, SecurityProfile,
    SecurityProtocol,
};
pub use security::parse_security;

/// Maximum information elements retained from one management frame
pub const MAX_INFORMATION_ELEMENTS: usize = 256;

/// Maximum pairwise cipher, AKM, or PMKID entries accepted from one security element
pub const MAX_SECURITY_LIST_ENTRIES: usize = 16;
