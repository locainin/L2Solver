//! Prepare a single link-local EAPOL Start before opening a backend

use l2_onpath::MacAddress;

use crate::Limits;

use super::wire;

/// One Start from the selected interface's own Ethernet identity
#[derive(Clone, Debug)]
pub struct Dot1xProbe {
    pub(super) source: MacAddress,
    pub(super) limits: Limits,
    frame: [u8; wire::START_LEN],
}

impl Dot1xProbe {
    /// Prepare a single PAE-group EAPOL Start
    ///
    /// The backend must verify that `source` belongs to the pinned interface
    /// before allowing a send. A Start can affect an existing supplicant, so
    /// the caller must obtain explicit opt-in and use a dedicated interface
    ///
    /// # Errors
    /// Returns an error if the shared Ethernet encoder rejects the frame
    pub fn new(source: MacAddress, limits: Limits) -> Result<Self, l2_core::EncodeError> {
        Ok(Self {
            source,
            limits,
            frame: wire::start(source)?,
        })
    }

    /// Borrow the complete FCS-free Ethernet frame including minimum padding
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Return the source MAC that the backend must bind to its selected link
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source
    }

    /// Return the admitted response time and receive limits
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
}
