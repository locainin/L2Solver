//! Prepare one scoped DHCP discovery before acquiring transmit authority

use std::{net::Ipv4Addr, num::NonZeroU32};

use l2_onpath::MacAddress;

use crate::{Limits, validate_ipv4_target};

use super::{DhcpError, encode};

// A short operator-supplied allowlist bounds memory and comparison work
const MAX_AUTHORIZED_SERVERS: usize = 64;

/// One DHCP discover using the selected interface's own Ethernet identity
#[derive(Clone, Debug)]
pub struct DhcpProbe {
    pub(super) source: MacAddress,
    pub(super) transaction: NonZeroU32,
    pub(super) allowed: Option<Vec<Ipv4Addr>>,
    pub(super) limits: Limits,
    frame: [u8; encode::FRAME_LEN],
}

impl DhcpProbe {
    /// Prepare the exact broadcast discovery request
    ///
    /// `transaction` must be freshly generated from a cryptographically secure
    /// random source for each operation. The backend must verify that `source`
    /// belongs to the selected interface before admitting the frame. An absent
    /// allowlist records offers without classifying server IDs as expected
    ///
    /// # Errors
    /// Rejects invalid server IDs, an empty or oversized allowlist, duplicate
    /// IDs, unavailable bounded storage, or an encoding failure
    pub fn new(
        source: MacAddress,
        transaction: NonZeroU32,
        allowed: Option<&[Ipv4Addr]>,
        limits: Limits,
    ) -> Result<Self, DhcpError> {
        let allowed = allowed.map(validate_allowlist).transpose()?;
        let frame = encode::discover(source, transaction)?;
        Ok(Self {
            source,
            transaction,
            allowed,
            limits,
            frame,
        })
    }

    /// Borrow the prepared complete Ethernet frame without FCS
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Return the source MAC that the backend must bind to its selected link
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source
    }

    /// Return the caller-supplied transaction identifier
    #[must_use]
    pub const fn transaction(&self) -> NonZeroU32 {
        self.transaction
    }

    /// Return the admitted deadline and receive limits
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
}

fn validate_allowlist(addresses: &[Ipv4Addr]) -> Result<Vec<Ipv4Addr>, DhcpError> {
    if addresses.is_empty() || addresses.len() > MAX_AUTHORIZED_SERVERS {
        return Err(DhcpError::InvalidServerAllowlist);
    }
    if addresses.iter().enumerate().any(|(index, address)| {
        validate_ipv4_target(*address).is_err()
            || addresses.iter().take(index).any(|other| other == address)
    }) {
        return Err(DhcpError::InvalidServerAllowlist);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(addresses.len())
        .map_err(|_| DhcpError::Allocation)?;
    result.extend_from_slice(addresses);
    Ok(result)
}
