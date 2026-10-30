//! Validate one on-link IPv6 target and prepare its solicitation

use std::{fmt, net::Ipv6Addr};

use l2_onpath::MacAddress;

use crate::Limits;

use super::wire;

/// An IPv6 neighbor solicitation cannot be prepared for the requested scope
#[derive(Debug)]
#[non_exhaustive]
pub enum NdpPlanError {
    /// Source and target must be usable unicast IPv6 addresses
    InvalidAddress,
    /// Target must differ from the selected source
    SameAddress,
    /// The selected on-link prefix length must be from 1 through 128
    InvalidPrefix,
    /// Target is outside the selected source prefix or IPv6 link scope
    TargetOffLink,
    /// The shared Ethernet encoder rejected the solicitation
    Encode(l2_core::EncodeError),
}

impl fmt::Display for NdpPlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => {
                output.write_str("address is not a usable unicast IPv6 address")
            }
            Self::SameAddress => output.write_str("target must differ from the source address"),
            Self::InvalidPrefix => {
                output.write_str("IPv6 prefix length is outside the allowed range")
            }
            Self::TargetOffLink => {
                output.write_str("target is outside the selected on-link prefix")
            }
            Self::Encode(error) => write!(output, "cannot encode the solicitation: {error}"),
        }
    }
}

impl std::error::Error for NdpPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// One neighbor solicitation bound to a selected source and on-link target
#[derive(Clone, Debug)]
pub struct NdpProbe {
    pub(super) source_mac: MacAddress,
    pub(super) source_ip: Ipv6Addr,
    pub(super) target: Ipv6Addr,
    pub(super) expected: Option<MacAddress>,
    pub(super) limits: Limits,
    prefix_len: u8,
    frame: [u8; wire::REQUEST_LEN],
}

impl NdpProbe {
    /// Prepare the exact solicitation before acquiring transmit authority
    ///
    /// The backend must independently verify that the source address and
    /// prefix belong to its pinned interface and that the target is authorized
    ///
    /// # Errors
    /// Rejects invalid addresses, aliases, off-link targets, or encoding errors
    pub fn new(
        source_mac: MacAddress,
        source_ip: Ipv6Addr,
        prefix_len: u8,
        target: Ipv6Addr,
        expected: Option<MacAddress>,
        limits: Limits,
    ) -> Result<Self, NdpPlanError> {
        if !usable_unicast(source_ip) || !usable_unicast(target) {
            return Err(NdpPlanError::InvalidAddress);
        }
        if source_ip == target {
            return Err(NdpPlanError::SameAddress);
        }
        if !(1..=128).contains(&prefix_len) {
            return Err(NdpPlanError::InvalidPrefix);
        }
        let shift = 128 - u32::from(prefix_len);
        if source_ip.is_unicast_link_local() != target.is_unicast_link_local()
            || u128::from_be_bytes(source_ip.octets()) >> shift
                != u128::from_be_bytes(target.octets()) >> shift
        {
            return Err(NdpPlanError::TargetOffLink);
        }
        let frame = wire::solicitation(source_mac, source_ip, target)?;
        Ok(Self {
            source_mac,
            source_ip,
            target,
            expected,
            limits,
            prefix_len,
            frame,
        })
    }

    /// Return the complete FCS-free solicitation frame
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Return the selected source MAC
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source_mac
    }

    /// Return the source IPv6 address
    #[must_use]
    pub const fn source_ip(&self) -> Ipv6Addr {
        self.source_ip
    }

    /// Return the selected source prefix length
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the one requested target IPv6 address
    #[must_use]
    pub const fn target(&self) -> Ipv6Addr {
        self.target
    }

    /// Return the optional expected target MAC
    #[must_use]
    pub const fn expected(&self) -> Option<MacAddress> {
        self.expected
    }

    /// Return the admitted receive limits
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
}

pub(super) const fn usable_unicast(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && address.to_ipv4().is_none()
}
