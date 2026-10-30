//! Preparation of one bounded broadcast ARP request

use std::net::Ipv4Addr;

use l2_core::{EthernetFrame, FrameField};
use l2_onpath::MacAddress;

use crate::{Limits, PlanError};

/// One ARP request bound to a selected source and target IPv4 address
#[derive(Clone, Debug)]
pub struct ArpProbe {
    pub(super) source_mac: MacAddress,
    pub(super) source_ip: Ipv4Addr,
    pub(super) target: Ipv4Addr,
    pub(super) expected: Option<MacAddress>,
    pub(super) limits: Limits,
    frame: [u8; 60],
}

impl ArpProbe {
    /// Prepare the exact request before acquiring transmit authority
    ///
    /// # Errors
    /// Rejects invalid source/target addresses, aliases, or encoder failures
    pub fn new(
        source_mac: MacAddress,
        source_ip: Ipv4Addr,
        target: Ipv4Addr,
        expected: Option<MacAddress>,
        limits: Limits,
    ) -> Result<Self, PlanError> {
        validate_ipv4_target(source_ip)?;
        validate_ipv4_target(target)?;
        if source_ip == target {
            return Err(PlanError::SameAddress);
        }
        let frame = request(source_mac, source_ip, target)?;
        Ok(Self {
            source_mac,
            source_ip,
            target,
            expected,
            limits,
            frame,
        })
    }

    /// Return the precommitted FCS-free Ethernet frame including minimum padding
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Return the explicitly selected source MAC
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source_mac
    }

    /// Return the explicitly selected configured source IPv4 address
    #[must_use]
    pub const fn source_ip(&self) -> Ipv4Addr {
        self.source_ip
    }

    /// Return the one requested IPv4 target
    #[must_use]
    pub const fn target(&self) -> Ipv4Addr {
        self.target
    }

    /// Return an optional expected target identity
    #[must_use]
    pub const fn expected(&self) -> Option<MacAddress> {
        self.expected
    }

    /// Return the admitted resource limits
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
}

/// Reject IPv4 values that cannot name one unicast on-link host
///
/// The caller must also confirm the target belongs to its authorized scope
///
/// # Errors
/// Rejects unspecified, loopback, multicast, broadcast, and reserved ranges
pub const fn validate_ipv4_target(address: Ipv4Addr) -> Result<(), PlanError> {
    let [first, ..] = address.octets();
    if first == 0 || first >= 224 || address.is_loopback() || address.is_broadcast() {
        return Err(PlanError::InvalidAddress);
    }
    Ok(())
}

fn request(
    source_mac: MacAddress,
    source_ip: Ipv4Addr,
    target: Ipv4Addr,
) -> Result<[u8; 60], PlanError> {
    let [m0, m1, m2, m3, m4, m5] = source_mac.bytes();
    let [s0, s1, s2, s3] = source_ip.octets();
    let [t0, t1, t2, t3] = target.octets();
    let payload = [
        0, 1, 8, 0, 6, 4, 0, 1, m0, m1, m2, m3, m4, m5, s0, s1, s2, s3, 0, 0, 0, 0, 0, 0, t0, t1,
        t2, t3,
    ];
    let ethernet = EthernetFrame {
        destination: [0xff; 6],
        source: source_mac.bytes(),
        vlan_tags: Vec::new(),
        field: FrameField::EtherType(0x0806),
        payload: &payload,
        padding: &[0; 18],
    };
    let mut frame = [0; 60];
    l2_core::encode(&ethernet, &mut frame).map_err(PlanError::Encode)?;
    Ok(frame)
}
