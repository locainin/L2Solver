//! Checked protocol identities and endpoint bindings

use std::net::IpAddr;

use l2_canary::AgentId;

use crate::{InterfaceBindingRequest, ModelError};

/// Protocol identity represented by a bounded descriptor
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtocolFamily {
    /// ARP and IPv4 neighbor identity checks
    ArpIpv4,
    /// NDP and IPv6 neighbor or router checks
    NdpIpv6,
    /// Ethernet switch forwarding and MAC learning checks
    MacSwitch,
}

impl ProtocolFamily {
    /// Stable operator-facing protocol label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArpIpv4 => "arp_ipv4",
            Self::NdpIpv6 => "ndp_ipv6",
            Self::MacSwitch => "mac_switch",
        }
    }
}

/// Address family of one recorded neighbor binding
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressFamily {
    /// IPv4 address carried by ARP
    Ipv4,
    /// IPv6 address carried by NDP
    Ipv6,
}

impl AddressFamily {
    /// Stable operator-facing address-family label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    /// Return the protocol family that can exercise this address family
    #[must_use]
    pub const fn protocol(self) -> ProtocolFamily {
        match self {
            Self::Ipv4 => ProtocolFamily::ArpIpv4,
            Self::Ipv6 => ProtocolFamily::NdpIpv6,
        }
    }

    /// Return whether an IP address has the selected family
    #[must_use]
    pub const fn matches(self, address: &IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

/// Checked six-octet endpoint or switch MAC identity
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Construct a unicast MAC identity
    ///
    /// # Errors
    /// Rejects zero, broadcast, and multicast values because none can name one
    /// controlled endpoint unambiguously
    pub fn new(bytes: [u8; 6]) -> Result<Self, ModelError> {
        if bytes == [0; 6] {
            return Err(ModelError::ZeroMac);
        }
        if bytes == [0xff; 6] {
            return Err(ModelError::BroadcastMac);
        }
        let [first, ..] = bytes;
        if first & 1 == 1 {
            return Err(ModelError::MulticastMac);
        }
        Ok(Self(bytes))
    }

    /// Return the complete MAC value
    #[must_use]
    pub const fn bytes(self) -> [u8; 6] {
        self.0
    }

    /// Borrow the MAC without copying
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// One checked IPv4 or IPv6 neighbor binding
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NeighborBinding {
    endpoint: AgentId,
    address: IpAddr,
    mac: MacAddress,
}

impl NeighborBinding {
    /// Construct an explicitly typed and non-ambiguous neighbor binding
    ///
    /// # Errors
    /// Rejects addresses that cannot identify one on-link neighbor
    pub fn new(endpoint: AgentId, address: IpAddr, mac: MacAddress) -> Result<Self, ModelError> {
        validate_neighbor_address(address)?;
        Ok(Self {
            endpoint,
            address,
            mac,
        })
    }

    /// Return the stable controlled endpoint identity
    #[must_use]
    pub const fn endpoint(self) -> AgentId {
        self.endpoint
    }

    /// Return the exact IPv4 or IPv6 address
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Return the MAC associated with the address
    #[must_use]
    pub const fn mac(self) -> MacAddress {
        self.mac
    }

    /// Return the address family carried by the binding
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self.address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }
}

// The same address rules apply to a present binding and an observed absent entry
pub fn validate_neighbor_address(address: IpAddr) -> Result<(), ModelError> {
    if address.is_unspecified() {
        return Err(ModelError::UnspecifiedAddress);
    }
    if address == IpAddr::V4(std::net::Ipv4Addr::BROADCAST) {
        return Err(ModelError::BroadcastAddress);
    }
    if address.is_multicast() {
        return Err(ModelError::MulticastAddress);
    }
    if address.is_loopback() {
        return Err(ModelError::LoopbackAddress);
    }
    Ok(())
}

/// One controlled endpoint whose binding may be armed for a bounded test
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlledEndpoint {
    binding: NeighborBinding,
    interface: InterfaceBindingRequest,
}

impl ControlledEndpoint {
    /// Associate one controlled endpoint with its original binding and interface
    #[must_use]
    pub const fn new(binding: NeighborBinding, interface: InterfaceBindingRequest) -> Self {
        Self { binding, interface }
    }

    /// Return the endpoint identity
    #[must_use]
    pub const fn id(self) -> AgentId {
        self.binding.endpoint()
    }

    /// Return the original binding
    #[must_use]
    pub const fn binding(self) -> NeighborBinding {
        self.binding
    }

    /// Return the endpoint address family
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.binding.family()
    }

    /// Return the exact namespace and interface attachment for this endpoint
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }
}
