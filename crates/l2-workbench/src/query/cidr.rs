use crate::query::QueryError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One literal IP network and its inclusive prefix length
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parse an address with an optional prefix length; a bare address is exact
    ///
    /// # Errors
    /// Returns an error when the address, prefix, or family-specific bound is invalid
    pub fn parse(text: &str) -> Result<Self, QueryError> {
        let mut parts = text.split('/');
        let address = parts.next().unwrap_or_default();
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| invalid("IP filter address is invalid"))?;
        let prefix = parts
            .next()
            .map(|prefix| {
                prefix
                    .parse::<u8>()
                    .map_err(|_| invalid("IP prefix must be an unsigned decimal number"))
            })
            .transpose()?
            .unwrap_or_else(|| if network.is_ipv4() { 32 } else { 128 });
        if parts.next().is_some() {
            return Err(invalid("IP filter must contain exactly one slash"));
        }
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(invalid("IP prefix exceeds the address family width"));
        }
        Ok(Self { network, prefix })
    }

    /// Return whether an address belongs to this network
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                masked_v4(network, self.prefix) == masked_v4(address, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                masked(u128::from(network), self.prefix, 128)
                    == masked(u128::from(address), self.prefix, 128)
            }
            _ => false,
        }
    }

    /// Return the configured prefix length
    #[must_use]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    /// Return the canonical network address after clearing host bits
    #[must_use]
    pub fn network(self) -> IpAddr {
        match self.network {
            IpAddr::V4(address) => IpAddr::V4(masked_v4(address, self.prefix)),
            IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(masked(
                u128::from(address),
                self.prefix,
                128,
            ))),
        }
    }
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(masked_v4_bits(u32::from(address), prefix))
}

const fn masked_v4_bits(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    let prefix = u32::from_le_bytes([prefix, 0, 0, 0]);
    let shift = 32 - prefix;
    (value >> shift) << shift
}

const fn masked(address: u128, prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    let shift = width - prefix;
    (address >> shift) << shift
}

fn invalid(message: &str) -> QueryError {
    QueryError::InvalidFilter(message.to_owned())
}
