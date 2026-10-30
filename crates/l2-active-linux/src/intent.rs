#[cfg(test)]
#[path = "../tests/intent/dhcp.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/intent/ndp.rs"]
mod ndp_tests;

#[cfg(test)]
#[path = "../tests/intent/dot1x.rs"]
mod dot1x_tests;

use crate::{InterfaceInfo, InterfaceSelector, select_arp_source};
use l2_active::{ArpProbe, Limits, NdpProbe, dhcp::DhcpProbe, dot1x::Dot1xProbe};
use l2_onpath::MacAddress;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

/// The fixed groups admitted for each receive-only operation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenKind {
    Discovery,
    Stp,
}

/// Only these typed operations can be reconstructed by the worker
#[derive(Debug)]
pub enum IntentKind {
    Arp {
        source: Ipv4Addr,
        target: Ipv4Addr,
    },
    Dhcp {
        transaction: NonZeroU32,
    },
    Ndp {
        source: Ipv6Addr,
        prefix_len: u8,
        target: Ipv6Addr,
    },
    Listen(ListenKind),
    Dot1x,
}

/// One typed operation and the exact bytes admitted for its single send
#[derive(Debug)]
pub struct Intent {
    kind: IntentKind,
    source_mac: MacAddress,
    limits: Limits,
    frame: Vec<u8>,
}

impl Intent {
    pub fn arp(probe: &ArpProbe) -> io::Result<Self> {
        Ok(Self {
            kind: IntentKind::Arp {
                source: probe.source_ip(),
                target: probe.target(),
            },
            source_mac: probe.source_mac(),
            limits: probe.limits(),
            frame: crate::buffer::copy(probe.frame())?,
        })
    }

    pub fn dhcp(probe: &DhcpProbe) -> io::Result<Self> {
        // The allowlist is a reporting choice and does not alter transmitted bytes
        Ok(Self {
            kind: IntentKind::Dhcp {
                transaction: probe.transaction(),
            },
            source_mac: probe.source_mac(),
            limits: probe.limits(),
            frame: crate::buffer::copy(probe.frame())?,
        })
    }

    pub fn ndp(probe: &NdpProbe) -> io::Result<Self> {
        Ok(Self {
            kind: IntentKind::Ndp {
                source: probe.source_ip(),
                prefix_len: probe.prefix_len(),
                target: probe.target(),
            },
            source_mac: probe.source_mac(),
            limits: probe.limits(),
            frame: crate::buffer::copy(probe.frame())?,
        })
    }

    pub fn dot1x(probe: &Dot1xProbe) -> io::Result<Self> {
        Ok(Self {
            kind: IntentKind::Dot1x,
            source_mac: probe.source_mac(),
            limits: probe.limits(),
            frame: crate::buffer::copy(probe.frame())?,
        })
    }

    pub const fn listen(source_mac: MacAddress, limits: Limits, kind: ListenKind) -> Self {
        Self {
            kind: IntentKind::Listen(kind),
            source_mac,
            limits,
            frame: Vec::new(),
        }
    }

    pub const fn listen_kind(&self) -> Option<ListenKind> {
        match self.kind {
            IntentKind::Listen(kind) => Some(kind),
            _ => None,
        }
    }

    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
    pub const fn kind(&self) -> &IntentKind {
        &self.kind
    }
    pub const fn tag(&self) -> u8 {
        match self.kind {
            IntentKind::Arp { .. } => 1,
            IntentKind::Dhcp { .. } => 2,
            IntentKind::Ndp { .. } => 3,
            IntentKind::Listen(ListenKind::Discovery) => 4,
            IntentKind::Listen(ListenKind::Stp) => 5,
            IntentKind::Dot1x => 6,
        }
    }
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    pub const fn source_mac(&self) -> MacAddress {
        self.source_mac
    }

    pub fn validate(&self, info: &InterfaceInfo, selector: &InterfaceSelector) -> io::Result<()> {
        if self.listen_kind().is_some() {
            validate_interface(info, self.source_mac)?;
        } else {
            validate_ethernet(info, self.source_mac, &self.frame)?;
        }
        // Listening and EAPOL group replies both require multicast reception
        let needs_multicast =
            self.listen_kind().is_some() || matches!(self.kind, IntentKind::Dot1x);
        if needs_multicast && info.flags() & 0x1000 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "operation requires a multicast-capable interface",
            ));
        }
        if let IntentKind::Arp { source, target } = self.kind {
            select_arp_source(info, Some(source), target)?;
        }
        if let IntentKind::Ndp {
            source,
            prefix_len,
            target,
        } = self.kind
        {
            // A selected interface zones link-local addresses without a route lookup
            require_link_local(source, target)?;
            let current = crate::ndp::discover(selector)?;
            if current.interface().identity() != info.identity() {
                return Err(io::Error::other("interface changed during IPv6 admission"));
            }
            let prepared = crate::ndp::prepare(&current, Some(source), target, None, self.limits)?;
            if prepared.source_mac() != self.source_mac
                || prepared.prefix_len() != prefix_len
                || prepared.frame() != self.frame
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NDP request does not match the selected IPv6 assignment",
                ));
            }
        }
        Ok(())
    }
}

fn require_link_local(source: Ipv6Addr, target: Ipv6Addr) -> io::Result<()> {
    if source.is_unicast_link_local() && target.is_unicast_link_local() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "global NDP requires verified on-link route support",
        ))
    }
}

pub fn validate_ethernet(
    info: &InterfaceInfo,
    source_mac: MacAddress,
    frame: &[u8],
) -> io::Result<()> {
    validate_interface(info, source_mac)?;
    let payload = frame
        .len()
        .checked_sub(14)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "short Ethernet frame"))?;
    if u64::try_from(payload).map_err(io::Error::other)? > u64::from(info.mtu()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "selected interface MTU is too small for the request",
        ));
    }
    Ok(())
}

fn validate_interface(info: &InterfaceInfo, source_mac: MacAddress) -> io::Result<()> {
    if !info.is_ethernet() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "probe requires an Ethernet interface",
        ));
    }
    if !info.is_up() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "selected interface is down",
        ));
    }
    if info.mac() != source_mac.bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source MAC does not match the selected interface",
        ));
    }
    Ok(())
}
