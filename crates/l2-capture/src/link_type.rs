//! Checked data-link identities carried with captured frame evidence

use core::fmt;

/// Data-link types understood by the capture boundary
///
/// The numeric values are the stable PCAP and PCAPNG link-layer assignments
/// Unknown values remain bounded to the 16-bit field used by both formats so
/// an unsupported PCAPNG interface can be preserved without guessing its layout
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LinkType {
    /// Ethernet frames with a 14-byte Ethernet header
    Ethernet,
    /// IEEE 802.11 frames without a radiotap prefix
    Ieee80211,
    /// Linux cooked capture with a 16-byte SLL header
    LinuxSll,
    /// IEEE 802.11 frames with a radiotap prefix
    Ieee80211Radiotap,
    /// Linux cooked capture with a 20-byte SLL2 header
    LinuxSll2,
    /// A link-layer assignment not decoded by this workspace
    Unknown(u16),
}

impl LinkType {
    /// PCAP and PCAPNG assignment for Ethernet
    pub const ETHERNET: Self = Self::Ethernet;

    /// PCAP and PCAPNG assignment for raw IEEE 802.11
    pub const IEEE802_11: Self = Self::Ieee80211;

    /// PCAP and PCAPNG assignment for radiotap IEEE 802.11
    pub const IEEE802_11_RADIOTAP: Self = Self::Ieee80211Radiotap;

    /// Convert a bounded PCAP or PCAPNG link-layer field into a checked identity
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            1 => Self::Ethernet,
            105 => Self::Ieee80211,
            113 => Self::LinuxSll,
            127 => Self::Ieee80211Radiotap,
            276 => Self::LinuxSll2,
            other => Self::Unknown(other),
        }
    }

    /// Return the original PCAP or PCAPNG link-layer field
    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Ethernet => 1,
            Self::Ieee80211 => 105,
            Self::LinuxSll => 113,
            Self::Ieee80211Radiotap => 127,
            Self::LinuxSll2 => 276,
            Self::Unknown(raw) => raw,
        }
    }

    /// Return whether this is one of the named link types in the model
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::Ethernet
                | Self::Ieee80211
                | Self::Ieee80211Radiotap
                | Self::LinuxSll
                | Self::LinuxSll2
        )
    }

    /// Return whether the retained bytes have the Ethernet layout
    #[must_use]
    pub const fn is_ethernet(self) -> bool {
        matches!(self, Self::Ethernet)
    }

    /// Return whether the retained bytes contain raw IEEE 802.11 data
    #[must_use]
    pub const fn is_wireless(self) -> bool {
        matches!(self, Self::Ieee80211 | Self::Ieee80211Radiotap)
    }

    /// Return a stable human-readable name for diagnostics
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Ieee80211 => "IEEE 802.11",
            Self::LinuxSll => "Linux cooked SLL",
            Self::Ieee80211Radiotap => "IEEE 802.11 Radiotap",
            Self::LinuxSll2 => "Linux cooked SLL2",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl From<u16> for LinkType {
    fn from(raw: u16) -> Self {
        Self::from_raw(raw)
    }
}

impl From<LinkType> for u16 {
    fn from(link_type: LinkType) -> Self {
        link_type.raw()
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(raw) => write!(formatter, "unknown ({raw})"),
            _ => formatter.write_str(self.name()),
        }
    }
}
