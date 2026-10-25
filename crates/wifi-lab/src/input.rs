/// Link-layer envelope carried by a raw wireless input
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LinkType {
    /// Raw IEEE 802.11 MAC bytes without a radiotap envelope
    Ieee80211,
    /// Radiotap bytes followed by an IEEE 802.11 payload
    Radiotap,
}

/// Owned raw wireless input with an explicit link type
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureInput {
    /// Raw IEEE 802.11 MAC bytes
    Ieee80211(Vec<u8>),
    /// Raw radiotap bytes and following IEEE 802.11 bytes
    Radiotap(Vec<u8>),
}

impl CaptureInput {
    /// Store raw IEEE 802.11 bytes
    #[must_use]
    pub fn ieee80211<B>(bytes: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Self::Ieee80211(bytes.into())
    }

    /// Store raw radiotap bytes
    #[must_use]
    pub fn radiotap<B>(bytes: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Self::Radiotap(bytes.into())
    }

    /// Return the explicit link type without inspecting the bytes
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        match self {
            Self::Ieee80211(_) => LinkType::Ieee80211,
            Self::Radiotap(_) => LinkType::Radiotap,
        }
    }

    /// Return the raw bytes exactly as supplied to the lab
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // The variant carries the only authoritative byte buffer
        match self {
            Self::Ieee80211(bytes) | Self::Radiotap(bytes) => bytes,
        }
    }

    /// Consume the input and return its raw bytes
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Ieee80211(bytes) | Self::Radiotap(bytes) => bytes,
        }
    }

    /// Borrow the input in the form accepted by `wifi-discovery`
    #[must_use]
    pub fn as_discovery_input(&self) -> wifi_discovery::WirelessInput<'_> {
        match self {
            Self::Ieee80211(bytes) => wifi_discovery::WirelessInput::Ieee80211(bytes),
            Self::Radiotap(bytes) => wifi_discovery::WirelessInput::Radiotap(bytes),
        }
    }
}
