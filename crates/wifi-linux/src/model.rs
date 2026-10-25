use crate::DiscoveryError;
use serde::Serialize;

pub const MAX_PHYS: usize = 256;
pub const MAX_INTERFACES: usize = 4_096;
pub const MAX_BANDS_PER_PHY: usize = 16;
pub const MAX_MODES_PER_PHY: usize = 32;
const MAX_INTERFACE_NAME: usize = 15;
const MAX_PHY_NAME: usize = 64;

/// Maximum raw channel records accepted for one band before normalization
pub const MAX_CHANNEL_RECORDS: usize = 1_024;

/// Maximum distinct channel frequencies retained for one band after normalization
pub const MAX_UNIQUE_CHANNELS: usize = 1_024;

/// Capability state that distinguishes unknown from unsupported
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CapabilityState {
    Supported,
    Unsupported,
    Unknown,
}

impl CapabilityState {
    /// Stable operator-facing capability label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "yes",
            Self::Unsupported => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// Linux wireless interface mode
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum WirelessMode {
    Unspecified,
    Adhoc,
    Station,
    AccessPoint,
    AccessPointVlan,
    WirelessDistribution,
    Monitor,
    Mesh,
    P2pClient,
    P2pGroupOwner,
    P2pDevice,
    OutsideBss,
    NeighborAwareness,
    Other(u32),
}

impl WirelessMode {
    /// Stable operator-facing interface-mode label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Adhoc => "adhoc",
            Self::Station => "station",
            Self::AccessPoint => "ap",
            Self::AccessPointVlan => "ap-vlan",
            Self::WirelessDistribution => "wds",
            Self::Monitor => "monitor",
            Self::Mesh => "mesh",
            Self::P2pClient => "p2p-client",
            Self::P2pGroupOwner => "p2p-go",
            Self::P2pDevice => "p2p-device",
            Self::OutsideBss => "ocb",
            Self::NeighborAwareness => "nan",
            Self::Other(_) => "other",
        }
    }
}

/// Physical radio band reported by `nl80211`
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum BandKind {
    Ghz2,
    Ghz5,
    Ghz6,
    Ghz60,
    SubGhz,
    LightCommunication,
    Other(u16),
}

/// One frequency and its current regulatory restrictions and capabilities
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ChannelCapability {
    frequency_mhz: u32,
    // Restriction evidence accumulates when kernel fragments describe one frequency
    restrictions: ChannelRestrictions,
    // Monitor permission is positive capability evidence, kept separate from restrictions
    monitor_permitted: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ChannelRestrictions {
    disabled: bool,
    no_initiate_radiation: bool,
    radar_required: bool,
}

impl ChannelRestrictions {
    const NONE: Self = Self {
        disabled: false,
        no_initiate_radiation: false,
        radar_required: false,
    };

    const fn merge(&mut self, other: Self) {
        // Every observed restriction remains set after normalization
        self.disabled |= other.disabled;
        self.no_initiate_radiation |= other.no_initiate_radiation;
        self.radar_required |= other.radar_required;
    }
}

impl ChannelCapability {
    /// Build a checked frequency record
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when the frequency is zero
    pub const fn new(frequency_mhz: u32) -> Result<Self, DiscoveryError> {
        if frequency_mhz == 0 {
            return Err(DiscoveryError::InvalidValue {
                field: "frequency",
                reason: "frequency must be nonzero",
            });
        }
        Ok(Self {
            frequency_mhz,
            restrictions: ChannelRestrictions::NONE,
            monitor_permitted: false,
        })
    }

    #[must_use]
    pub const fn with_disabled(mut self) -> Self {
        self.restrictions.disabled = true;
        self
    }

    #[must_use]
    pub const fn with_no_initiate_radiation(mut self) -> Self {
        self.restrictions.no_initiate_radiation = true;
        self
    }

    #[must_use]
    pub const fn with_radar_required(mut self) -> Self {
        self.restrictions.radar_required = true;
        self
    }

    #[must_use]
    pub const fn with_monitor_permitted(mut self) -> Self {
        self.monitor_permitted = true;
        self
    }

    #[must_use]
    pub const fn frequency_mhz(self) -> u32 {
        self.frequency_mhz
    }

    #[must_use]
    pub const fn disabled(self) -> bool {
        self.restrictions.disabled
    }

    #[must_use]
    pub const fn no_initiate_radiation(self) -> bool {
        self.restrictions.no_initiate_radiation
    }

    #[must_use]
    pub const fn radar_required(self) -> bool {
        self.restrictions.radar_required
    }

    #[must_use]
    pub const fn monitor_permitted(self) -> bool {
        self.monitor_permitted
    }

    const fn merge(&mut self, other: Self) {
        // A restriction observed in any equivalent record remains visible
        self.restrictions.merge(other.restrictions);
        // Positive monitor evidence also survives record normalization
        self.monitor_permitted |= other.monitor_permitted;
    }
}

/// Checked channel set for one radio band
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Band {
    kind: BandKind,
    channels: Vec<ChannelCapability>,
}

impl Band {
    /// Build a bounded, sorted channel set
    ///
    /// Raw records are limited by [`MAX_CHANNEL_RECORDS`] before equivalent
    /// frequencies are merged. The normalized set is limited by
    /// [`MAX_UNIQUE_CHANNELS`] afterward
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when the channel budget is exceeded
    pub fn new(kind: BandKind, channels: Vec<ChannelCapability>) -> Result<Self, DiscoveryError> {
        Ok(Self {
            kind,
            channels: normalize_channels(channels, true)?,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> BandKind {
        self.kind
    }

    #[must_use]
    pub fn channels(&self) -> &[ChannelCapability] {
        &self.channels
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<(), DiscoveryError> {
        // Each fragment was bounded before parsing, so only the normalized result is limited here
        let combined = self
            .channels
            .iter()
            .copied()
            .chain(other.channels)
            .collect();
        let normalized = normalize_channels(combined, false)?;
        self.channels = normalized;
        Ok(())
    }
}

fn normalize_channels(
    mut channels: Vec<ChannelCapability>,
    enforce_record_limit: bool,
) -> Result<Vec<ChannelCapability>, DiscoveryError> {
    if enforce_record_limit {
        validate_count(
            "channel records per band",
            channels.len(),
            MAX_CHANNEL_RECORDS,
        )?;
    }
    channels.sort_by_key(|channel| channel.frequency_mhz);
    let mut normalized: Vec<ChannelCapability> = Vec::with_capacity(channels.len());
    for channel in channels {
        if let Some(existing) = normalized.last_mut()
            && existing.frequency_mhz == channel.frequency_mhz
        {
            existing.merge(channel);
            continue;
        }
        normalized.push(channel);
    }
    validate_count(
        "unique channel frequencies per band",
        normalized.len(),
        MAX_UNIQUE_CHANNELS,
    )?;
    Ok(normalized)
}

/// Checked capabilities for one physical radio
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhyCapabilities {
    id: u32,
    name: Option<String>,
    modes: Vec<WirelessMode>,
    bands: Vec<Band>,
    monitor_mode: CapabilityState,
    injection: CapabilityState,
}

impl PhyCapabilities {
    /// Build one bounded physical-radio record
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] for invalid names or oversized collections
    ///
    /// Monitor support remains [`CapabilityState::Unknown`] when the normalized
    /// modes do not include monitor because this constructor has no attribute
    /// presence evidence for an explicit unsupported result
    pub fn new(
        id: u32,
        name: Option<String>,
        modes: Vec<WirelessMode>,
        bands: Vec<Band>,
        injection: CapabilityState,
    ) -> Result<Self, DiscoveryError> {
        let monitor_mode = if modes.contains(&WirelessMode::Monitor) {
            CapabilityState::Supported
        } else {
            // A caller that has no source-level iftype evidence cannot claim
            // that monitor mode is unsupported
            CapabilityState::Unknown
        };
        Self::new_with_monitor_mode(id, name, modes, bands, monitor_mode, injection)
    }

    /// Build a record when nl80211 supplied explicit monitor-mode evidence
    pub(crate) fn new_with_monitor_mode(
        id: u32,
        name: Option<String>,
        mut modes: Vec<WirelessMode>,
        mut bands: Vec<Band>,
        monitor_mode: CapabilityState,
        injection: CapabilityState,
    ) -> Result<Self, DiscoveryError> {
        if name.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_PHY_NAME || value.contains('\0')
        }) {
            return Err(DiscoveryError::InvalidValue {
                field: "physical radio name",
                reason: "name must be 1..=64 bytes without NUL",
            });
        }
        validate_count("modes per physical radio", modes.len(), MAX_MODES_PER_PHY)?;
        validate_count("bands per physical radio", bands.len(), MAX_BANDS_PER_PHY)?;
        let monitor_present = modes.contains(&WirelessMode::Monitor);
        let monitor_consistent = match monitor_mode {
            CapabilityState::Supported => monitor_present,
            CapabilityState::Unsupported | CapabilityState::Unknown => !monitor_present,
        };
        if !monitor_consistent {
            return Err(DiscoveryError::InvalidValue {
                field: "monitor capability",
                reason: "monitor state must match normalized iftype evidence",
            });
        }
        modes.sort_unstable();
        modes.dedup();
        bands.sort_by_key(Band::kind);
        let mut merged_bands: Vec<Band> = Vec::with_capacity(bands.len());
        for band in bands {
            if let Some(existing) = merged_bands.last_mut()
                && existing.kind == band.kind
            {
                existing.merge(band)?;
            } else {
                merged_bands.push(band);
            }
        }
        Ok(Self {
            id,
            name,
            modes,
            bands: merged_bands,
            monitor_mode,
            injection,
        })
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn modes(&self) -> &[WirelessMode] {
        &self.modes
    }

    #[must_use]
    pub fn bands(&self) -> &[Band] {
        &self.bands
    }

    #[must_use]
    pub const fn monitor_mode(&self) -> CapabilityState {
        self.monitor_mode
    }

    /// Injection stays unknown until a bounded hardware qualification succeeds
    #[must_use]
    pub const fn injection(&self) -> CapabilityState {
        self.injection
    }
}

/// Checked identity for one kernel wireless interface
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InterfaceInfo {
    index: u32,
    name: String,
    phy: u32,
    mode: WirelessMode,
}

impl InterfaceInfo {
    /// Build one checked kernel interface identity
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] for index zero or an invalid interface name
    pub fn new(
        index: u32,
        name: String,
        phy: u32,
        mode: WirelessMode,
    ) -> Result<Self, DiscoveryError> {
        if index == 0 {
            return Err(DiscoveryError::InvalidValue {
                field: "interface index",
                reason: "index must be nonzero",
            });
        }
        if name.is_empty() || name.len() > MAX_INTERFACE_NAME || name.contains('\0') {
            return Err(DiscoveryError::InvalidValue {
                field: "interface name",
                reason: "name must be 1..=15 bytes without NUL",
            });
        }
        Ok(Self {
            index,
            name,
            phy,
            mode,
        })
    }

    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn phy(&self) -> u32 {
        self.phy
    }

    #[must_use]
    pub const fn mode(&self) -> WirelessMode {
        self.mode
    }
}

/// Deterministic read-only snapshot of Linux wireless state
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct WirelessInventory {
    phys: Vec<PhyCapabilities>,
    interfaces: Vec<InterfaceInfo>,
}

impl WirelessInventory {
    /// Build a sorted inventory with unique kernel identities
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] for oversized collections or duplicate IDs
    pub fn new(
        mut phys: Vec<PhyCapabilities>,
        mut interfaces: Vec<InterfaceInfo>,
    ) -> Result<Self, DiscoveryError> {
        validate_count("physical radios", phys.len(), MAX_PHYS)?;
        validate_count("interfaces", interfaces.len(), MAX_INTERFACES)?;
        phys.sort_by_key(PhyCapabilities::id);
        interfaces.sort_by_key(InterfaceInfo::index);
        reject_duplicate_ids(&phys, PhyCapabilities::id, "physical radio")?;
        reject_duplicate_ids(&interfaces, InterfaceInfo::index, "interface")?;
        for interface in &interfaces {
            if phys
                .binary_search_by_key(&interface.phy(), PhyCapabilities::id)
                .is_err()
            {
                return Err(DiscoveryError::UnknownPhy {
                    interface: interface.index(),
                    phy: interface.phy(),
                });
            }
        }
        Ok(Self { phys, interfaces })
    }

    #[must_use]
    pub fn phys(&self) -> &[PhyCapabilities] {
        &self.phys
    }

    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }
}

fn reject_duplicate_ids<T>(
    values: &[T],
    id: impl Fn(&T) -> u32,
    field: &'static str,
) -> Result<(), DiscoveryError> {
    for pair in values.windows(2) {
        let Some(first) = pair.first() else {
            continue;
        };
        let Some(second) = pair.get(1) else {
            continue;
        };
        if id(first) == id(second) {
            return Err(DiscoveryError::DuplicateIdentity {
                field,
                value: id(first),
            });
        }
    }
    Ok(())
}

pub const fn validate_count(
    field: &'static str,
    count: usize,
    maximum: usize,
) -> Result<(), DiscoveryError> {
    if count > maximum {
        return Err(DiscoveryError::ResourceLimit {
            field,
            count,
            maximum,
        });
    }
    Ok(())
}
