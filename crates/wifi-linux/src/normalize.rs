use crate::{
    Band, BandKind, ChannelCapability, DiscoveryError, WirelessMode, model::validate_count,
};
use wl_nl80211::{
    Nl80211Band, Nl80211BandInfo, Nl80211BandType, Nl80211FrequencyInfo, Nl80211IfMode,
    Nl80211InterfaceType,
};

pub fn supported_mode(value: Nl80211IfMode) -> WirelessMode {
    match value {
        Nl80211IfMode::Adhoc => WirelessMode::Adhoc,
        Nl80211IfMode::Station => WirelessMode::Station,
        Nl80211IfMode::Ap => WirelessMode::AccessPoint,
        Nl80211IfMode::ApVlan => WirelessMode::AccessPointVlan,
        Nl80211IfMode::Wds => WirelessMode::WirelessDistribution,
        Nl80211IfMode::Monitor => WirelessMode::Monitor,
        Nl80211IfMode::MeshPoint => WirelessMode::Mesh,
        Nl80211IfMode::P2pClient => WirelessMode::P2pClient,
        Nl80211IfMode::P2pGo => WirelessMode::P2pGroupOwner,
        Nl80211IfMode::P2pDevice => WirelessMode::P2pDevice,
        Nl80211IfMode::Ocb => WirelessMode::OutsideBss,
        Nl80211IfMode::Nan => WirelessMode::NeighborAwareness,
        Nl80211IfMode::Other(value) => WirelessMode::Other(u32::from(value)),
    }
}

pub const fn interface_mode(value: Nl80211InterfaceType) -> WirelessMode {
    match value {
        Nl80211InterfaceType::Unspecified => WirelessMode::Unspecified,
        Nl80211InterfaceType::Adhoc => WirelessMode::Adhoc,
        Nl80211InterfaceType::Station => WirelessMode::Station,
        Nl80211InterfaceType::Ap => WirelessMode::AccessPoint,
        Nl80211InterfaceType::ApVlan => WirelessMode::AccessPointVlan,
        Nl80211InterfaceType::Wds => WirelessMode::WirelessDistribution,
        Nl80211InterfaceType::Monitor => WirelessMode::Monitor,
        Nl80211InterfaceType::MeshPoint => WirelessMode::Mesh,
        Nl80211InterfaceType::P2pClient => WirelessMode::P2pClient,
        Nl80211InterfaceType::P2pGo => WirelessMode::P2pGroupOwner,
        Nl80211InterfaceType::P2pDevice => WirelessMode::P2pDevice,
        Nl80211InterfaceType::Ocb => WirelessMode::OutsideBss,
        Nl80211InterfaceType::Nan => WirelessMode::NeighborAwareness,
        Nl80211InterfaceType::Other(value) => WirelessMode::Other(value),
    }
}

pub fn band(value: Nl80211Band) -> Result<Band, DiscoveryError> {
    let kind = match value.kind {
        Nl80211BandType::Band2GHz => BandKind::Ghz2,
        Nl80211BandType::Band5GHz => BandKind::Ghz5,
        Nl80211BandType::Band6GHz => BandKind::Ghz6,
        Nl80211BandType::Band60GHz => BandKind::Ghz60,
        Nl80211BandType::BandS1GHz => BandKind::SubGhz,
        Nl80211BandType::BandLc => BandKind::LightCommunication,
        Nl80211BandType::Other(value) => BandKind::Other(value),
    };
    let mut channels = Vec::new();
    for info in value.info {
        let Nl80211BandInfo::Freqs(frequencies) = info else {
            continue;
        };
        for frequency in frequencies {
            let Some(frequency_mhz) = frequency_mhz(&frequency.info)? else {
                continue;
            };
            validate_count(
                "channel records per band",
                channels.len() + 1,
                crate::MAX_CHANNEL_RECORDS,
            )?;
            let mut channel = ChannelCapability::new(frequency_mhz)?;
            if frequency.info.contains(&Nl80211FrequencyInfo::Disabled) {
                channel = channel.with_disabled();
            }
            if frequency.info.iter().any(|item| {
                matches!(
                    item,
                    Nl80211FrequencyInfo::NoIr | Nl80211FrequencyInfo::NoIbss
                )
            }) {
                channel = channel.with_no_initiate_radiation();
            }
            if frequency.info.contains(&Nl80211FrequencyInfo::Radar) {
                channel = channel.with_radar_required();
            }
            if frequency.info.contains(&Nl80211FrequencyInfo::CanMonitor) {
                channel = channel.with_monitor_permitted();
            }
            channels.push(channel);
        }
    }
    Band::new(kind, channels)
}

fn frequency_mhz(info: &[Nl80211FrequencyInfo]) -> Result<Option<u32>, DiscoveryError> {
    let mut output = None;
    for value in info.iter().filter_map(|item| match item {
        Nl80211FrequencyInfo::Freq(value) => Some(*value),
        _ => None,
    }) {
        if output.replace(value).is_some() {
            return Err(DiscoveryError::InvalidValue {
                field: "channel frequency",
                reason: "attribute appears more than once",
            });
        }
    }
    Ok(output)
}
