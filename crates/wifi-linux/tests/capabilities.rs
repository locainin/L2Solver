use proptest::prelude::*;
use wifi_linux::{
    Band, BandKind, CapabilityState, ChannelCapability, DiscoveryError, InterfaceInfo,
    MAX_CHANNEL_RECORDS, MAX_UNIQUE_CHANNELS, PhyCapabilities, WirelessInventory, WirelessMode,
};

#[test]
fn operator_labels_are_stable() {
    assert_eq!(CapabilityState::Supported.as_str(), "yes");
    assert_eq!(CapabilityState::Unsupported.as_str(), "no");
    assert_eq!(CapabilityState::Unknown.as_str(), "unknown");
    assert_eq!(WirelessMode::Station.as_str(), "station");
    assert_eq!(WirelessMode::AccessPoint.as_str(), "ap");
    assert_eq!(WirelessMode::Other(99).as_str(), "other");
}

#[test]
fn normalized_inventory_sorts_and_deduplicates() -> Result<(), Box<dyn std::error::Error>> {
    let first = ChannelCapability::new(5_180)?;
    let duplicate = ChannelCapability::new(5_180)?;
    let second = ChannelCapability::new(2_412)?;
    let phy = PhyCapabilities::new(
        2,
        Some("phy2".into()),
        vec![WirelessMode::Station, WirelessMode::Monitor],
        vec![
            Band::new(wifi_linux::BandKind::Ghz5, vec![first, duplicate])?,
            Band::new(wifi_linux::BandKind::Ghz2, vec![second])?,
        ],
        CapabilityState::Unknown,
    )?;
    let interface = InterfaceInfo::new(9, "wlp2s0".into(), 2, WirelessMode::Station)?;

    let inventory = WirelessInventory::new(vec![phy], vec![interface])?;
    let normalized_phy = inventory.phys().first().ok_or("missing physical radio")?;
    let first_band = normalized_phy.bands().first().ok_or("missing first band")?;
    let second_band = normalized_phy.bands().get(1).ok_or("missing second band")?;
    let normalized_interface = inventory.interfaces().first().ok_or("missing interface")?;

    assert_eq!(inventory.phys().len(), 1);
    assert_eq!(first_band.kind(), wifi_linux::BandKind::Ghz2);
    assert_eq!(second_band.channels().len(), 1);
    assert_eq!(normalized_interface.name(), "wlp2s0");
    assert_eq!(normalized_interface.index(), 9);
    assert_eq!(normalized_interface.phy(), 2);
    assert_eq!(normalized_interface.mode(), WirelessMode::Station);
    assert_eq!(normalized_phy.id(), 2);
    assert_eq!(normalized_phy.name(), Some("phy2"));
    assert_eq!(
        normalized_phy.modes(),
        &[WirelessMode::Station, WirelessMode::Monitor]
    );
    assert_eq!(normalized_phy.monitor_mode(), CapabilityState::Supported);
    assert_eq!(normalized_phy.injection(), CapabilityState::Unknown);
    Ok(())
}

#[test]
fn channel_flags_are_independent() -> Result<(), Box<dyn std::error::Error>> {
    let plain = ChannelCapability::new(5_240)?;
    assert_flags(plain, [false, false, false, false]);

    let disabled = ChannelCapability::new(5_245)?.with_disabled();
    assert_flags(disabled, [true, false, false, false]);

    let no_ir = ChannelCapability::new(5_250)?.with_no_initiate_radiation();
    assert_flags(no_ir, [false, true, false, false]);

    let radar = ChannelCapability::new(5_255)?.with_radar_required();
    assert_flags(radar, [false, false, true, false]);

    let monitor = ChannelCapability::new(5_260)?.with_monitor_permitted();
    assert_flags(monitor, [false, false, false, true]);
    Ok(())
}

#[test]
fn channel_retains_combined_flags() -> Result<(), Box<dyn std::error::Error>> {
    let channel = ChannelCapability::new(5_265)?
        .with_disabled()
        .with_no_initiate_radiation()
        .with_radar_required()
        .with_monitor_permitted();

    assert_eq!(channel.frequency_mhz(), 5_265);
    assert_flags(channel, [true, true, true, true]);
    Ok(())
}

#[test]
fn duplicate_frequencies_merge_all_orders() -> Result<(), Box<dyn std::error::Error>> {
    let records = [
        ChannelCapability::new(5_265)?.with_disabled(),
        ChannelCapability::new(5_265)?.with_no_initiate_radiation(),
        ChannelCapability::new(5_265)?.with_radar_required(),
        ChannelCapability::new(5_265)?.with_monitor_permitted(),
    ];
    let expected = Band::new(BandKind::Ghz5, records.to_vec())?;

    for permutation in permutations(&records) {
        assert_eq!(Band::new(BandKind::Ghz5, permutation)?, expected);
    }

    let channel = expected
        .channels()
        .first()
        .ok_or("missing merged channel")?;
    assert_flags(*channel, [true, true, true, true]);
    Ok(())
}

#[test]
fn adding_restrictions_is_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let plain = ChannelCapability::new(5_270)?;
    let added = ChannelCapability::new(5_270)?
        .with_disabled()
        .with_no_initiate_radiation()
        .with_radar_required();
    let before = Band::new(BandKind::Ghz5, vec![plain])?;
    let after = Band::new(BandKind::Ghz5, vec![plain, added])?;
    let before = before.channels().first().ok_or("missing base channel")?;
    let after = after.channels().first().ok_or("missing merged channel")?;

    assert!(!before.disabled());
    assert!(!before.no_initiate_radiation());
    assert!(!before.radar_required());
    assert!(after.disabled());
    assert!(after.no_initiate_radiation());
    assert!(after.radar_required());
    assert!(!after.monitor_permitted());
    Ok(())
}

#[test]
fn split_bands_deduplicate_before_limit() -> Result<(), Box<dyn std::error::Error>> {
    let channel = ChannelCapability::new(5_280)?.with_disabled();
    let first = Band::new(BandKind::Ghz5, vec![channel; MAX_CHANNEL_RECORDS])?;
    let second = Band::new(BandKind::Ghz5, vec![channel; MAX_CHANNEL_RECORDS])?;
    let phy = PhyCapabilities::new(
        1,
        None,
        vec![],
        vec![first, second],
        CapabilityState::Unknown,
    )?;

    let band = phy.bands().first().ok_or("missing merged band")?;
    assert_eq!(band.channels().len(), 1);
    assert_eq!(
        band.channels().first().map(|channel| channel.disabled()),
        Some(true)
    );
    Ok(())
}

#[test]
fn channel_limits_separate_raw_unique() -> Result<(), Box<dyn std::error::Error>> {
    let duplicate = ChannelCapability::new(5_285)?;
    assert_eq!(
        Band::new(BandKind::Ghz5, vec![duplicate; MAX_CHANNEL_RECORDS + 1]),
        Err(DiscoveryError::ResourceLimit {
            field: "channel records per band",
            count: MAX_CHANNEL_RECORDS + 1,
            maximum: MAX_CHANNEL_RECORDS,
        })
    );

    let channels = (0..MAX_UNIQUE_CHANNELS)
        .map(|offset| ChannelCapability::new(5_000 + u32::try_from(offset).unwrap_or(0)))
        .collect::<Result<Vec<_>, _>>()?;
    let first = Band::new(BandKind::Ghz5, channels)?;
    let second = Band::new(BandKind::Ghz5, vec![ChannelCapability::new(7_000)?])?;
    assert_eq!(
        PhyCapabilities::new(
            1,
            None,
            vec![],
            vec![first, second],
            CapabilityState::Unknown,
        ),
        Err(DiscoveryError::ResourceLimit {
            field: "unique channel frequencies per band",
            count: MAX_UNIQUE_CHANNELS + 1,
            maximum: MAX_UNIQUE_CHANNELS,
        })
    );
    Ok(())
}

#[track_caller]
fn assert_flags(channel: ChannelCapability, expected: [bool; 4]) {
    let actual = [
        channel.disabled(),
        channel.no_initiate_radiation(),
        channel.radar_required(),
        channel.monitor_permitted(),
    ];
    assert_eq!(actual, expected);
}

fn permutations(values: &[ChannelCapability]) -> Vec<Vec<ChannelCapability>> {
    let Some((&first, rest)) = values.split_first() else {
        return vec![Vec::new()];
    };
    let mut output = Vec::new();
    for permutation in permutations(rest) {
        for position in 0..=permutation.len() {
            let mut candidate = permutation.clone();
            candidate.insert(position, first);
            output.push(candidate);
        }
    }
    output
}

proptest! {
    #[test]
    fn equivalent_channel_records_order_independent(bits in prop::collection::vec(any::<u8>(), 1..=12)) {
        let records = bits
            .iter()
            .map(|bits| channel_for_bits(*bits))
            .collect::<Result<Vec<_>, _>>();
        let Ok(records) = records else {
            prop_assert!(false, "the fixed nonzero test frequency must be valid");
            return Ok(());
        };
        let mut reversed = records.clone();
        reversed.reverse();
        let canonical = Band::new(BandKind::Ghz5, records);
        let reversed = Band::new(BandKind::Ghz5, reversed);
        prop_assert_eq!(canonical, reversed);
    }

    #[test]
    fn restriction_observations_are_monotonic(
        base_bits in any::<u8>(),
        added_bits in any::<u8>(),
    ) {
        let base = channel_for_bits(base_bits);
        let added = channel_for_bits(added_bits);
        let (Ok(base), Ok(added)) = (base, added) else {
            prop_assert!(false, "the fixed nonzero test frequency must be valid");
            return Ok(());
        };
        let before = Band::new(BandKind::Ghz5, vec![base]);
        let after = Band::new(BandKind::Ghz5, vec![base, added]);
        let (Ok(before), Ok(after)) = (before, after) else {
            prop_assert!(false, "generated records stay below the channel limit");
            return Ok(());
        };
        let Some(before) = before.channels().first() else {
            prop_assert!(false, "one input record must produce one channel");
            return Ok(());
        };
        let Some(after) = after.channels().first() else {
            prop_assert!(false, "two equivalent input records must produce one channel");
            return Ok(());
        };
        prop_assert!(!before.disabled() || after.disabled());
        prop_assert!(!before.no_initiate_radiation() || after.no_initiate_radiation());
        prop_assert!(!before.radar_required() || after.radar_required());
        prop_assert!(!before.monitor_permitted() || after.monitor_permitted());
    }
}

fn channel_for_bits(bits: u8) -> Result<ChannelCapability, DiscoveryError> {
    let mut channel = ChannelCapability::new(5_290)?;
    if bits & 0b0001 != 0 {
        channel = channel.with_disabled();
    }
    if bits & 0b0010 != 0 {
        channel = channel.with_no_initiate_radiation();
    }
    if bits & 0b0100 != 0 {
        channel = channel.with_radar_required();
    }
    if bits & 0b1000 != 0 {
        channel = channel.with_monitor_permitted();
    }
    Ok(channel)
}

#[test]
fn invalid_kernel_identity_is_rejected() {
    assert!(InterfaceInfo::new(0, "wlan0".into(), 1, WirelessMode::Station).is_err());
    assert!(InterfaceInfo::new(1, "bad\0name".into(), 1, WirelessMode::Station).is_err());
    assert!(
        PhyCapabilities::new(
            1,
            Some(String::new()),
            vec![],
            vec![],
            CapabilityState::Unknown
        )
        .is_err()
    );
}

#[test]
fn duplicate_kernel_ids_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let phy = PhyCapabilities::new(1, None, vec![], vec![], CapabilityState::Unknown)?;
    let interface = InterfaceInfo::new(1, "mon0".into(), 1, WirelessMode::Monitor)?;

    assert!(WirelessInventory::new(vec![phy.clone(), phy], vec![]).is_err());
    assert!(WirelessInventory::new(vec![], vec![interface.clone(), interface]).is_err());
    Ok(())
}

#[test]
fn injection_never_inferred_monitor_support() -> Result<(), Box<dyn std::error::Error>> {
    let phy = PhyCapabilities::new(
        1,
        None,
        vec![WirelessMode::Monitor],
        vec![],
        CapabilityState::Unknown,
    )?;

    assert_eq!(phy.monitor_mode(), CapabilityState::Supported);
    assert_eq!(phy.injection(), CapabilityState::Unknown);
    Ok(())
}

#[test]
fn monitor_capability_needs_iftype() -> Result<(), Box<dyn std::error::Error>> {
    let phy = PhyCapabilities::new(
        1,
        None,
        vec![WirelessMode::Station],
        vec![],
        CapabilityState::Unknown,
    )?;

    assert_eq!(phy.monitor_mode(), CapabilityState::Unknown);
    Ok(())
}

#[test]
fn inventory_rejects_interfaces_unknown_phys() -> Result<(), Box<dyn std::error::Error>> {
    let phy = PhyCapabilities::new(2, None, vec![], vec![], CapabilityState::Unknown)?;
    let interface = InterfaceInfo::new(7, "wlan0".into(), 9, WirelessMode::Station)?;

    assert_eq!(
        WirelessInventory::new(vec![phy], vec![interface]),
        Err(DiscoveryError::UnknownPhy {
            interface: 7,
            phy: 9,
        })
    );
    Ok(())
}

#[test]
fn capability_errors() {
    assert_eq!(
        DiscoveryError::Netlink("permission denied".into()).to_string(),
        "nl80211 discovery failed: permission denied"
    );
    assert_eq!(
        DiscoveryError::MissingAttribute("interface index").to_string(),
        "nl80211 response lacks interface index"
    );
    assert_eq!(
        DiscoveryError::InvalidValue {
            field: "frequency",
            reason: "frequency must be nonzero",
        }
        .to_string(),
        "invalid nl80211 frequency: frequency must be nonzero"
    );
    assert_eq!(
        DiscoveryError::ResourceLimit {
            field: "interfaces",
            count: 4_097,
            maximum: 4_096,
        }
        .to_string(),
        "nl80211 interfaces count 4097 exceeds limit 4096"
    );
    assert_eq!(
        DiscoveryError::DuplicateIdentity {
            field: "interface",
            value: 3,
        }
        .to_string(),
        "duplicate nl80211 interface identity 3"
    );
    assert_eq!(
        DiscoveryError::UnknownPhy {
            interface: 7,
            phy: 9,
        }
        .to_string(),
        "nl80211 interface 7 refers to unknown physical radio 9"
    );
}

#[test]
fn capability_limits() -> Result<(), Box<dyn std::error::Error>> {
    let channel = ChannelCapability::new(2_412)?;
    assert!(Band::new(BandKind::Ghz2, vec![channel; 1_024]).is_ok());
    assert!(Band::new(BandKind::Ghz2, vec![channel; 1_025]).is_err());

    let band = Band::new(BandKind::Ghz2, vec![channel])?;
    assert!(
        PhyCapabilities::new(
            1,
            None,
            vec![WirelessMode::Station; 32],
            vec![],
            CapabilityState::Unknown,
        )
        .is_ok()
    );
    assert!(
        PhyCapabilities::new(
            1,
            None,
            vec![WirelessMode::Station; 33],
            vec![],
            CapabilityState::Unknown,
        )
        .is_err()
    );
    assert!(
        PhyCapabilities::new(
            1,
            None,
            vec![],
            vec![band.clone(); 16],
            CapabilityState::Unknown,
        )
        .is_ok()
    );
    assert!(
        PhyCapabilities::new(1, None, vec![], vec![band; 17], CapabilityState::Unknown,).is_err()
    );

    let phys = (0..256)
        .map(|id| PhyCapabilities::new(id, None, vec![], vec![], CapabilityState::Unknown))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(WirelessInventory::new(phys, vec![]).is_ok());
    let phys = (0..257)
        .map(|id| PhyCapabilities::new(id, None, vec![], vec![], CapabilityState::Unknown))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(WirelessInventory::new(phys, vec![]).is_err());

    let phy = PhyCapabilities::new(1, None, vec![], vec![], CapabilityState::Unknown)?;
    let interfaces = (1..=4_096)
        .map(|index| InterfaceInfo::new(index, format!("w{index}"), 1, WirelessMode::Station))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(WirelessInventory::new(vec![phy.clone()], interfaces).is_ok());
    let interfaces = (1..=4_097)
        .map(|index| InterfaceInfo::new(index, format!("w{index}"), 1, WirelessMode::Station))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(WirelessInventory::new(vec![phy], interfaces).is_err());
    Ok(())
}

#[test]
fn split_wiphy_bands_merge_channels() -> Result<(), Box<dyn std::error::Error>> {
    let phy = PhyCapabilities::new(
        1,
        None,
        vec![],
        vec![
            Band::new(
                wifi_linux::BandKind::Ghz5,
                vec![ChannelCapability::new(5_180)?],
            )?,
            Band::new(
                wifi_linux::BandKind::Ghz5,
                vec![ChannelCapability::new(5_200)?],
            )?,
        ],
        CapabilityState::Unknown,
    )?;

    let band = phy.bands().first().ok_or("missing merged band")?;
    assert_eq!(phy.bands().len(), 1);
    assert_eq!(band.channels().len(), 2);
    assert_eq!(
        band.channels().first().map(|item| item.frequency_mhz()),
        Some(5_180)
    );
    assert_eq!(
        band.channels().get(1).map(|item| item.frequency_mhz()),
        Some(5_200)
    );
    Ok(())
}
