use super as discover;
use crate::{DiscoveryError, MAX_CHANNEL_RECORDS, WirelessInventory, WirelessMode};

mod connection;
mod dump_completion;

use proptest::prelude::*;
use wl_nl80211::{
    Nl80211Attr, Nl80211Band, Nl80211BandInfo, Nl80211Command, Nl80211Frequency,
    Nl80211FrequencyInfo, Nl80211IfMode, Nl80211Message,
};

const fn message(attributes: Vec<Nl80211Attr>) -> Nl80211Message {
    Nl80211Message {
        cmd: Nl80211Command::NewWiphy,
        attributes,
    }
}

fn band(frequencies: &[u32]) -> Nl80211Band {
    Nl80211Band {
        kind: wl_nl80211::Nl80211BandType::Band5GHz,
        info: vec![Nl80211BandInfo::Freqs(
            frequencies
                .iter()
                .map(|frequency| Nl80211Frequency {
                    index: 1,
                    info: vec![Nl80211FrequencyInfo::Freq(*frequency)],
                })
                .collect(),
        )],
    }
}

#[test]
fn wiphy_dump_unique_radio_limit() -> Result<(), Box<dyn std::error::Error>> {
    let first = message(vec![
        Nl80211Attr::Wiphy(7),
        Nl80211Attr::WiphyName(String::from("phy7")),
        Nl80211Attr::SupportedIftypes(vec![Nl80211IfMode::Station]),
        Nl80211Attr::WiphyBands(vec![band(&[5_180])]),
    ]);
    let second = message(vec![
        Nl80211Attr::Wiphy(7),
        Nl80211Attr::WiphyBands(vec![band(&[5_200])]),
    ]);

    let inventory = normalize_messages(vec![first, second], Vec::new())?;
    let phy = inventory.phys().first().ok_or("missing physical radio")?;
    let channels = phy.bands().first().ok_or("missing 5 GHz band")?.channels();
    assert_eq!(inventory.phys().len(), 1);
    assert_eq!(channels.len(), 2);
    assert_eq!(phy.modes(), &[WirelessMode::Station]);
    Ok(())
}

#[test]
fn conflicting_names_radio_rejected_either() {
    for names in [["phy-old", "phy-new"], ["phy-new", "phy-old"]] {
        let records = names
            .into_iter()
            .map(|name| {
                message(vec![
                    Nl80211Attr::Wiphy(7),
                    Nl80211Attr::WiphyName(name.into()),
                ])
            })
            .collect();
        assert!(matches!(
            normalize_messages(records, vec![]),
            Err(DiscoveryError::InvalidValue {
                field: "physical radio name",
                ..
            })
        ));
    }
}

proptest! {
    #[test]
    fn radio_fragments_independent_arrival(
        inputs in prop::collection::vec((any::<u8>(), any::<u8>()), 1..24)
    ) {
        let records: Vec<_> = inputs.iter().map(|(_, channel)| message(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::WiphyName("phy7".into()),
            Nl80211Attr::SupportedIftypes(vec![Nl80211IfMode::Station]),
            Nl80211Attr::WiphyBands(vec![band(&[5_000 + u32::from(*channel) * 5])]),
        ])).collect();
        let expected = normalize_messages(records.clone(), vec![]);
        prop_assert!(expected.is_ok());
        let mut reordered: Vec<_> = inputs.iter().zip(records).collect();
        reordered.sort_by_key(|((rank, _), _)| *rank);
        let actual = normalize_messages(reordered.into_iter().map(|(_, value)| value).collect(), vec![]);
        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn physical_dump_limit_while_collecting() {
    let mut physical = discover::PhysicalAccumulator::new();
    let result = (0..=256)
        .map(|id| physical.merge(vec![Nl80211Attr::Wiphy(id)]))
        .find(Result::is_err)
        .unwrap_or(Ok(()));

    assert_eq!(
        result,
        Err(DiscoveryError::ResourceLimit {
            field: "physical radios",
            count: 257,
            maximum: 256,
        })
    );
}

#[test]
fn split_wiphy_fragment_work_bounded() {
    let mut physical = discover::PhysicalAccumulator::new();
    let mut result = Ok(());
    for _ in 0..=4_096 {
        result = physical.merge(vec![Nl80211Attr::Wiphy(7)]);
        if result.is_err() {
            break;
        }
    }

    assert_eq!(
        result,
        Err(DiscoveryError::ResourceLimit {
            field: "physical dump records",
            count: 4_097,
            maximum: 4_096,
        })
    );
}

#[test]
fn single_wiphy_band_boundary() {
    let frequencies: Vec<_> = (0..=MAX_CHANNEL_RECORDS)
        .map(|offset| 5_000_u32 + u32::try_from(offset).unwrap_or_default())
        .collect();
    let result = normalize_messages(
        vec![message(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::WiphyBands(vec![band(&frequencies)]),
        ])],
        Vec::new(),
    );

    assert_eq!(
        result,
        Err(DiscoveryError::ResourceLimit {
            field: "channel records per band",
            count: MAX_CHANNEL_RECORDS + 1,
            maximum: MAX_CHANNEL_RECORDS,
        })
    );
}

#[test]
fn interface_dump_limit_while_collecting() {
    let mut interfaces = discover::InterfaceAccumulator::new();
    let mut result = Ok(());
    for index in 1..=4_097 {
        result = interfaces.push(message(vec![
            Nl80211Attr::IfIndex(index),
            Nl80211Attr::IfName(format!("w{index}")),
            Nl80211Attr::Wiphy(1),
            Nl80211Attr::IfType(wl_nl80211::Nl80211InterfaceType::Station),
        ]));
        if result.is_err() {
            break;
        }
    }
    assert_eq!(
        result,
        Err(DiscoveryError::ResourceLimit {
            field: "interfaces",
            count: 4_097,
            maximum: 4_096,
        })
    );
}

#[test]
fn non_netdev_records_do_not_hide_the_selected_network_interface()
-> Result<(), Box<dyn std::error::Error>> {
    use wl_nl80211::Nl80211InterfaceType;

    let physical = vec![message(vec![Nl80211Attr::Wiphy(7)])];
    let mut devices: Vec<_> = [
        Nl80211InterfaceType::P2pDevice,
        Nl80211InterfaceType::Nan,
        Nl80211InterfaceType::Other(14),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, mode)| {
        message(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(u64::try_from(index).unwrap_or_default() + 1),
            Nl80211Attr::IfType(mode),
        ])
    })
    .collect();
    devices.push(message(vec![
        Nl80211Attr::Wiphy(7),
        Nl80211Attr::IfIndex(9),
        Nl80211Attr::IfName("wlan0".into()),
        Nl80211Attr::IfType(Nl80211InterfaceType::Station),
    ]));
    let inventory = normalize_messages(physical, devices)?;
    assert_eq!(inventory.interfaces().len(), 1);
    assert_eq!(
        inventory
            .interfaces()
            .first()
            .map(crate::InterfaceInfo::index),
        Some(9)
    );
    Ok(())
}

#[test]
fn malformed_non_netdev_and_missing_netdev_identity_are_rejected() {
    use wl_nl80211::Nl80211InterfaceType;

    let cases = [
        vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::IfType(Nl80211InterfaceType::P2pDevice),
        ],
        vec![
            Nl80211Attr::Wdev(2),
            Nl80211Attr::IfType(Nl80211InterfaceType::Nan),
        ],
        vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(2),
            Nl80211Attr::Wdev(3),
            Nl80211Attr::IfType(Nl80211InterfaceType::Other(14)),
        ],
        vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(2),
            Nl80211Attr::IfIndex(9),
            Nl80211Attr::IfType(Nl80211InterfaceType::P2pDevice),
        ],
        vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(2),
            Nl80211Attr::IfName("unexpected".into()),
            Nl80211Attr::IfType(Nl80211InterfaceType::Nan),
        ],
        vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(2),
            Nl80211Attr::IfType(Nl80211InterfaceType::Other(13)),
        ],
    ];
    for attributes in cases {
        let mut interfaces = discover::InterfaceAccumulator::new();
        assert!(interfaces.push(message(attributes)).is_err());
    }
}

#[test]
fn skipped_non_netdev_records_still_count_toward_dump_budget() {
    use wl_nl80211::Nl80211InterfaceType;

    let mut interfaces = discover::InterfaceAccumulator::new();
    let mut result = Ok(());
    for _ in 0..=4_096 {
        result = interfaces.push(message(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::Wdev(2),
            Nl80211Attr::IfType(Nl80211InterfaceType::P2pDevice),
        ]));
        if result.is_err() {
            break;
        }
    }
    assert_eq!(
        result,
        Err(DiscoveryError::ResourceLimit {
            field: "interfaces",
            count: 4_097,
            maximum: 4_096,
        })
    );
}

#[test]
fn non_netdev_record_with_unknown_radio_is_rejected() {
    use wl_nl80211::Nl80211InterfaceType;

    let physical = vec![message(vec![Nl80211Attr::Wiphy(7)])];
    let devices = vec![message(vec![
        Nl80211Attr::Wiphy(9),
        Nl80211Attr::Wdev(2),
        Nl80211Attr::IfType(Nl80211InterfaceType::P2pDevice),
    ])];
    assert!(matches!(
        normalize_messages(physical, devices),
        Err(DiscoveryError::InvalidValue {
            field: "physical radio ID",
            ..
        })
    ));
}

#[test]
fn duplicate_scalar_attributes_rejected_either() {
    for indexes in [[1, 2], [2, 1]] {
        let interface = message(vec![
            Nl80211Attr::IfIndex(indexes[0]),
            Nl80211Attr::IfIndex(indexes[1]),
            Nl80211Attr::IfName("wlan0".into()),
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::IfType(wl_nl80211::Nl80211InterfaceType::Station),
        ]);
        assert!(matches!(
            normalize_messages(Vec::new(), vec![interface]),
            Err(DiscoveryError::InvalidValue {
                field: "interface index",
                ..
            })
        ));
    }
}

#[test]
fn duplicate_physical_attributes_rejected_either() {
    for identities in [[7, 8], [8, 7]] {
        let physical = message(vec![
            Nl80211Attr::Wiphy(identities[0]),
            Nl80211Attr::Wiphy(identities[1]),
        ]);
        assert!(matches!(
            normalize_messages(vec![physical], Vec::new()),
            Err(DiscoveryError::InvalidValue {
                field: "physical radio ID",
                ..
            })
        ));
    }
}

#[test]
fn duplicate_frequency_attributes_rejected_either() {
    for frequencies in [[5_180, 5_200], [5_200, 5_180]] {
        let physical = message(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::WiphyBands(vec![Nl80211Band {
                kind: wl_nl80211::Nl80211BandType::Band5GHz,
                info: vec![Nl80211BandInfo::Freqs(vec![Nl80211Frequency {
                    index: 1,
                    info: vec![
                        Nl80211FrequencyInfo::Freq(frequencies[0]),
                        Nl80211FrequencyInfo::Freq(frequencies[1]),
                    ],
                }])],
            }]),
        ]);
        assert!(matches!(
            normalize_messages(vec![physical], Vec::new()),
            Err(DiscoveryError::InvalidValue {
                field: "channel frequency",
                ..
            })
        ));
    }
}

#[test]
fn rejected_physical_not_partial_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut physical = discover::PhysicalAccumulator::new();
    assert!(matches!(
        physical.merge(vec![
            Nl80211Attr::Wiphy(7),
            Nl80211Attr::SupportedIftypes(vec![Nl80211IfMode::Station]),
            Nl80211Attr::WiphyName(String::new()),
        ]),
        Err(DiscoveryError::InvalidValue {
            field: "physical radio name",
            ..
        })
    ));

    physical.merge(vec![
        Nl80211Attr::Wiphy(7),
        Nl80211Attr::WiphyName("phy7".into()),
    ])?;
    let normalized = physical.finish()?;
    let phy = normalized.first().ok_or("missing physical radio")?;
    assert!(phy.modes().is_empty());
    Ok(())
}

// Synthetic records follow the same accumulators and final validation as live dumps
fn normalize_messages(
    physical_records: Vec<Nl80211Message>,
    interface_records: Vec<Nl80211Message>,
) -> Result<WirelessInventory, DiscoveryError> {
    let mut physical = discover::PhysicalAccumulator::new();
    for record in physical_records {
        physical.merge(record.attributes)?;
    }
    let mut interfaces = discover::InterfaceAccumulator::new();
    for record in interface_records {
        interfaces.push(record)?;
    }
    let physical = physical.finish()?;
    let interfaces = interfaces.finish(&physical)?;
    WirelessInventory::new(physical, interfaces)
}
