use netlink_packet_core::{DefaultNla, Emitable, NLA_F_NESTED};

use super::{Capability, FeatureFlags, UnknownReason};

fn nla(kind: u16, bytes: &[u8]) -> DefaultNla {
    DefaultNla::new(kind, bytes.to_vec())
}

fn encoded(attributes: &[DefaultNla]) -> Vec<u8> {
    let mut result = vec![0; attributes.buffer_len()];
    attributes.emit(&mut result);
    result
}

fn nested(kind: u16, attributes: &[DefaultNla]) -> DefaultNla {
    nla(kind | NLA_F_NESTED, &encoded(attributes))
}

fn bit(index: u32, name: &str, value: bool) -> DefaultNla {
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    let mut attributes = vec![nla(1, &index.to_ne_bytes()), nla(2, &name)];
    if value {
        attributes.push(nla(3, &[]));
    }
    nested(1, &attributes)
}

fn bitset(masked: bool, entries: &[DefaultNla]) -> DefaultNla {
    let mut attributes = Vec::new();
    if !masked {
        attributes.push(nla(1, &[]));
    }
    attributes.push(nla(2, &64_u32.to_ne_bytes()));
    attributes.push(nested(3, entries));
    nested(0, &attributes)
}

fn value(attribute: DefaultNla) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Remove only the outer test wrapper; nested payload remains intact
    let bytes = encoded(&[attribute]);
    let header: [u8; 2] = bytes
        .get(..2)
        .ok_or("missing attribute header")?
        .try_into()?;
    let length = usize::from(u16::from_ne_bytes(header));
    Ok(bytes
        .get(4..length)
        .ok_or("missing attribute value")?
        .to_vec())
}

fn feature_reply(index: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hardware = value(bitset(
        true,
        &[
            bit(7, "rx-vlan-hw-parse", true),
            bit(8, "tx-vlan-hw-insert", false),
            bit(9, "rx-vlan-filter", true),
        ],
    ))?;
    let wanted = value(bitset(false, &[bit(8, "tx-vlan-hw-insert", false)]))?;
    let active = value(bitset(false, &[bit(7, "rx-vlan-hw-parse", false)]))?;
    Ok(encoded(&[
        nested(1, &[nla(1, &index.to_ne_bytes())]),
        nla(2 | NLA_F_NESTED, &hardware),
        nla(3 | NLA_F_NESTED, &wanted),
        nla(4 | NLA_F_NESTED, &active),
    ]))
}

#[test]
fn verbose_feature_names_map_to_hw_wanted_and_active_without_fixed_indices()
-> Result<(), Box<dyn std::error::Error>> {
    let report = super::decode::features(&feature_reply(17)?, 17)?;
    assert_eq!(
        report.ctag_rx,
        Capability::Reported(FeatureFlags {
            hw: true,
            wanted: false,
            active: true
        })
    );
    assert_eq!(
        report.ctag_tx,
        Capability::Reported(FeatureFlags {
            hw: false,
            wanted: true,
            active: false
        })
    );
    assert_eq!(
        report.ctag_filter,
        Capability::Reported(FeatureFlags {
            hw: true,
            wanted: false,
            active: false
        })
    );
    assert_eq!(
        report.stag_rx,
        Capability::Unknown(UnknownReason::NotReported)
    );
    Ok(())
}

#[test]
fn feature_reply_requires_correct_interface_and_complete_bitsets()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = feature_reply(17)?;
    assert!(super::decode::features(&bytes, 18).is_err());
    for length in 0..bytes.len() {
        assert!(
            super::decode::features(bytes.get(..length).ok_or("missing prefix")?, 17).is_err(),
            "truncated at {length}"
        );
    }
    Ok(())
}

#[test]
fn timestamping_absent_bitmap_is_empty_and_absent_phc_is_none()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = encoded(&[nested(1, &[nla(1, &17_u32.to_ne_bytes())])]);
    let report = super::decode::timestamps(&bytes, 17)?;
    assert_eq!(report.tx_software, Capability::Reported(false));
    assert_eq!(report.rx_hardware, Capability::Reported(false));
    assert_eq!(report.phc_index, Capability::Reported(None));
    Ok(())
}

#[test]
fn timestamping_reads_flags_and_phc_index_from_kernel_bitsets()
-> Result<(), Box<dyn std::error::Error>> {
    let flags = value(bitset(
        false,
        &[
            bit(0, "hardware-transmit", false),
            bit(3, "software-receive", false),
        ],
    ))?;
    let bytes = encoded(&[
        nested(1, &[nla(1, &17_u32.to_ne_bytes())]),
        nla(2 | NLA_F_NESTED, &flags),
        nla(5, &4_u32.to_ne_bytes()),
    ]);
    let report = super::decode::timestamps(&bytes, 17)?;
    assert_eq!(report.tx_hardware, Capability::Reported(true));
    assert_eq!(report.rx_software, Capability::Reported(true));
    assert_eq!(report.tx_software, Capability::Reported(false));
    assert_eq!(report.phc_index, Capability::Reported(Some(4)));
    Ok(())
}

#[test]
fn unnamed_timestamp_bit_does_not_claim_other_flags_are_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let unnamed = nested(1, &[nla(1, &1_u32.to_ne_bytes())]);
    let flags = value(bitset(false, &[unnamed]))?;
    let bytes = encoded(&[
        nested(1, &[nla(1, &17_u32.to_ne_bytes())]),
        nla(2 | NLA_F_NESTED, &flags),
    ]);
    let report = super::decode::timestamps(&bytes, 17)?;
    assert_eq!(
        report.tx_software,
        Capability::Unknown(UnknownReason::NotReported)
    );
    assert_eq!(
        report.rx_hardware,
        Capability::Unknown(UnknownReason::NotReported)
    );
    Ok(())
}

#[test]
fn duplicate_or_out_of_range_timestamp_bits_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    for bits in [
        vec![
            bit(1, "software-transmit", false),
            bit(1, "software-receive", false),
        ],
        vec![bit(64, "software-transmit", false)],
    ] {
        let flags = value(bitset(false, &bits))?;
        let bytes = encoded(&[
            nested(1, &[nla(1, &17_u32.to_ne_bytes())]),
            nla(2 | NLA_F_NESTED, &flags),
        ]);
        assert!(super::decode::timestamps(&bytes, 17).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_headers_and_oversized_bitsets_are_rejected() {
    let header = nested(1, &[nla(1, &17_u32.to_ne_bytes())]);
    let duplicate_header = encoded(&[header.clone(), header.clone()]);
    assert!(super::decode::timestamps(&duplicate_header, 17).is_err());

    let oversized = nested(
        2,
        &[nla(1, &[]), nla(2, &513_u32.to_ne_bytes()), nested(3, &[])],
    );
    assert!(super::decode::timestamps(&encoded(&[header, oversized]), 17).is_err());
}
