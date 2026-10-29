use std::{error::Error, net::Ipv4Addr};

use l2_onpath::neighbor::state::{
    StateRecordClaim, StateRecordReference, StateSource, StateSourceError, StateSourceQuality,
};
use l2_onpath::{
    AgentId, ClockDomainId, ClockStamp, EvidenceSourceId, InterfaceBindingRequest, MAX_STIMULI,
    MacAddress, RunId,
};
use sha2::{Digest, Sha256};

fn claim() -> Result<StateRecordClaim, Box<dyn Error>> {
    Ok(StateRecordClaim {
        run_id: RunId::from_recorded([0x11; 16])?,
        observer: AgentId::new([0x22; 16])?,
        interface: InterfaceBindingRequest::new(1, 2, 3, 4)?,
        subject: AgentId::new([0x33; 16])?,
        address: Ipv4Addr::new(192, 0, 2, 1).into(),
        binding: Some(MacAddress::new([2, 0, 0, 0, 0, 0x11])?),
        observed_at: ClockStamp::new(ClockDomainId::new([0x44; 16])?, 5)?,
    })
}

const fn quality() -> StateSourceQuality {
    StateSourceQuality {
        complete: true,
        dropped_records: 0,
    }
}

#[test]
fn valid_source_resolves_the_exact_modeled_claim_and_quality() -> Result<(), Box<dyn Error>> {
    let original = claim()?;
    let source = StateSource::from_records(quality(), &[original])?;
    let reference = StateRecordReference::new(source.source(), 1)?;
    let resolved = source.resolve(reference)?;

    assert_eq!(resolved.reference(), reference);
    assert_eq!(resolved.record(), original);
    assert_eq!(resolved.quality(), quality());
    assert_eq!(source.len(), 1);
    Ok(())
}

#[test]
fn source_rejects_zero_wrong_source_and_out_of_range_references() -> Result<(), Box<dyn Error>> {
    let source = StateSource::from_records(quality(), &[claim()?])?;
    assert!(matches!(
        StateRecordReference::new(source.source(), 0),
        Err(StateSourceError::ZeroRecord)
    ));
    let wrong = StateRecordReference::new(EvidenceSourceId::from_bytes([9; 32]), 1)?;
    assert!(matches!(
        source.resolve(wrong),
        Err(StateSourceError::SourceMismatch)
    ));
    let absent = StateRecordReference::new(source.source(), 2)?;
    assert!(matches!(
        source.resolve(absent),
        Err(StateSourceError::RecordOutOfBounds)
    ));
    Ok(())
}

#[test]
fn changed_source_bytes_cannot_resolve_the_original_reference() -> Result<(), Box<dyn Error>> {
    let source = StateSource::from_records(quality(), &[claim()?])?;
    let reference = StateRecordReference::new(source.source(), 1)?;
    let mut changed = source.bytes().to_vec();
    let last = changed.last_mut().ok_or("state source is empty")?;
    *last ^= 1;
    let changed_source = StateSource::from_bytes(&changed)?;
    assert!(matches!(
        changed_source.resolve(reference),
        Err(StateSourceError::SourceMismatch)
    ));
    Ok(())
}

#[test]
fn canonical_bytes_encode_each_field_and_identify_the_exact_source() -> Result<(), Box<dyn Error>> {
    let source = StateSource::from_records(quality(), &[claim()?])?;

    // Assemble the documented wire format independently from the encoder
    let mut expected = b"L2STATE\0\x01\x01".to_vec();
    expected.extend_from_slice(&0_u64.to_be_bytes());
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&[0x22; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&2_u64.to_be_bytes());
    expected.extend_from_slice(&3_u32.to_be_bytes());
    expected.extend_from_slice(&4_u32.to_be_bytes());
    expected.extend_from_slice(&[0x33; 16]);
    expected.push(4);
    expected.extend_from_slice(&[192, 0, 2, 1]);
    expected.extend_from_slice(&[0; 12]);
    expected.push(1);
    expected.extend_from_slice(&[2, 0, 0, 0, 0, 0x11]);
    expected.extend_from_slice(&[0x44; 16]);
    expected.extend_from_slice(&5_u64.to_be_bytes());
    assert_eq!(source.bytes(), expected);
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(source.source(), EvidenceSourceId::from_bytes(digest));
    Ok(())
}

#[test]
fn truncated_source_is_rejected_before_any_record_resolves() -> Result<(), Box<dyn Error>> {
    let source = StateSource::from_records(quality(), &[claim()?])?;
    let bytes = source.bytes();
    // Every strict prefix loses part of the header or record
    for end in 0..bytes.len() {
        let shortened = bytes.get(..end).ok_or("invalid prefix")?;
        assert!(matches!(
            StateSource::from_bytes(shortened),
            Err(StateSourceError::InvalidEncoding)
        ));
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        StateSource::from_bytes(&trailing),
        Err(StateSourceError::InvalidEncoding)
    ));
    Ok(())
}

#[test]
fn ipv6_absence_and_incomplete_lossy_source_round_trip() -> Result<(), Box<dyn Error>> {
    let mut original = claim()?;
    original.address = "2001:db8::5".parse()?;
    original.binding = None;
    let quality = StateSourceQuality {
        complete: false,
        dropped_records: 3,
    };
    let source = StateSource::from_records(quality, &[original])?;
    let reopened = StateSource::from_bytes(source.bytes())?;
    let reference = StateRecordReference::new(source.source(), 1)?;
    let resolved = reopened.resolve(reference)?;
    assert_eq!(resolved.record(), original);
    assert_eq!(resolved.quality(), quality);
    Ok(())
}

#[test]
fn distinct_records_resolve_by_one_based_position() -> Result<(), Box<dyn Error>> {
    let first = claim()?;
    let mut second = first;
    second.address = Ipv4Addr::new(198, 51, 100, 4).into();
    second.binding = None;
    let source = StateSource::from_records(quality(), &[first, second])?;
    assert_eq!(source.len(), 2);
    assert!(!source.is_empty());
    assert_eq!(
        source
            .resolve(StateRecordReference::new(source.source(), 1)?)?
            .record(),
        first
    );
    assert_eq!(
        source
            .resolve(StateRecordReference::new(source.source(), 2)?)?
            .record(),
        second
    );
    assert!(matches!(
        source.resolve(StateRecordReference::new(source.source(), u64::MAX)?),
        Err(StateSourceError::RecordOutOfBounds)
    ));
    Ok(())
}

#[test]
fn empty_and_maximum_size_sources_are_bounded() -> Result<(), Box<dyn Error>> {
    let empty = StateSource::from_records(quality(), &[])?;
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(matches!(
        empty.resolve(StateRecordReference::new(empty.source(), 1)?),
        Err(StateSourceError::RecordOutOfBounds)
    ));

    let records = vec![claim()?; MAX_STIMULI + 1];
    let maximum = records
        .get(..MAX_STIMULI)
        .ok_or("missing bounded records")?;
    let source = StateSource::from_records(quality(), maximum)?;
    assert_eq!(source.len(), MAX_STIMULI);
    let last = u64::try_from(MAX_STIMULI)?;
    assert_eq!(
        source
            .resolve(StateRecordReference::new(source.source(), last)?)?
            .record(),
        claim()?
    );
    assert!(matches!(
        StateSource::from_records(quality(), &records),
        Err(StateSourceError::RecordLimit)
    ));
    let mut oversized_header = empty.bytes().to_vec();
    let count = u16::try_from(MAX_STIMULI + 1)?.to_be_bytes();
    oversized_header
        .get_mut(18..20)
        .ok_or("missing record count")?
        .copy_from_slice(&count);
    assert!(matches!(
        StateSource::from_bytes(&oversized_header),
        Err(StateSourceError::RecordLimit)
    ));
    Ok(())
}

#[test]
fn invalid_neighbor_addresses_are_rejected_before_encoding() -> Result<(), Box<dyn Error>> {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "224.0.0.1",
        "::",
        "::1",
        "ff02::1",
    ] {
        let mut record = claim()?;
        record.address = address.parse()?;
        record.binding = None;
        assert!(matches!(
            StateSource::from_records(quality(), &[record]),
            Err(StateSourceError::InvalidAddress)
        ));
    }
    Ok(())
}

#[test]
fn encoded_invalid_addresses_and_macs_are_rejected() -> Result<(), Box<dyn Error>> {
    let ipv4_source = StateSource::from_records(quality(), &[claim()?])?;
    for address in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
        let mut bytes = ipv4_source.bytes().to_vec();
        bytes
            .get_mut(93..97)
            .ok_or("missing IPv4 address")?
            .copy_from_slice(&address);
        assert!(matches!(
            StateSource::from_bytes(&bytes),
            Err(StateSourceError::InvalidEncoding)
        ));
    }
    for mac in [[0; 6], [255; 6], [1, 0, 0, 0, 0, 1]] {
        let mut bytes = ipv4_source.bytes().to_vec();
        bytes
            .get_mut(110..116)
            .ok_or("missing MAC address")?
            .copy_from_slice(&mac);
        assert!(matches!(
            StateSource::from_bytes(&bytes),
            Err(StateSourceError::InvalidEncoding)
        ));
    }

    // A stored IPv6 record must satisfy the same on-link address checks
    let mut record = claim()?;
    record.address = "2001:db8::5".parse()?;
    let ipv6_source = StateSource::from_records(quality(), &[record])?;
    for address in ["::", "::1", "ff02::1"] {
        let mut bytes = ipv6_source.bytes().to_vec();
        let address: std::net::Ipv6Addr = address.parse()?;
        bytes
            .get_mut(93..109)
            .ok_or("missing IPv6 address")?
            .copy_from_slice(&address.octets());
        assert!(matches!(
            StateSource::from_bytes(&bytes),
            Err(StateSourceError::InvalidEncoding)
        ));
    }
    Ok(())
}

#[test]
fn invalid_headers_and_noncanonical_record_fields_are_rejected() -> Result<(), Box<dyn Error>> {
    let source = StateSource::from_records(quality(), &[claim()?])?;
    // Each changed byte breaks a distinct format or field invariant
    for (offset, value) in [
        (0, 0),   // marker
        (8, 2),   // version
        (9, 2),   // completeness flag
        (92, 5),  // address family
        (97, 1),  // IPv4 padding
        (109, 2), // binding flag
        (110, 1), // multicast MAC
    ] {
        let mut bytes = source.bytes().to_vec();
        *bytes.get_mut(offset).ok_or("missing encoded field")? = value;
        assert!(
            matches!(
                StateSource::from_bytes(&bytes),
                Err(StateSourceError::InvalidEncoding)
            ),
            "corrupt offset {offset} must be rejected"
        );
    }
    // Checked identities, interface, domain, and local ticks cannot be zero
    for (start, end) in [
        (20, 36),
        (36, 52),
        (52, 60),
        (76, 92),
        (116, 132),
        (132, 140),
    ] {
        let mut bytes = source.bytes().to_vec();
        bytes
            .get_mut(start..end)
            .ok_or("missing encoded field")?
            .fill(0);
        assert!(
            matches!(
                StateSource::from_bytes(&bytes),
                Err(StateSourceError::InvalidEncoding)
            ),
            "zeroed field at {start} must be rejected"
        );
    }
    // An absent entry must not retain hidden MAC bytes
    let mut absent_with_mac = source.bytes().to_vec();
    *absent_with_mac.get_mut(109).ok_or("missing binding flag")? = 0;
    assert!(matches!(
        StateSource::from_bytes(&absent_with_mac),
        Err(StateSourceError::InvalidEncoding)
    ));
    Ok(())
}
