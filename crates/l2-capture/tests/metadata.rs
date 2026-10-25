use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, Direction, FcsStatus, InterfaceId,
    MAX_FCS_LENGTH, MAX_TIMESTAMP_RESOLUTION_EXPONENT, MetadataError, TimestampResolution,
    TimestampSource, VlanAuxData,
};

#[test]
fn pcapng_constants_keep_wire_meaning() {
    assert_eq!(MAX_FCS_LENGTH, 31);
    assert_eq!(MAX_TIMESTAMP_RESOLUTION_EXPONENT, 127);
}

#[test]
fn fcs_lengths_accept_protocol_boundaries() -> Result<(), MetadataError> {
    let shortest = FcsStatus::present(1)?;
    let longest = FcsStatus::present(MAX_FCS_LENGTH)?;

    assert_eq!(shortest.length(), Some(1));
    assert_eq!(longest.length(), Some(MAX_FCS_LENGTH));
    Ok(())
}

#[test]
fn rejects_invalid_fcs_lengths() {
    assert!(matches!(
        FcsStatus::present(0),
        Err(MetadataError::InvalidFcsLength { length: 0, max })
            if max == MAX_FCS_LENGTH
    ));

    assert!(matches!(
        FcsStatus::present(MAX_FCS_LENGTH.saturating_add(1)),
        Err(MetadataError::InvalidFcsLength { length, max })
            if length == MAX_FCS_LENGTH.saturating_add(1) && max == MAX_FCS_LENGTH
    ));
}

#[test]
fn metadata_errors_wire_field_context() {
    assert_eq!(
        MetadataError::InvalidFcsLength {
            length: 0,
            max: MAX_FCS_LENGTH,
        }
        .to_string(),
        "invalid FCS length 0 bytes; expected 1..=31"
    );
    assert_eq!(
        MetadataError::InvalidTimestampResolution {
            radix: 2,
            exponent: 128,
            max: MAX_TIMESTAMP_RESOLUTION_EXPONENT,
        }
        .to_string(),
        "invalid base-2 timestamp exponent 128; expected 0..=127"
    );
}

#[test]
fn timestamp_exponents_accept_protocol_boundaries() -> Result<(), MetadataError> {
    let decimal = TimestampResolution::decimal(MAX_TIMESTAMP_RESOLUTION_EXPONENT)?;
    let binary = TimestampResolution::binary(MAX_TIMESTAMP_RESOLUTION_EXPONENT)?;

    assert_eq!(decimal.exponent(), MAX_TIMESTAMP_RESOLUTION_EXPONENT);
    assert_eq!(binary.exponent(), MAX_TIMESTAMP_RESOLUTION_EXPONENT);
    assert_eq!(decimal.radix(), 10);
    assert_eq!(binary.radix(), 2);
    Ok(())
}

#[test]
fn rejects_invalid_timestamp_exponents() {
    let invalid = MAX_TIMESTAMP_RESOLUTION_EXPONENT.saturating_add(1);

    assert!(matches!(
        TimestampResolution::decimal(invalid),
        Err(MetadataError::InvalidTimestampResolution {
            radix: 10,
            exponent,
            max,
        }) if exponent == invalid && max == MAX_TIMESTAMP_RESOLUTION_EXPONENT
    ));
    assert!(matches!(
        TimestampResolution::binary(invalid),
        Err(MetadataError::InvalidTimestampResolution {
            radix: 2,
            exponent,
            max,
        }) if exponent == invalid && max == MAX_TIMESTAMP_RESOLUTION_EXPONENT
    ));
}

#[test]
fn accepts_prevalidated_timestamp_resolution() -> Result<(), MetadataError> {
    let decimal = TimestampResolution::decimal(MAX_TIMESTAMP_RESOLUTION_EXPONENT)?;
    let binary = TimestampResolution::binary(MAX_TIMESTAMP_RESOLUTION_EXPONENT)?;

    assert_eq!(
        CaptureTimestamp::new(1, decimal, 2, TimestampSource::CaptureFile).resolution(),
        decimal
    );
    assert_eq!(
        CaptureTimestamp::new(3, binary, 4, TimestampSource::Unknown).resolution(),
        binary
    );
    Ok(())
}

#[test]
fn exposes_checked_metadata_accessors() -> Result<(), Box<dyn std::error::Error>> {
    let interface = InterfaceId {
        section: 3,
        index: 7,
    };
    let timestamp = CaptureTimestamp::new(
        99,
        TimestampResolution::decimal(6)?,
        -2,
        TimestampSource::CaptureFile,
    );
    let fcs = FcsStatus::present(4)?;
    let metadata = CaptureMetadata::new(
        interface,
        4,
        Some(CaptureLocator::ClassicPcap {
            record_offset: 10,
            data_offset: 26,
        }),
        Some(timestamp),
        Direction::Inbound,
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 0x0064,
        }),
        fcs,
    );

    assert_eq!(metadata.interface(), interface);
    assert_eq!(metadata.original_len(), 4);
    assert_eq!(
        metadata.locator(),
        Some(CaptureLocator::ClassicPcap {
            record_offset: 10,
            data_offset: 26,
        })
    );
    assert_eq!(metadata.timestamp(), Some(timestamp));
    assert_eq!(metadata.direction(), Direction::Inbound);
    assert_eq!(
        metadata.vlan(),
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 0x0064
        })
    );
    assert_eq!(metadata.fcs(), fcs);
    assert_eq!(timestamp.ticks(), 99);
    assert_eq!(timestamp.resolution(), TimestampResolution::decimal(6)?);
    assert_eq!(timestamp.offset_seconds(), -2);
    assert_eq!(timestamp.source(), TimestampSource::CaptureFile);
    Ok(())
}
