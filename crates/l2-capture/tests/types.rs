use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, FrameError,
    InterfaceId, MAX_FRAME_LENGTH, TimestampResolution, TimestampSource, VlanAuxData,
};

#[test]
fn derives_capture_state_from_bytes() -> Result<(), Box<dyn std::error::Error>> {
    // The metadata records the wire length, while the frame derives the retained length
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 3,
            index: 7,
        },
        4,
        None,
        Some(CaptureTimestamp::new(
            99,
            TimestampResolution::decimal(6)?,
            -2,
            TimestampSource::CaptureFile,
        )),
        Direction::Inbound,
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 0x0064,
        }),
        FcsStatus::present(4)?,
    );
    let frame = CapturedFrame::new(vec![1, 2, 3], metadata.clone())?;

    assert_eq!(frame.bytes(), &[1, 2, 3]);
    assert_eq!(frame.captured_len(), 3);
    assert!(frame.is_truncated());
    assert_eq!(frame.metadata(), &metadata);
    Ok(())
}

#[test]
fn accepts_maximum_without_derived_lengths() -> Result<(), FrameError> {
    // A full-size frame has no truncation marker beyond the original length
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(MAX_FRAME_LENGTH).unwrap_or_default(),
    );
    let frame = CapturedFrame::new(vec![0; MAX_FRAME_LENGTH], metadata)?;

    assert_eq!(frame.captured_len(), MAX_FRAME_LENGTH);
    assert!(!frame.is_truncated());
    Ok(())
}

#[test]
fn rejects_oversized_inconsistent_frame() {
    // The retained-byte ceiling is independent of the original wire length
    let oversized = CapturedFrame::new(
        vec![0; MAX_FRAME_LENGTH + 1],
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            u32::try_from(MAX_FRAME_LENGTH + 1).unwrap_or_default(),
        ),
    );
    assert!(matches!(
        oversized,
        Err(FrameError::FrameTooLong {
            length,
            max: MAX_FRAME_LENGTH,
        }) if length == MAX_FRAME_LENGTH + 1
    ));

    // A capture cannot retain more bytes than the wire length it reports
    let inconsistent = CapturedFrame::new(
        vec![0; 2],
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            1,
        ),
    );
    assert!(matches!(
        inconsistent,
        Err(FrameError::CapturedLengthExceedsOriginal {
            captured: 2,
            original: 1,
        })
    ));
}

#[test]
fn unknown_metadata_explicit_unknown_values() {
    // Backends use this constructor when the source has no optional metadata
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 1,
            index: 2,
        },
        17,
    );

    assert_eq!(
        metadata.interface(),
        InterfaceId {
            section: 1,
            index: 2
        }
    );
    assert_eq!(metadata.original_len(), 17);
    assert_eq!(metadata.locator(), None);
    assert_eq!(metadata.timestamp(), None);
    assert_eq!(metadata.direction(), Direction::Unknown);
    assert_eq!(metadata.vlan(), None);
    assert_eq!(metadata.fcs(), FcsStatus::Unknown);
}

#[test]
fn interface_ids_orderable_section_index() {
    // The tuple-like ordering keeps IDs deterministic across section changes
    let first = InterfaceId {
        section: 1,
        index: 9,
    };
    let second = InterfaceId {
        section: 2,
        index: 0,
    };
    assert!(first < second);
}
