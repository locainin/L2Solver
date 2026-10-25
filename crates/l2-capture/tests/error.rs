use l2_capture::{CaptureMetadata, CapturedFrame, FrameError, InterfaceId};

#[test]
fn frame_errors_keep_actionable_context() {
    let errors = [
        (
            FrameError::FrameTooLong {
                length: 65_536,
                max: 65_535,
            },
            "captured frame length 65536 exceeds maximum 65535",
        ),
        (
            FrameError::CapturedLengthExceedsOriginal {
                captured: 2,
                original: 1,
            },
            "captured frame length 2 exceeds original length 1",
        ),
    ];

    for (error, expected) in errors {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn exposes_exact_evidence_bytes() -> Result<(), FrameError> {
    let frame = CapturedFrame::new(
        vec![0xde, 0xad, 0xbe, 0xef],
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            4,
        ),
    )?;

    assert_eq!(
        <CapturedFrame as AsRef<[u8]>>::as_ref(&frame),
        frame.bytes()
    );
    Ok(())
}
