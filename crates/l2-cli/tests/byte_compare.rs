use l2_cli::byte_compare::{
    CompareError, CompareOptions, MAX_BYTE_OFFSET, MAX_REPORTED_SPANS, MAX_SELECTED_BYTES,
    XorStatus, compare,
};

#[test]
fn selected_ranges_offsets_relative_range() -> Result<(), Box<dyn std::error::Error>> {
    let comparison = compare(
        &[0xaa, 0x10, 0x20, 0x30, 0x40],
        &[0xbb, 0x10, 0x21, 0x22, 0x40],
        CompareOptions {
            left_offset: 1,
            right_offset: 1,
            length: Some(4),
            xor_key: None,
        },
    )?;

    assert_eq!(comparison.compared_length, 4);
    assert_eq!(comparison.differing_bytes, 2);
    assert_eq!(comparison.spans.len(), 1);
    let span = comparison.spans.first().ok_or("missing difference span")?;
    assert_eq!(span.offset, 1);
    assert_eq!(span.length, 2);
    assert_eq!(comparison.left_tail_length, 0);
    assert_eq!(comparison.right_tail_length, 0);
    assert!(!comparison.spans_truncated);
    assert!(comparison.xor_verification.is_none());
    Ok(())
}

#[test]
fn unequal_tails_separately_byte_mismatches() -> Result<(), Box<dyn std::error::Error>> {
    let comparison = compare(
        &[1, 2, 3, 4],
        &[1, 2],
        CompareOptions {
            left_offset: 0,
            right_offset: 0,
            length: None,
            xor_key: None,
        },
    )?;

    assert_eq!(comparison.compared_length, 2);
    assert_eq!(comparison.differing_bytes, 0);
    assert_eq!(comparison.left_tail_length, 2);
    assert_eq!(comparison.right_tail_length, 0);
    Ok(())
}

#[test]
fn validates_exact_empty_default_remainder() -> Result<(), Box<dyn std::error::Error>> {
    let empty = compare(
        &[1, 2],
        &[3, 4],
        CompareOptions {
            left_offset: 2,
            right_offset: 2,
            length: None,
            xor_key: None,
        },
    )?;
    assert_eq!(empty.compared_length, 0);

    assert!(matches!(
        compare(
            &[1, 2],
            &[3, 4],
            CompareOptions {
                left_offset: 1,
                right_offset: 1,
                length: Some(2),
                xor_key: None,
            }
        ),
        Err(CompareError::RangeOutOfBounds { .. })
    ));
    assert!(matches!(
        compare(
            &[1, 2],
            &[3, 4],
            CompareOptions {
                left_offset: 3,
                right_offset: 0,
                length: None,
                xor_key: None,
            }
        ),
        Err(CompareError::OffsetOutOfBounds { .. })
    ));
    Ok(())
}

#[test]
fn ranges_offsets_public_api_limits() {
    for length in [0, MAX_SELECTED_BYTES + 1] {
        assert!(matches!(
            compare(
                &[],
                &[],
                CompareOptions {
                    left_offset: 0,
                    right_offset: 0,
                    length: Some(length),
                    xor_key: None,
                }
            ),
            Err(CompareError::InvalidRangeLength { .. })
        ));
    }

    assert!(matches!(
        compare(
            &[0],
            &[0],
            CompareOptions {
                left_offset: MAX_BYTE_OFFSET + 1,
                right_offset: 0,
                length: None,
                xor_key: None,
            }
        ),
        Err(CompareError::OffsetTooLarge { .. })
    ));

    let oversized_packet = vec![0; MAX_SELECTED_BYTES + 1];
    assert!(matches!(
        compare(
            &oversized_packet,
            &[0],
            CompareOptions {
                left_offset: 0,
                right_offset: 0,
                length: None,
                xor_key: None,
            }
        ),
        Err(CompareError::SelectionTooLong { .. })
    ));
}

#[test]
fn verifies_repeating_xor_selected_range() -> Result<(), Box<dyn std::error::Error>> {
    let left = [0xff, 0x10, 0x20, 0x30, 0x40];
    let right = [0x00, 0x00, 0x11, 0x22, 0x33, 0x41];
    let verified = compare(
        &left,
        &right,
        CompareOptions {
            left_offset: 1,
            right_offset: 2,
            length: Some(4),
            xor_key: Some(&[1, 2, 3]),
        },
    )?;
    assert_eq!(verified.xor_verification, Some(XorStatus::Verified));

    let mismatches = compare(
        &left,
        &[0x00, 0x00, 0x10, 0x22, 0x33, 0x42],
        CompareOptions {
            left_offset: 1,
            right_offset: 2,
            length: Some(4),
            xor_key: Some(&[1, 2, 3]),
        },
    )?;
    assert_eq!(
        mismatches.xor_verification,
        Some(XorStatus::Mismatch { differing_bytes: 2 })
    );
    Ok(())
}

#[test]
fn xor_verification_not_empty_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let unequal = compare(
        &[1, 2, 3],
        &[1, 2],
        CompareOptions {
            left_offset: 0,
            right_offset: 0,
            length: None,
            xor_key: Some(&[0]),
        },
    )?;
    assert_eq!(unequal.xor_verification, Some(XorStatus::NotComparable));

    let empty = compare(
        &[1],
        &[2],
        CompareOptions {
            left_offset: 1,
            right_offset: 1,
            length: None,
            xor_key: Some(&[0]),
        },
    )?;
    assert_eq!(empty.xor_verification, Some(XorStatus::NotComparable));
    Ok(())
}

#[test]
fn differences_bounding_contiguous_spans() -> Result<(), Box<dyn std::error::Error>> {
    let mut left = vec![0_u8; MAX_REPORTED_SPANS * 2 + 2];
    let right = vec![1_u8; MAX_REPORTED_SPANS * 2 + 2];
    for value in left.iter_mut().step_by(2) {
        *value = 1;
    }
    let comparison = compare(
        &left,
        &right,
        CompareOptions {
            left_offset: 0,
            right_offset: 0,
            length: None,
            xor_key: None,
        },
    )?;

    assert_eq!(comparison.differing_bytes, MAX_REPORTED_SPANS + 1);
    assert_eq!(comparison.spans.len(), MAX_REPORTED_SPANS);
    assert!(comparison.spans_truncated);
    Ok(())
}

#[test]
fn rejects_empty_overlong_xor_keys() {
    for key in [&[][..], &[0; 257][..]] {
        assert!(matches!(
            compare(
                &[1],
                &[2],
                CompareOptions {
                    left_offset: 0,
                    right_offset: 0,
                    length: None,
                    xor_key: Some(key),
                }
            ),
            Err(CompareError::InvalidXorKeyLength { .. })
        ));
    }
}
