use super::{NextBoundary, next_boundary_parts};
use crate::protocol::{ByteOrder, FramingKind, LengthMeaning};

fn assert_frame(actual: &NextBoundary, end: usize) {
    assert!(matches!(actual, NextBoundary::Frame(actual_end) if *actual_end == end));
}

fn assert_incomplete(actual: &NextBoundary) {
    assert!(matches!(actual, NextBoundary::Incomplete));
}

fn assert_invalid(actual: &NextBoundary) {
    assert!(matches!(actual, NextBoundary::Invalid));
}

#[test]
fn delimiter_every_cursor() {
    let bytes = b"abc|def|";
    let framing = FramingKind::Delimiter { byte: b'|' };
    let cases = [
        (0, Some(4)),
        (4, Some(8)),
        (8, None),
        (9, None),
        (usize::MAX, None),
    ];

    for split in 0..=bytes.len() {
        let (prefix, suffix) = bytes.split_at(split);
        for (cursor, expected) in cases {
            match expected {
                Some(end) => {
                    assert_frame(&next_boundary_parts(prefix, suffix, cursor, &framing), end);
                }
                None => assert_incomplete(&next_boundary_parts(prefix, suffix, cursor, &framing)),
            }
        }
    }
}

#[test]
fn fixed_size_cursor_overflow_results() {
    let bytes = b"abcdefgh";
    for split in 0..=bytes.len() {
        let (prefix, suffix) = bytes.split_at(split);
        assert_frame(
            &next_boundary_parts(prefix, suffix, 0, &FramingKind::FixedSize { bytes: 3 }),
            3,
        );
        assert_frame(
            &next_boundary_parts(prefix, suffix, 3, &FramingKind::FixedSize { bytes: 3 }),
            6,
        );
        assert_incomplete(&next_boundary_parts(
            prefix,
            suffix,
            6,
            &FramingKind::FixedSize { bytes: 3 },
        ));
        assert_incomplete(&next_boundary_parts(
            prefix,
            suffix,
            9,
            &FramingKind::FixedSize { bytes: 3 },
        ));
        assert_invalid(&next_boundary_parts(
            prefix,
            suffix,
            0,
            &FramingKind::FixedSize { bytes: 0 },
        ));
        assert_incomplete(&next_boundary_parts(
            prefix,
            suffix,
            1,
            &FramingKind::FixedSize { bytes: usize::MAX },
        ));
    }
}

fn encoded_length(value: u64, width: usize, byte_order: ByteOrder) -> Vec<u8> {
    let encoded = match byte_order {
        ByteOrder::BigEndian => value.to_be_bytes(),
        ByteOrder::LittleEndian => value.to_le_bytes(),
    };
    match byte_order {
        ByteOrder::BigEndian => encoded.into_iter().skip(8 - width).collect(),
        ByteOrder::LittleEndian => encoded.into_iter().take(width).collect(),
    }
}

fn length_message(
    width: usize,
    byte_order: ByteOrder,
    meaning: LengthMeaning,
) -> Result<Vec<u8>, std::num::TryFromIntError> {
    const PREFIX_OFFSET: usize = 2;
    const BODY: &[u8] = b"xyz";
    let field_end = PREFIX_OFFSET + width;
    let value = match meaning {
        LengthMeaning::WholeMessage => u64::try_from(field_end + BODY.len())?,
        LengthMeaning::BytesAfterField => u64::try_from(BODY.len())?,
    };

    let mut message = vec![0xa5; PREFIX_OFFSET];
    message.extend(encoded_length(value, width, byte_order));
    message.extend_from_slice(BODY);
    Ok(message)
}

#[test]
fn length_prefix_width_meanings() -> Result<(), Box<dyn std::error::Error>> {
    for width in [1_usize, 2, 4, 8] {
        for byte_order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
            for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                let message = length_message(width, byte_order, meaning)?;
                let frame_length = message.len();
                let mut bytes = message.clone();
                bytes.extend_from_slice(&message);
                let framing = FramingKind::LengthPrefix {
                    offset: 2,
                    width,
                    byte_order,
                    meaning,
                };

                for split in 0..=bytes.len() {
                    let (prefix, suffix) = bytes.split_at(split);
                    assert_frame(
                        &next_boundary_parts(prefix, suffix, 0, &framing),
                        frame_length,
                    );
                    assert_frame(
                        &next_boundary_parts(prefix, suffix, frame_length, &framing),
                        frame_length * 2,
                    );
                    assert_incomplete(&next_boundary_parts(
                        prefix,
                        suffix,
                        frame_length * 2,
                        &framing,
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn length_prefix_invalid_width_overflow() {
    let valid = FramingKind::LengthPrefix {
        offset: 2,
        width: 4,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };
    let bytes = [0, 0, 0, 0, 0, 8, b'x'];
    for split in 0..=bytes.len() {
        let (prefix, suffix) = bytes.split_at(split);
        assert_incomplete(&next_boundary_parts(prefix, suffix, 0, &valid));
    }

    assert_invalid(&next_boundary_parts(
        &[],
        &[],
        0,
        &FramingKind::LengthPrefix {
            offset: 0,
            width: 3,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
    ));
    assert_invalid(&next_boundary_parts(
        &[],
        &[],
        0,
        &FramingKind::LengthPrefix {
            offset: usize::MAX,
            width: 8,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
    ));

    let short_whole_message = FramingKind::LengthPrefix {
        offset: 2,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };
    assert_invalid(&next_boundary_parts(
        &[0, 0, 2],
        &[],
        0,
        &short_whole_message,
    ));

    let overflowing_after_field = FramingKind::LengthPrefix {
        offset: 0,
        width: 8,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::BytesAfterField,
    };
    assert_invalid(&next_boundary_parts(
        &[u8::MAX; 8],
        &[],
        0,
        &overflowing_after_field,
    ));

    let overflowing_cursor = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };
    assert_invalid(&next_boundary_parts(
        &[1],
        &[],
        usize::MAX,
        &overflowing_cursor,
    ));
}
