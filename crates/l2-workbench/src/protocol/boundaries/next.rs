use super::super::{ByteOrder, FramingKind, LengthMeaning};
use crate::integer::decode_unsigned;

pub(in crate::protocol) fn next_boundary(
    bytes: &[u8],
    cursor: usize,
    kind: &FramingKind,
) -> NextBoundary {
    next_boundary_parts(bytes, &[], cursor, kind)
}

pub(in crate::protocol) fn next_boundary_parts(
    prefix: &[u8],
    suffix: &[u8],
    cursor: usize,
    kind: &FramingKind,
) -> NextBoundary {
    let view = ByteView { prefix, suffix };
    let Some(length) = view.len() else {
        return NextBoundary::Invalid;
    };

    match kind {
        FramingKind::Delimiter { byte } => delimiter_end(view, cursor, *byte),
        FramingKind::FixedSize { bytes: size } => fixed_end(length, cursor, *size),
        FramingKind::LengthPrefix {
            offset,
            width,
            byte_order,
            meaning,
        } => length_end(view, length, cursor, *offset, *width, *byte_order, *meaning),
    }
}

#[derive(Clone, Copy)]
struct ByteView<'a> {
    prefix: &'a [u8],
    suffix: &'a [u8],
}

impl ByteView<'_> {
    const fn len(self) -> Option<usize> {
        self.prefix.len().checked_add(self.suffix.len())
    }

    fn get(self, index: usize) -> Option<u8> {
        if let Some(byte) = self.prefix.get(index) {
            return Some(*byte);
        }
        let suffix_index = index.checked_sub(self.prefix.len())?;
        self.suffix.get(suffix_index).copied()
    }

    fn find(self, cursor: usize, byte: u8) -> Option<usize> {
        if cursor <= self.prefix.len() {
            if let Some(offset) = self
                .prefix
                .get(cursor..)?
                .iter()
                .position(|candidate| *candidate == byte)
            {
                return cursor.checked_add(offset);
            }
            return self
                .suffix
                .iter()
                .position(|candidate| *candidate == byte)
                .and_then(|offset| self.prefix.len().checked_add(offset));
        }

        let suffix_cursor = cursor.checked_sub(self.prefix.len())?;
        self.suffix
            .get(suffix_cursor..)?
            .iter()
            .position(|candidate| *candidate == byte)
            .and_then(|offset| cursor.checked_add(offset))
    }

    fn copy_into(self, start: usize, output: &mut [u8]) -> Option<()> {
        for (offset, byte) in output.iter_mut().enumerate() {
            *byte = self.get(start.checked_add(offset)?)?;
        }
        Some(())
    }
}

fn delimiter_end(view: ByteView<'_>, cursor: usize, delimiter: u8) -> NextBoundary {
    view.find(cursor, delimiter)
        .and_then(|offset| offset.checked_add(1))
        .map_or(NextBoundary::Incomplete, NextBoundary::Frame)
}

fn fixed_end(length: usize, cursor: usize, size: usize) -> NextBoundary {
    if size == 0 {
        return NextBoundary::Invalid;
    }
    cursor
        .checked_add(size)
        .filter(|end| *end <= length)
        .map_or(NextBoundary::Incomplete, NextBoundary::Frame)
}

fn length_end(
    view: ByteView<'_>,
    input_length: usize,
    cursor: usize,
    offset: usize,
    width: usize,
    byte_order: ByteOrder,
    meaning: LengthMeaning,
) -> NextBoundary {
    let Some(field_end) = offset.checked_add(width) else {
        return NextBoundary::Invalid;
    };
    if !matches!(width, 1 | 2 | 4 | 8) {
        return NextBoundary::Invalid;
    }
    let Some(field_start) = cursor.checked_add(offset) else {
        return NextBoundary::Invalid;
    };
    let Some(absolute_field_end) = cursor.checked_add(field_end) else {
        return NextBoundary::Invalid;
    };
    if absolute_field_end > input_length {
        return NextBoundary::Incomplete;
    }
    let mut field = [0_u8; 8];
    let Some(field) = field.get_mut(..width) else {
        return NextBoundary::Invalid;
    };
    if view.copy_into(field_start, field).is_none() {
        return NextBoundary::Incomplete;
    }
    let Some(value) = decode_unsigned(field, byte_order == ByteOrder::LittleEndian) else {
        return NextBoundary::Invalid;
    };
    let length = match meaning {
        LengthMeaning::WholeMessage => usize::try_from(value).ok(),
        LengthMeaning::BytesAfterField => usize::try_from(value)
            .ok()
            .and_then(|after| field_end.checked_add(after)),
    };
    let Some(length) = length else {
        return NextBoundary::Invalid;
    };
    if length == 0 || length < field_end {
        return NextBoundary::Invalid;
    }
    let Some(end) = cursor.checked_add(length) else {
        return NextBoundary::Invalid;
    };
    if end > input_length {
        return NextBoundary::Incomplete;
    }
    NextBoundary::Frame(end)
}

pub(in crate::protocol) enum NextBoundary {
    Frame(usize),
    Incomplete,
    Invalid,
}
