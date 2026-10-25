use super::Operation;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

/// Borrowed operation identity with execution-equivalent parameters normalized
pub struct OperationIdentity<'a>(OperationIdentityKind<'a>);

enum OperationIdentityKind<'a> {
    RotateBits { count: u8 },
    XorRepeat { key: &'a [u8], offset: usize },
    Exact(&'a Operation),
}

impl<'a> OperationIdentity<'a> {
    pub fn new(operation: &'a Operation) -> Self {
        let identity = match operation {
            Operation::RotateBits { count } => {
                OperationIdentityKind::RotateBits { count: count % 8 }
            }
            Operation::XorRepeat { key, offset } => OperationIdentityKind::XorRepeat {
                key,
                offset: *offset,
            },
            operation => OperationIdentityKind::Exact(operation),
        };
        Self(identity)
    }
}

impl PartialEq for OperationIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                OperationIdentityKind::RotateBits { count: left },
                OperationIdentityKind::RotateBits { count: right },
            ) => left == right,
            (
                OperationIdentityKind::XorRepeat {
                    key: left_key,
                    offset: left_offset,
                },
                OperationIdentityKind::XorRepeat {
                    key: right_key,
                    offset: right_offset,
                },
            ) => xor_streams_equal(left_key, *left_offset, right_key, *right_offset),
            (OperationIdentityKind::Exact(left), OperationIdentityKind::Exact(right)) => {
                left == right
            }
            _ => false,
        }
    }
}

impl Eq for OperationIdentity<'_> {}

impl Serialize for OperationIdentity<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            OperationIdentityKind::RotateBits { count } => {
                let mut state = serializer.serialize_struct("Operation", 2)?;
                state.serialize_field("kind", "rotate_bits")?;
                state.serialize_field("count", count)?;
                state.end()
            }
            OperationIdentityKind::XorRepeat { key, offset } if key.is_empty() => {
                let mut state = serializer.serialize_struct("Operation", 3)?;
                state.serialize_field("kind", "xor_repeat")?;
                state.serialize_field("key", key)?;
                // Invalid empty keys retain their caller offset without division
                state.serialize_field("offset", offset)?;
                state.end()
            }
            OperationIdentityKind::XorRepeat { key, offset } => {
                let period = primitive_period(key).map_err(|()| {
                    <S::Error as serde::ser::Error>::custom(
                        "could not allocate canonical XOR key identity",
                    )
                })?;
                let phase = offset % period;
                let mut state = serializer.serialize_struct("Operation", 3)?;
                state.serialize_field("kind", "xor_repeat")?;
                state.serialize_field("key", &CanonicalXorKey { key, period, phase })?;
                state.serialize_field("offset", &0_usize)?;
                state.end()
            }
            OperationIdentityKind::Exact(operation) => operation.serialize(serializer),
        }
    }
}

struct CanonicalXorKey<'a> {
    key: &'a [u8],
    period: usize,
    phase: usize,
}

impl Serialize for CanonicalXorKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.period))?;
        for position in 0..self.period {
            // A rotation of a primitive word remains primitive, so the original
            // shortest period is also the shortest period after phase adjustment
            let byte = rotated_key_byte(self.key, self.period, self.phase, position)
                .ok_or_else(|| <S::Error as serde::ser::Error>::custom("invalid XOR key phase"))?;
            sequence.serialize_element(&byte)?;
        }
        sequence.end()
    }
}

fn xor_streams_equal(
    left_key: &[u8],
    left_offset: usize,
    right_key: &[u8],
    right_offset: usize,
) -> bool {
    if left_key.is_empty() || right_key.is_empty() {
        // Empty keys fail execution and keep distinct caller offsets for identity
        return left_key.is_empty() && right_key.is_empty() && left_offset == right_offset;
    }

    let Some(combined_length) = left_key.len().checked_add(right_key.len()) else {
        return false;
    };
    let left_phase = left_offset % left_key.len();
    let right_phase = right_offset % right_key.len();
    (0..combined_length).all(|position| {
        match (
            concat_stream_byte(left_key, left_phase, right_key, right_phase, position),
            concat_stream_byte(right_key, right_phase, left_key, left_phase, position),
        ) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    })
}

fn concat_stream_byte(
    first_key: &[u8],
    first_phase: usize,
    second_key: &[u8],
    second_phase: usize,
    position: usize,
) -> Option<u8> {
    if position < first_key.len() {
        rotated_key_byte(first_key, first_key.len(), first_phase, position)
    } else {
        let position = position - first_key.len();
        rotated_key_byte(second_key, second_key.len(), second_phase, position)
    }
}

fn rotated_key_byte(key: &[u8], period: usize, phase: usize, position: usize) -> Option<u8> {
    if period == 0 || period > key.len() || phase >= period {
        return None;
    }
    let position = position % period;
    let until_wrap = period - phase;
    let index = if position >= until_wrap {
        position - until_wrap
    } else {
        phase + position
    };
    key.get(index).copied()
}

fn primitive_period(key: &[u8]) -> Result<usize, ()> {
    if key.is_empty() {
        return Err(());
    }
    let mut prefix = Vec::new();
    prefix.try_reserve_exact(key.len()).map_err(|_| ())?;
    prefix.resize(key.len(), 0);

    for index in 1..key.len() {
        let byte = key.get(index).copied().ok_or(())?;
        let mut matched = prefix.get(index - 1).copied().ok_or(())?;
        while matched > 0 && key.get(matched).copied().ok_or(())? != byte {
            matched = prefix.get(matched - 1).copied().ok_or(())?;
        }
        if key.get(matched).copied().ok_or(())? == byte {
            matched += 1;
        }
        *prefix.get_mut(index).ok_or(())? = matched;
    }

    let last_prefix = prefix.get(key.len() - 1).copied().ok_or(())?;
    let candidate = key
        .len()
        .checked_sub(last_prefix)
        .filter(|value| *value > 0)
        .ok_or(())?;
    if key.len().is_multiple_of(candidate) {
        Ok(candidate)
    } else {
        Ok(key.len())
    }
}
