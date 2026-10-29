//! Admit JSON nodes and strings before building owned checkpoint state

use super::{MemoryBudget, MemoryClass, MemoryError, MemoryLease};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{error::Error, fmt};

// Cover collection spare capacity and map entries without claiming an exact RSS bound
const VALUE_BYTES: usize = 4 * size_of::<serde_json::Value>() + 2 * size_of::<usize>();

/// Memory held while decoding JSON and retaining its owned representation
#[derive(Debug)]
pub struct JsonMemoryAdmission {
    scratch: MemoryLease,
    retained: MemoryLease,
}

impl JsonMemoryAdmission {
    /// Release parser scratch and keep the charge for the decoded state
    #[must_use]
    pub fn into_retained(self) -> MemoryLease {
        let Self { scratch, retained } = self;
        drop(scratch);
        retained
    }
}

/// Failure to validate or admit a JSON representation
#[derive(Debug)]
pub enum JsonMemoryError {
    /// The input does not contain one complete JSON value
    InvalidJson {
        /// One-based line of the parser rejection
        line: usize,
        /// Column of the parser rejection
        column: usize,
    },
    /// The shared budget cannot admit the required allocation
    Memory(MemoryError),
    /// Encoded input size cannot be represented by the budget
    SizeOverflow,
}

impl fmt::Display for JsonMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { line, column } => {
                write!(
                    formatter,
                    "invalid JSON metadata at line {line}, column {column}"
                )
            }
            Self::Memory(error) => error.fmt(formatter),
            Self::SizeOverflow => formatter.write_str("JSON metadata size overflow"),
        }
    }
}

impl Error for JsonMemoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::InvalidJson { .. } | Self::SizeOverflow => None,
        }
    }
}

/// Validate bounded JSON and reserve its parser scratch and owned node allowance
///
/// The allowance covers ordinary JSON nodes and strings, including spare collection capacity
/// Typed decoders that allocate from numeric dimensions still need their own validated bounds
/// Keep the admission through decoding, then retain its lease for the decoded state's lifetime
///
/// # Errors
/// Returns an error for malformed JSON, an unrepresentable size, or refused memory admission
pub fn admit_json(
    bytes: &[u8],
    memory: &MemoryBudget,
    class: MemoryClass,
) -> Result<JsonMemoryAdmission, JsonMemoryError> {
    // Escaped strings grow a scratch Vec, so include both buffers during reallocation
    let scratch_bytes = u64::try_from(bytes.len())
        .ok()
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or(JsonMemoryError::SizeOverflow)?;
    let scratch = memory
        .try_reserve(class, scratch_bytes)
        .map_err(JsonMemoryError::Memory)?;
    let mut meter = Meter { bytes: 0 };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Seed(&mut meter)
        .deserialize(&mut decoder)
        .and_then(|()| decoder.end())
        .map_err(|error| JsonMemoryError::InvalidJson {
            line: error.line(),
            column: error.column(),
        })?;
    let retained = memory
        .try_reserve(class, meter.bytes)
        .map_err(JsonMemoryError::Memory)?;
    Ok(JsonMemoryAdmission { scratch, retained })
}

struct Meter {
    bytes: u64,
}

impl Meter {
    fn add<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.bytes = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| self.bytes.checked_add(bytes))
            .ok_or_else(|| E::custom("JSON metadata size overflow"))?;
        Ok(())
    }
}

struct Seed<'meter>(&'meter mut Meter);

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        self.0.add(VALUE_BYTES)?;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON metadata")
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.0.add(
            value
                .len()
                .checked_mul(2)
                .ok_or_else(|| E::custom("JSON string size overflow"))?,
        )
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element_seed(Seed(self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Seed(self.0))?.is_some() {
            map.next_value_seed(Seed(self.0))?;
        }
        Ok(())
    }
}
