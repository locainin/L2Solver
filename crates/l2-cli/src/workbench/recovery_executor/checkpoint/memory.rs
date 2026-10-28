//! Admit owned checkpoint metadata without first building an uncharged JSON tree

use super::{RecoveryError, RecoveryExecutionError, operational};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

// Include collection spare capacity and map entries in the logical metadata allowance
// This estimate is independent of allocator overhead, RSS, and the restored Case's charge
const VALUE_BYTES: usize = 4 * size_of::<serde_json::Value>() + 2 * size_of::<usize>();

pub(super) fn admit(
    bytes: &[u8],
    memory: Option<&MemoryBudget>,
) -> Result<(Option<MemoryLease>, Option<MemoryLease>), RecoveryExecutionError> {
    let Some(memory) = memory else {
        return Ok((None, None));
    };
    // Escaped strings can require a temporary buffer as large as the encoded input
    let scratch = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(bytes.len()).map_err(|_| RecoveryError::AllocationFailed)?,
        )
        .map_err(operational)?;
    let mut meter = Meter { bytes: 0 };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Seed(&mut meter)
        .deserialize(&mut decoder)
        .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    decoder
        .end()
        .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    let retained = memory
        .try_reserve(MemoryClass::Executor, meter.bytes)
        .map_err(operational)?;
    Ok((Some(scratch), Some(retained)))
}

struct Meter {
    bytes: u64,
}

impl Meter {
    fn add<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.bytes = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| self.bytes.checked_add(bytes))
            .ok_or_else(|| E::custom("checkpoint metadata size overflow"))?;
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
        formatter.write_str("checkpoint metadata")
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
                .ok_or_else(|| E::custom("checkpoint string size overflow"))?,
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
