use super::budget::{
    DecodeBudget, DecodeError, MAX_DEPTH, OBJECT_BYTES, OBJECT_ENTRY_BYTES, SET_ENTRY_BYTES,
};
use crate::workbench::tshark::model::EnrichedPacket;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, fmt};

pub(super) struct PacketSeed<'a>(pub(super) &'a mut DecodeBudget);

impl<'de> DeserializeSeed<'de> for PacketSeed<'_> {
    type Value = Vec<EnrichedPacket>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(PacketVisitor(self.0))
    }
}

struct PacketVisitor<'a>(&'a mut DecodeBudget);

impl<'de> Visitor<'de> for PacketVisitor<'_> {
    type Value = Vec<EnrichedPacket>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of TShark packets")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut packets = Vec::new();
        while let Some(entry) = sequence.next_element_seed(ValueSeed {
            budget: self.0,
            depth: 1,
        })? {
            let packet = packet(entry, packets.len(), self.0)?;
            self.0.reserve_one(&mut packets)?;
            packets.push(packet);
        }
        Ok(packets)
    }
}

fn packet<E: de::Error>(
    mut entry: Value,
    index: usize,
    budget: &mut DecodeBudget,
) -> Result<EnrichedPacket, E> {
    let layers = entry
        .get_mut("_source")
        .and_then(|source| source.get_mut("layers"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            budget.fail(DecodeError::InvalidPacket(
                "TShark packet is missing its structured layer object",
            ))
        })?;
    let number = layers
        .get("frame")
        .and_then(|frame| frame.get("frame.number"))
        .and_then(json_u64)
        .ok_or_else(|| {
            budget.fail(DecodeError::InvalidPacket(
                "TShark packet is missing its source frame number",
            ))
        })?;
    let expected = u64::try_from(index)
        .ok()
        .and_then(|index| index.checked_add(1))
        .ok_or_else(|| budget.fail(DecodeError::InvalidPacket("TShark packet number overflow")))?;
    if number != expected {
        return Err(budget.fail(DecodeError::InvalidPacket(
            "TShark packet numbers are missing, skipped, or out of order",
        )));
    }
    // Move the layer tree out before dropping the rest of this packet
    let fields = Value::Object(std::mem::take(layers));
    let mut reassembled_fields = BTreeSet::new();
    collect_reassembled_fields(&fields, &mut reassembled_fields, budget)?;
    Ok(EnrichedPacket {
        packet_number: number,
        tool_derived: true,
        fields,
        reassembled_fields,
    })
}

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|text| text.parse::<u64>().ok())
        .or_else(|| value.as_u64())
}

fn collect_reassembled_fields<E: de::Error>(
    value: &Value,
    fields: &mut BTreeSet<String>,
    budget: &mut DecodeBudget,
) -> Result<(), E> {
    match value {
        Value::Object(object) => collect_reassembled_object(object, fields, budget)?,
        Value::Array(values) => {
            for value in values {
                collect_reassembled_fields(value, fields, budget)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn collect_reassembled_object<E: de::Error>(
    object: &Map<String, Value>,
    fields: &mut BTreeSet<String>,
    budget: &mut DecodeBudget,
) -> Result<(), E> {
    for (name, value) in object {
        if name.contains("reassembled") && !fields.contains(name) {
            // Charge both the retained key and its set node before insertion
            budget.charge(SET_ENTRY_BYTES)?;
            fields.insert(budget.copy_string(name)?);
        }
        collect_reassembled_fields(value, fields, budget)?;
    }
    Ok(())
}

struct ValueSeed<'a> {
    budget: &'a mut DecodeBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(self.budget.fail(DecodeError::NestingLimit));
        }
        deserializer.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'a> {
    budget: &'a mut DecodeBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a TShark JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.budget.copy_string(value).map(Value::String)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            self.budget.reserve_one(&mut values)?;
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        self.budget.charge(OBJECT_BYTES)?;
        let mut values = Map::new();
        while let Some(key) = map.next_key_seed(StringSeed(self.budget))? {
            self.budget.charge(OBJECT_ENTRY_BYTES)?;
            let value = map.next_value_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StringSeed<'a>(&'a mut DecodeBudget);

impl<'de> DeserializeSeed<'de> for StringSeed<'_> {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_string(StringVisitor(self.0))
    }
}

struct StringVisitor<'a>(&'a mut DecodeBudget);

impl Visitor<'_> for StringVisitor<'_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a TShark JSON object key")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.0.copy_string(value)
    }
}
