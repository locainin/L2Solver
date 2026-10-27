use l2_workbench::job::JobSnapshot;
use l2_workbench::job::cache::SourceIdentity;
use serde::{Deserialize, Deserializer, de};
use std::{fmt, marker::PhantomData};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

const MAX_SETTINGS_NODES: usize = 16_384;
pub(super) const MAX_SETTINGS_ITEMS: usize = 4_096;
const MAX_SETTINGS_DEPTH: usize = 32;
const MAX_SETTINGS_STRING_BYTES: usize = 64 * 1024;
const MAX_SETTINGS_TOTAL_STRING_BYTES: usize = 512 * 1024;
const MAX_SOURCE_IDENTITY_NODES: usize = 32;
const MAX_SOURCE_IDENTITY_ITEMS: usize = 16;
const MAX_SOURCE_IDENTITY_DEPTH: usize = 8;
const MAX_SOURCE_IDENTITY_STRING_BYTES: usize = 256;
const MAX_SOURCE_IDENTITY_TOTAL_STRING_BYTES: usize = 2 * 1024;
const MAX_JOB_SNAPSHOT_NODES: usize = 4_096;
const MAX_JOB_SNAPSHOT_ITEMS: usize = 80;
const MAX_JOB_SNAPSHOT_DEPTH: usize = 8;
const MAX_JOB_SNAPSHOT_STRING_BYTES: usize = 4 * 1024;
const MAX_JOB_SNAPSHOT_TOTAL_STRING_BYTES: usize = 128 * 1024;
const MAX_FILE_NAME_BYTES: usize = 255;
const MAX_SOURCE_ID_BYTES: usize = 7 + 64;

#[derive(Clone, Copy)]
struct ValueLimits {
    nodes: usize,
    items: usize,
    depth: usize,
    string_bytes: usize,
    total_string_bytes: usize,
}

const SETTINGS_LIMITS: ValueLimits = ValueLimits {
    nodes: MAX_SETTINGS_NODES,
    items: MAX_SETTINGS_ITEMS,
    depth: MAX_SETTINGS_DEPTH,
    string_bytes: MAX_SETTINGS_STRING_BYTES,
    total_string_bytes: MAX_SETTINGS_TOTAL_STRING_BYTES,
};

const SOURCE_IDENTITY_LIMITS: ValueLimits = ValueLimits {
    nodes: MAX_SOURCE_IDENTITY_NODES,
    items: MAX_SOURCE_IDENTITY_ITEMS,
    depth: MAX_SOURCE_IDENTITY_DEPTH,
    string_bytes: MAX_SOURCE_IDENTITY_STRING_BYTES,
    total_string_bytes: MAX_SOURCE_IDENTITY_TOTAL_STRING_BYTES,
};

const JOB_SNAPSHOT_LIMITS: ValueLimits = ValueLimits {
    nodes: MAX_JOB_SNAPSHOT_NODES,
    items: MAX_JOB_SNAPSHOT_ITEMS,
    depth: MAX_JOB_SNAPSHOT_DEPTH,
    string_bytes: MAX_JOB_SNAPSHOT_STRING_BYTES,
    total_string_bytes: MAX_JOB_SNAPSHOT_TOTAL_STRING_BYTES,
};

struct ValueBudget {
    limits: ValueLimits,
    nodes: usize,
    string_bytes: usize,
}

impl ValueBudget {
    const fn new(limits: ValueLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            string_bytes: 0,
        }
    }

    fn record_node<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > self.limits.depth {
            return Err(E::custom("metadata nesting depth limit exceeded"));
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| E::custom("metadata node count overflow"))?;
        if self.nodes > self.limits.nodes {
            return Err(E::custom("metadata node limit exceeded"));
        }
        Ok(())
    }

    fn record_string<E: de::Error>(&mut self, depth: usize, length: usize) -> Result<(), E> {
        self.record_node(depth)?;
        if length > self.limits.string_bytes {
            return Err(E::custom("metadata string size limit exceeded"));
        }
        self.string_bytes = self
            .string_bytes
            .checked_add(length)
            .ok_or_else(|| E::custom("metadata string size overflow"))?;
        if self.string_bytes > self.limits.total_string_bytes {
            return Err(E::custom("metadata string budget exceeded"));
        }
        Ok(())
    }
}

struct BoundedValueSeed<'a> {
    budget: &'a mut ValueBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedValueSeed<'_> {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BoundedValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedValueVisitor<'a> {
    budget: &'a mut ValueBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedValueVisitor<'_> {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON metadata")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_node(self.depth)?;
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_node(self.depth)?;
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_node(self.depth)?;
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_node(self.depth)?;
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("metadata contains an invalid number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_string(self.depth, value.len())?;
        Ok(serde_json::Value::String(copy_bounded_string::<E>(value)?))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_string(self.depth, value.len())?;
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_unit()
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_node(self.depth)?;
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.record_node(self.depth)?;
        let capacity = sequence
            .size_hint()
            .unwrap_or_default()
            .min(self.budget.limits.items);
        let mut values = Vec::new();
        values.try_reserve(capacity).map_err(de::Error::custom)?;
        let child_depth = next_depth(self.depth).map_err(de::Error::custom)?;
        while values.len() < self.budget.limits.items {
            let Some(value) = sequence.next_element_seed(BoundedValueSeed {
                budget: self.budget,
                depth: child_depth,
            })?
            else {
                return Ok(serde_json::Value::Array(values));
            };
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom("metadata sequence item limit exceeded"));
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.budget.record_node(self.depth)?;
        let child_depth = next_depth(self.depth).map_err(de::Error::custom)?;
        let mut values = serde_json::Map::new();
        let mut count = 0;
        while count < self.budget.limits.items {
            let Some(key) = map.next_key_seed(BoundedStringSeed {
                budget: self.budget,
                depth: child_depth,
            })?
            else {
                return Ok(serde_json::Value::Object(values));
            };
            let value = map.next_value_seed(BoundedValueSeed {
                budget: self.budget,
                depth: child_depth,
            })?;
            values.insert(key, value);
            count += 1;
        }
        if map.next_key::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom("metadata map entry limit exceeded"));
        }
        Ok(serde_json::Value::Object(values))
    }
}

struct BoundedStringSeed<'a> {
    budget: &'a mut ValueBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(BoundedStringVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedStringVisitor<'a> {
    budget: &'a mut ValueBudget,
    depth: usize,
}

impl Visitor<'_> for BoundedStringVisitor<'_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_string(self.depth, value.len())?;
        copy_bounded_string::<E>(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.record_string(self.depth, value.len())?;
        Ok(value)
    }
}

struct LimitedString<const MAXIMUM: usize>(String);

impl<const MAXIMUM: usize> LimitedString<MAXIMUM> {
    fn parse<E: de::Error>(value: String) -> Result<Self, E> {
        if value.len() > MAXIMUM {
            return Err(E::custom("metadata string size limit exceeded"));
        }
        Ok(Self(value))
    }
}

impl<'de, const MAXIMUM: usize> Deserialize<'de> for LimitedString<MAXIMUM> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LimitedStringVisitor<const MAXIMUM: usize>;

        impl<const MAXIMUM: usize> Visitor<'_> for LimitedStringVisitor<MAXIMUM> {
            type Value = LimitedString<MAXIMUM>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string with at most {MAXIMUM} bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAXIMUM {
                    return Err(E::custom("metadata string size limit exceeded"));
                }
                copy_bounded_string::<E>(value).map(LimitedString)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                LimitedString::parse(value)
            }
        }

        deserializer.deserialize_string(LimitedStringVisitor::<MAXIMUM>)
    }
}

struct LimitedSequence<T, const MAXIMUM: usize>(Vec<T>);

impl<'de, T, const MAXIMUM: usize> Deserialize<'de> for LimitedSequence<T, MAXIMUM>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LimitedSequenceVisitor<T, const MAXIMUM: usize>(PhantomData<T>);

        impl<'de, T, const MAXIMUM: usize> Visitor<'de> for LimitedSequenceVisitor<T, MAXIMUM>
        where
            T: Deserialize<'de>,
        {
            type Value = LimitedSequence<T, MAXIMUM>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence with at most {MAXIMUM} entries")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or_default().min(MAXIMUM);
                let mut values = Vec::new();
                values.try_reserve(capacity).map_err(de::Error::custom)?;
                while values.len() < MAXIMUM {
                    let Some(value) = sequence.next_element()? else {
                        return Ok(LimitedSequence(values));
                    };
                    values.push(value);
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("manifest sequence item limit exceeded"));
                }
                Ok(LimitedSequence(values))
            }
        }

        deserializer.deserialize_seq(LimitedSequenceVisitor::<T, MAXIMUM>(PhantomData))
    }
}

pub(super) fn deserialize_settings<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_value(deserializer, SETTINGS_LIMITS)
}

pub(super) fn deserialize_source_identity<'de, D>(
    deserializer: D,
) -> Result<SourceIdentity, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_bounded_value(deserializer, SOURCE_IDENTITY_LIMITS)?;
    let identity = serde_json::from_value(value).map_err(de::Error::custom)?;
    let digest = match &identity {
        SourceIdentity::Fast(fingerprint) => &fingerprint.sample_sha256,
        SourceIdentity::Sha256(digest) => digest,
        _ => {
            return Err(de::Error::custom(
                "metadata has an unsupported source identity",
            ));
        }
    };
    validate_sha256_value::<D::Error>(digest)?;
    Ok(identity)
}

pub(super) fn deserialize_job_snapshot<'de, D>(deserializer: D) -> Result<JobSnapshot, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_bounded_value(deserializer, JOB_SNAPSHOT_LIMITS)?;
    serde_json::from_value(value).map_err(de::Error::custom)
}

fn deserialize_bounded_value<'de, D>(
    deserializer: D,
    limits: ValueLimits,
) -> Result<serde_json::Value, D::Error>
where
    D: Deserializer<'de>,
{
    let mut budget = ValueBudget::new(limits);
    BoundedValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(deserializer)
}

pub(super) fn deserialize_artifacts<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_sequence::<D, T, { super::manifest::MAX_RESULT_ARTIFACTS }>(deserializer)
}

pub(super) fn deserialize_output_stamps<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_sequence::<D, T, { super::manifest::MAX_RESULT_OUTPUT_STAMPS }>(deserializer)
}

pub(super) fn deserialize_source_digests<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let LimitedSequence::<LimitedString<64>, { super::manifest::MAX_RESULT_SOURCES }>(digests) =
        LimitedSequence::deserialize(deserializer)?;
    digests
        .into_iter()
        .map(|digest| validate_sha256::<D::Error>(digest.0))
        .collect()
}

pub(super) fn deserialize_optional_sources<'de, D, T>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<LimitedSequence<T, { super::manifest::MAX_RESULT_SOURCES }>>::deserialize(deserializer)
        .map(|sources| sources.map(|sources| sources.0))
}

pub(super) fn deserialize_file_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    LimitedString::<MAX_FILE_NAME_BYTES>::deserialize(deserializer).map(|file| file.0)
}

pub(super) fn deserialize_source_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    LimitedString::<MAX_SOURCE_ID_BYTES>::deserialize(deserializer).map(|source| source.0)
}

pub(super) fn deserialize_optional_source_label<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<LimitedString<1024>>::deserialize(deserializer).map(|label| label.map(|label| label.0))
}

pub(super) fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let digest = LimitedString::<64>::deserialize(deserializer)?.0;
    validate_sha256::<D::Error>(digest)
}

pub(super) fn deserialize_optional_sha256<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<LimitedString<64>>::deserialize(deserializer)?
        .map(|digest| validate_sha256::<D::Error>(digest.0))
        .transpose()
}

pub(super) fn deserialize_status<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<LimitedString<8>>::deserialize(deserializer).map(|status| status.map(|v| v.0))
}

fn deserialize_sequence<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    LimitedSequence::<T, MAXIMUM>::deserialize(deserializer).map(|sequence| sequence.0)
}

fn validate_sha256<E: de::Error>(digest: String) -> Result<String, E> {
    validate_sha256_value::<E>(&digest)?;
    Ok(digest)
}

fn validate_sha256_value<E: de::Error>(digest: &str) -> Result<(), E> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(E::custom("metadata contains an invalid SHA-256 digest"));
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, &'static str> {
    depth
        .checked_add(1)
        .ok_or("metadata nesting depth overflow")
}

fn copy_bounded_string<E: de::Error>(value: &str) -> Result<String, E> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len()).map_err(E::custom)?;
    copy.push_str(value);
    Ok(copy)
}

#[cfg(test)]
#[path = "../../tests/result_directory/recovery_transition_snapshot.rs"]
mod recovery_transition_snapshot_tests;
