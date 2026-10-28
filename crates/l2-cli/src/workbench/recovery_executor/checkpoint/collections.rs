//! Stable collection encodings that reject repeated saved keys

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

pub(in crate::workbench::recovery_executor) fn sorted_entries<K: Ord, V>(
    value: &HashMap<K, V>,
) -> Result<Vec<(&K, &V)>, std::collections::TryReserveError> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(value.len())?;
    entries.extend(value.iter());
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    Ok(entries)
}

pub(in crate::workbench::recovery_executor) mod hash_map {
    use super::{Deserialize, Deserializer, Hash, HashMap, Serialize, Serializer, sorted_entries};

    pub(in crate::workbench::recovery_executor) fn serialize<
        K: Ord + Serialize,
        V: Serialize,
        S: Serializer,
    >(
        value: &HashMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        sorted_entries(value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub(in crate::workbench::recovery_executor) fn deserialize<
        'de,
        K: Deserialize<'de> + Eq + Hash,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<HashMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        let mut values = HashMap::new();
        values
            .try_reserve(entries.len())
            .map_err(serde::de::Error::custom)?;
        for (key, value) in entries {
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("repeated checkpoint map key"));
            }
        }
        Ok(values)
    }
}

pub(in crate::workbench::recovery_executor) mod btree_map {
    use super::{BTreeMap, Deserialize, Deserializer, Serialize, SerializeSeq, Serializer};

    pub(in crate::workbench::recovery_executor) fn serialize<
        K: Serialize,
        V: Serialize,
        S: Serializer,
    >(
        value: &BTreeMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(value.len()))?;
        for entry in value {
            sequence.serialize_element(&entry)?;
        }
        sequence.end()
    }

    pub(in crate::workbench::recovery_executor) fn deserialize<
        'de,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        let mut values = BTreeMap::new();
        for (key, value) in entries {
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("repeated checkpoint map key"));
            }
        }
        Ok(values)
    }
}

pub(in crate::workbench::recovery_executor) mod hash_set {
    use super::{Deserialize, Deserializer, Hash, HashSet, Serialize, Serializer};

    pub(in crate::workbench::recovery_executor) fn serialize<T: Ord + Serialize, S: Serializer>(
        value: &HashSet<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(value.len())
            .map_err(serde::ser::Error::custom)?;
        entries.extend(value.iter());
        entries.sort_unstable();
        entries.serialize(serializer)
    }

    pub(in crate::workbench::recovery_executor) fn deserialize<
        'de,
        T: Deserialize<'de> + Eq + Hash,
        D: Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<HashSet<T>, D::Error> {
        let entries = Vec::<T>::deserialize(deserializer)?;
        let mut values = HashSet::new();
        values
            .try_reserve(entries.len())
            .map_err(serde::de::Error::custom)?;
        for value in entries {
            if !values.insert(value) {
                return Err(serde::de::Error::custom("repeated checkpoint set member"));
            }
        }
        Ok(values)
    }
}
